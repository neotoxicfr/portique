//! Pipeline graphique EGFX côté client (MS-RDPEGFX), sans I/O.
//!
//! Reçoit les messages du canal `Microsoft::Windows::RDS::Graphics`, les décompresse (ZGFX),
//! applique les commandes aux surfaces (RGBA en mémoire), compose les surfaces sur la sortie
//! (le bureau) et signale les zones modifiées. Les images H.264 sont décodées par l'appelant
//! (WebCodecs dans le navigateur) : le traitement se met alors en pause jusqu'à `submit_yuv420`,
//! pour que l'ordre des commandes et l'accusé de fin d'image restent exacts.

#![no_std]
extern crate alloc;

mod avc444;
mod cmd;
mod yuv;

use alloc::{collections::BTreeMap, collections::VecDeque, string::String, vec, vec::Vec};

use rdp_codecs::{clearcodec::ClearCodec, progressive::Progressive, zgfx::Zgfx};

pub use cmd::{Avc, caps_advertise};
pub use yuv::Yuv420;

/// Image H.264 4:2:0 déjà convertie en RGBA par le navigateur (décodeurs qui ne rendent que du RGB).
pub struct Rgba<'a> {
    pub width: u32,
    pub height: u32,
    pub data: &'a [u8],
    pub stride: u32,
}

impl Rgba<'_> {
    fn check(&self) -> Result<(), Error> {
        if self.width == 0 || self.height == 0 {
            return Err(Error::Invalid("image H.264 vide"));
        }
        let need = (self.height as u64 - 1) * self.stride as u64 + self.width as u64 * 4;
        if (self.stride as u64) < self.width as u64 * 4 || (self.data.len() as u64) < need {
            return Err(Error::Truncated("image RGBA"));
        }
        Ok(())
    }
}

/// Sous-image auxiliaire d'un AVC444 : plans YUV, ou RGB du navigateur à inverser.
enum AuxIn<'a> {
    Yuv(&'a Yuv420<'a>),
    Rgba(&'a Rgba<'a>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Truncated(&'static str),
    Invalid(&'static str),
    Codec(rdp_codecs::Error),
}

impl From<rdp_codecs::Error> for Error {
    fn from(e: rdp_codecs::Error) -> Self {
        Error::Codec(e)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Truncated(w) => write!(f, "EGFX : {w} tronqué"),
            Error::Invalid(w) => write!(f, "EGFX : {w}"),
            Error::Codec(e) => write!(f, "EGFX : {e}"),
        }
    }
}

impl core::error::Error for Error {}

/// Rectangle (x, y, largeur, hauteur).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

impl Rect {
    fn clip(self, width: u32, height: u32) -> Option<Rect> {
        let x2 = (self.x.saturating_add(self.w)).min(width);
        let y2 = (self.y.saturating_add(self.h)).min(height);
        (self.x < x2 && self.y < y2).then(|| Rect { x: self.x, y: self.y, w: x2 - self.x, h: y2 - self.y })
    }
}

/// Ce que l'appelant doit faire après une étape.
#[derive(Debug, PartialEq)]
pub enum Out {
    /// Message à envoyer sur le canal graphique (accusés d'image).
    Send(Vec<u8>),
    /// Nouvelle taille de sortie : réallouer le canevas. `monitors` : écrans du bureau en
    /// coordonnées de sortie (origine = coin haut-gauche du rectangle englobant).
    Reset { width: u32, height: u32, monitors: Vec<Rect> },
    /// Fin d'image : zones de la sortie à recopier vers l'écran.
    Present { damage: Vec<Rect> },
    /// Image H.264 à décoder puis à rendre par `submit_yuv420` (ou `skip_frame`).
    Avc420 { data: Vec<u8> },
    /// Image 4:4:4 en deux sous-images à décoder avec le MÊME décodeur, dans l'ordre (principale
    /// puis auxiliaire), puis à rendre par `submit_avc444` (ou `skip_frame`).
    Avc444 { main: Option<Vec<u8>>, aux: Option<Vec<u8>> },
    /// Commande ignorée (codec non pris en charge…), pour le journal.
    Ignored(String),
}

struct Surface {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
    origin: Option<(u32, u32)>,
    /// Plans YUV 4:4:4 reconstitués (créés à la première image AVC444).
    p444: Option<avc444::Planes444>,
}

struct Cached {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
}

/// Commande H.264 en attente de décodage.
struct PendingAvc {
    surface: u16,
    /// Zones de la vue principale (luma).
    rects: Vec<Rect>,
    /// AVC444 : zones de la vue auxiliaire (chroma) et variante v2.
    aux: Option<(Vec<Rect>, bool)>,
}

pub struct Gfx {
    zgfx: Zgfx,
    clear: ClearCodec,
    progressive: Progressive,
    surfaces: BTreeMap<u16, Surface>,
    cache: BTreeMap<u16, Cached>,
    output: Vec<u8>,
    width: u32,
    height: u32,
    damage: Vec<Rect>,
    /// PDU décompressées en attente (le traitement s'arrête sur une image H.264).
    queue: VecDeque<Vec<u8>>,
    pending_avc: Option<PendingAvc>,
    frames_decoded: u32,
    surface_bytes: usize,
    cache_bytes: usize,
    queued_bytes: usize,
    /// La conversion RGB du navigateur ne s'inverse pas (chroma interpolée, autre matrice) : plus
    /// de recomposition 4:4:4 depuis ses images RGB.
    rgb_refused: bool,
}

// Plafonds : les données viennent du réseau, aucune allocation ni boucle n'est laissée libre.
/// Côté maximal d'une surface ou de la sortie.
pub const MAX_SIDE: u32 = 8192;
/// Nombre de surfaces simultanées et mémoire totale qu'elles occupent.
const MAX_SURFACES: usize = 64;
const MAX_SURFACE_BYTES: usize = 512 * 1024 * 1024;
/// Petit cache EGFX annoncé (RDPGFX_CAPS_FLAG_SMALL_CACHE) : 16 Mo et 4 096 emplacements.
const MAX_CACHE_SLOTS: u16 = 4096;
const MAX_CACHE_BYTES: usize = 16 * 1024 * 1024;
/// Pixels qu'une seule commande peut copier ou remplir (≈ 8 écrans 4K).
const MAX_PIXELS_PER_COMMAND: u64 = 64 * 1024 * 1024;
/// Octets de PDU en attente pendant le décodage d'une image H.264.
const MAX_QUEUED_BYTES: usize = 64 * 1024 * 1024;
const MAX_DAMAGE_RECTS: usize = 64;

impl Default for Gfx {
    fn default() -> Self {
        Self::new()
    }
}

impl Gfx {
    pub fn new() -> Self {
        Self {
            zgfx: Zgfx::new(),
            clear: ClearCodec::new(),
            progressive: Progressive::new(),
            surfaces: BTreeMap::new(),
            cache: BTreeMap::new(),
            output: Vec::new(),
            width: 0,
            height: 0,
            damage: Vec::new(),
            queue: VecDeque::new(),
            pending_avc: None,
            frames_decoded: 0,
            surface_bytes: 0,
            cache_bytes: 0,
            queued_bytes: 0,
            rgb_refused: false,
        }
    }

    /// Sortie composée (RGBA, stride = largeur × 4).
    pub fn output(&self) -> (&[u8], u32, u32) {
        (&self.output, self.width, self.height)
    }

    /// Traite un message du canal graphique.
    pub fn process(&mut self, msg: &[u8]) -> Result<Vec<Out>, Error> {
        let mut raw = Vec::new();
        self.zgfx.decompress(msg, &mut raw)?;
        let mut rest = &raw[..];
        while !rest.is_empty() {
            if rest.len() < 8 {
                return Err(Error::Truncated("en-tête RDPGFX"));
            }
            let len = u32::from_le_bytes([rest[4], rest[5], rest[6], rest[7]]) as usize;
            if len < 8 || len > rest.len() {
                return Err(Error::Invalid("longueur de PDU RDPGFX"));
            }
            // Compté seulement si la PDU entre dans la file : `run` ne décompte que ce qu'il dépile.
            if self.queued_bytes + len > MAX_QUEUED_BYTES {
                return Err(Error::Invalid("trop de commandes en attente"));
            }
            self.queued_bytes += len;
            self.queue.push_back(rest[..len].to_vec());
            rest = &rest[len..];
        }
        self.run()
    }

    /// Une image H.264 attend son décodage.
    pub fn waiting_for_avc(&self) -> bool {
        self.pending_avc.is_some()
    }

    /// Applique l'image H.264 décodée (taille de la surface, alignée sur 16) puis reprend.
    pub fn submit_yuv420(&mut self, frame: &Yuv420<'_>) -> Result<Vec<Out>, Error> {
        if let Some(p) = self.pending_avc.take() {
            let mut done = Vec::new();
            let mut origin = None;
            if let Some(s) = self.surfaces.get_mut(&p.surface) {
                origin = s.origin;
                for r in &p.rects {
                    if let Some(r) = r.clip(s.width, s.height) {
                        frame.to_rgba(r, &mut s.rgba, s.width)?;
                        done.push(r);
                    }
                }
            }
            for r in done {
                self.touch(p.surface, r, origin);
            }
        }
        self.run()
    }

    /// Applique une image 4:2:0 (AVC420, ou sous-image principale d'un AVC444) que le navigateur a
    /// déjà convertie en RGBA, puis reprend.
    pub fn submit_rgba(&mut self, frame: &Rgba<'_>) -> Result<Vec<Out>, Error> {
        if let Some(p) = self.pending_avc.take() {
            let mut done = Vec::new();
            let mut origin = None;
            if let Some(s) = self.surfaces.get_mut(&p.surface) {
                origin = s.origin;
                for r in &p.rects {
                    let Some(r) = r.clip(s.width, s.height) else { continue };
                    if r.x + r.w > frame.width || r.y + r.h > frame.height {
                        return Err(Error::Invalid("zone H.264 hors de l'image décodée"));
                    }
                    for row in r.y..r.y + r.h {
                        let src = (row * frame.stride + r.x * 4) as usize;
                        let src = frame
                            .data
                            .get(src..src + (r.w * 4) as usize)
                            .ok_or(Error::Truncated("image RGBA"))?;
                        let dst = ((row * s.width + r.x) * 4) as usize;
                        s.rgba[dst..dst + (r.w * 4) as usize].copy_from_slice(src);
                    }
                    done.push(r);
                }
            }
            for r in done {
                self.touch(p.surface, r, origin);
            }
        }
        self.run()
    }

    /// Applique une image AVC444 décodée (sous-images principale et/ou auxiliaire) puis reprend.
    pub fn submit_avc444(
        &mut self,
        main: Option<&Yuv420<'_>>,
        aux: Option<&Yuv420<'_>>,
    ) -> Result<Vec<Out>, Error> {
        self.avc444(main, aux.map(AuxIn::Yuv))
    }

    /// Image AVC444 que le navigateur n'a rendue qu'en RGB : les plans YUV des deux sous-images
    /// sont retrouvés en inversant sa conversion (BT.709 pleine plage, chroma répétée sur 2×2),
    /// puis recombinés en 4:4:4. Refusée, l'image restant en attente (l'appelant se rabat sur
    /// `submit_rgba`), si une image est illisible ou si la conversion du navigateur se révèle
    /// autre : constaté une fois, plus de recomposition pour la session. Une sous-image
    /// auxiliaire jugée incohérente est ignorée (la principale reste affichée seule).
    pub fn submit_avc444_rgba(
        &mut self,
        main: Option<&Rgba<'_>>,
        aux: Option<&Rgba<'_>>,
    ) -> Result<Vec<Out>, Error> {
        const REFUSED: Error = Error::Invalid("conversion RGB du navigateur non inversible");
        if self.rgb_refused {
            return Err(REFUSED);
        }
        for f in main.iter().chain(aux.iter()) {
            f.check()?;
        }
        // Chroma seule : il faut la luma d'une image précédente.
        let has_planes = |g: &Self| {
            g.pending_avc.as_ref().and_then(|p| g.surfaces.get(&p.surface)).is_some_and(|s| s.p444.is_some())
        };
        if main.is_none() && !has_planes(self) {
            return Err(Error::Invalid("chroma AVC444 sans luma"));
        }
        let rects = self.pending_avc.as_ref().map(|p| p.rects.clone()).unwrap_or_default();
        let main = main.map(|f| avc444::FromRgb::new(f, &rects, |_, _| None)).transpose()?;
        if main.as_ref().is_some_and(avc444::FromRgb::interpolated) {
            self.rgb_refused = true;
            return Err(REFUSED);
        }
        self.avc444(main.as_ref().map(avc444::FromRgb::view).as_ref(), aux.map(AuxIn::Rgba))
    }

    /// Le 4:4:4 est-il encore recomposé depuis les images RGB du navigateur ?
    pub fn rgb_444(&self) -> bool {
        !self.rgb_refused
    }

    fn avc444(&mut self, main: Option<&Yuv420<'_>>, aux: Option<AuxIn<'_>>) -> Result<Vec<Out>, Error> {
        if let Some(p) = self.pending_avc.take() {
            let mut done = Vec::new();
            let mut origin = None;
            if let Some(s) = self.surfaces.get_mut(&p.surface) {
                origin = s.origin;
                if s.p444.is_none() {
                    let planes = avc444::Planes444::new(s.width, s.height);
                    let grew = planes.bytes();
                    if self.surface_bytes + grew > MAX_SURFACE_BYTES {
                        return Err(Error::Invalid("mémoire de surface épuisée (AVC444)"));
                    }
                    // Compté dès qu'ils sont gardés : une image refusée plus bas ne les retire pas.
                    self.surface_bytes += grew;
                    s.p444 = Some(planes);
                }
                let (sw, sh) = (s.width, s.height);
                let planes = s.p444.as_mut().unwrap();
                if let Some(f) = main {
                    planes.apply_main(f, &p.rects)?;
                    for r in &p.rects {
                        if let Some(r) = r.clip(sw.min(f.width), sh.min(f.height)) {
                            planes.to_rgba_420(r, &mut s.rgba, sw);
                            done.push(r);
                        }
                    }
                }
                if let (Some(f), Some((rects, v2))) = (aux, p.aux.as_ref()) {
                    let applied = match f {
                        AuxIn::Yuv(f) => {
                            planes.apply_aux(f, rects, *v2)?;
                            true
                        }
                        AuxIn::Rgba(f) => {
                            let a = planes.aux_from_rgba(f, rects, *v2)?;
                            let ok = !a.interpolated() && planes.aux_consistent(&a, rects, *v2);
                            if ok {
                                planes.apply_aux_from(&a, rects, *v2);
                            }
                            self.rgb_refused |= !ok;
                            ok
                        }
                    };
                    if applied {
                        for r in rects {
                            if let Some(r) = r.clip(sw, sh) {
                                planes.to_rgba_444(r, &mut s.rgba, sw);
                                done.push(r);
                            }
                        }
                    }
                }
            }
            for r in done {
                self.touch(p.surface, r, origin);
            }
        }
        self.run()
    }

    /// Abandonne l'image H.264 en attente (décodeur indisponible) et reprend.
    pub fn skip_frame(&mut self) -> Result<Vec<Out>, Error> {
        self.pending_avc = None;
        self.run()
    }

    fn run(&mut self) -> Result<Vec<Out>, Error> {
        let mut out = Vec::new();
        while self.pending_avc.is_none() {
            let Some(pdu) = self.queue.pop_front() else { break };
            self.queued_bytes -= pdu.len();
            self.command(&pdu, &mut out)?;
        }
        Ok(out)
    }

    /// Marque une zone de surface modifiée et la recopie sur la sortie si la surface y est mappée.
    fn touch(&mut self, surface: u16, r: Rect, origin: Option<(u32, u32)>) {
        let Some((ox, oy)) = origin else { return };
        let Some(s) = self.surfaces.get(&surface) else { return };
        let dst = Rect { x: ox + r.x, y: oy + r.y, w: r.w, h: r.h };
        let Some(dst) = dst.clip(self.width, self.height) else { return };
        for row in 0..dst.h {
            let so = (((r.y + row) * s.width + r.x) * 4) as usize;
            let doff = (((dst.y + row) * self.width + dst.x) * 4) as usize;
            let n = (dst.w * 4) as usize;
            self.output[doff..doff + n].copy_from_slice(&s.rgba[so..so + n]);
        }
        if self.damage.len() < MAX_DAMAGE_RECTS {
            self.damage.push(dst);
        } else {
            // Trop de petites zones : une seule zone englobante.
            let b = self.damage.iter().fold(dst, |a, r| {
                let x1 = a.x.min(r.x);
                let y1 = a.y.min(r.y);
                let x2 = (a.x + a.w).max(r.x + r.w);
                let y2 = (a.y + a.h).max(r.y + r.h);
                Rect { x: x1, y: y1, w: x2 - x1, h: y2 - y1 }
            });
            self.damage = vec![b];
        }
    }

    fn surface_mut(&mut self, id: u16) -> Result<&mut Surface, Error> {
        self.surfaces.get_mut(&id).ok_or(Error::Invalid("surface inconnue"))
    }
}
