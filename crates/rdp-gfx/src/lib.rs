//! Pipeline graphique EGFX côté client (MS-RDPEGFX), sans I/O.
//!
//! Reçoit les messages du canal `Microsoft::Windows::RDS::Graphics`, les décompresse (ZGFX),
//! applique les commandes aux surfaces (RGBA en mémoire), compose les surfaces sur la sortie
//! (le bureau) et signale les zones modifiées. Les images H.264 sont décodées par l'appelant
//! (WebCodecs dans le navigateur) : le traitement se met alors en pause jusqu'à `submit_yuv420`,
//! pour que l'ordre des commandes et l'accusé de fin d'image restent exacts.

#![no_std]
extern crate alloc;

mod cmd;
mod yuv;

use alloc::{collections::BTreeMap, collections::VecDeque, string::String, vec, vec::Vec};

use rdp_codecs::{clearcodec::ClearCodec, zgfx::Zgfx};

pub use cmd::caps_advertise;
pub use yuv::Yuv420;

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
    /// Nouvelle taille de sortie : réallouer le canevas.
    Reset { width: u32, height: u32 },
    /// Fin d'image : zones de la sortie à recopier vers l'écran.
    Present { damage: Vec<Rect> },
    /// Image H.264 à décoder puis à rendre par `submit_yuv420` (ou `skip_frame`).
    Avc420 { data: Vec<u8> },
    /// Commande ignorée (codec non pris en charge…), pour le journal.
    Ignored(String),
}

struct Surface {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
    origin: Option<(u32, u32)>,
}

struct Cached {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
}

/// Commande H.264 en attente de décodage.
struct PendingAvc {
    surface: u16,
    rects: Vec<Rect>,
}

pub struct Gfx {
    zgfx: Zgfx,
    clear: ClearCodec,
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
}

/// Plafonds : surfaces jusqu'en 8K, 4 096 emplacements de cache (petit cache EGFX).
const MAX_SIDE: u32 = 8192;
const MAX_CACHE_SLOTS: u16 = 4096;
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
            surfaces: BTreeMap::new(),
            cache: BTreeMap::new(),
            output: Vec::new(),
            width: 0,
            height: 0,
            damage: Vec::new(),
            queue: VecDeque::new(),
            pending_avc: None,
            frames_decoded: 0,
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

    /// Abandonne l'image H.264 en attente (décodeur indisponible) et reprend.
    pub fn skip_frame(&mut self) -> Result<Vec<Out>, Error> {
        self.pending_avc = None;
        self.run()
    }

    fn run(&mut self) -> Result<Vec<Out>, Error> {
        let mut out = Vec::new();
        while self.pending_avc.is_none() {
            let Some(pdu) = self.queue.pop_front() else { break };
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
