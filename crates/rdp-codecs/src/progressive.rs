//! Décodeur RemoteFX Progressive (MS-RDPEGFX 2.2.4.2 et 3.3.8.2), codecId CAPROGRESSIVE
//! (0x0009) des RDPGFX_WIRE_TO_SURFACE_PDU_2.
//!
//! Tuiles 64 × 64 en YCbCr, DWT à trois niveaux (souvent « reduce-extrapolate »), RLGR1. Une
//! tuile arrive entière (TILE_SIMPLE) ou en passes : TILE_FIRST quantifiée grossièrement, puis
//! des TILE_UPGRADE qui ajoutent des bits (SRL pour les coefficients encore nuls, bits bruts pour
//! les autres). L'état par tuile (coefficients courants, signes) vit dans le contexte
//! `codecContextId` jusqu'à RDPGFX_DELETE_ENCODING_CONTEXT_PDU.
//!
//! Déquantification : décalage de `q + BitPos - 1` (quantification de la région + quantification
//! progressive de la passe, virgule fixe 11.5 comme le reste de RemoteFX).

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::Error;
use crate::rfx::{self, BitReader, COEFFS, Rlgr, TILE};

const WBT_FRAME_BEGIN: u16 = 0xCCC1;
const WBT_FRAME_END: u16 = 0xCCC2;
const WBT_CONTEXT: u16 = 0xCCC3;
const WBT_REGION: u16 = 0xCCC4;
const WBT_TILE_SIMPLE: u16 = 0xCCC5;
const WBT_TILE_FIRST: u16 = 0xCCC6;
const WBT_TILE_UPGRADE: u16 = 0xCCC7;

const RFX_DWT_REDUCE_EXTRAPOLATE: u8 = 0x01;
const RFX_TILE_DIFFERENCE: u8 = 0x01;
/// progressiveQuality : table « pleine qualité » (tous les BitPos à zéro).
const FULL_QUALITY: u8 = 0xFF;

/// Valeur par bande, ordre linéaire (HL1 … HH3, LL3).
type Quant = [u8; 10];

/// Rectangle mis à jour, coordonnées surface : (x, y, largeur, hauteur).
pub type Rect = (u32, u32, u32, u32);

/// État d'une tuile reçue.
struct Tile {
    /// Coefficients déquantifiés courants (Y, Cb, Cr), avant DWT inverse.
    coeffs: Vec<[i16; COEFFS]>,
    /// Signe de chaque coefficient (−1, 0, 1) pour les passes de raffinement ; vide une fois la
    /// qualité finale atteinte.
    sign: Vec<[i8; COEFFS]>,
    /// BitPos de la dernière passe, par composante et par bande (0 = complet).
    bitpos: [Quant; 3],
    extrapolate: bool,
}

#[derive(Default)]
struct Context {
    /// Clé : yIdx << 16 | xIdx.
    tiles: BTreeMap<u32, Tile>,
}

/// Décodeur avec état, un contexte par `codecContextId`.
pub struct Progressive {
    contexts: BTreeMap<u32, Context>,
    /// Tampons de travail : sortie RLGR, trois plans pour la DWT inverse, tampon de la DWT.
    work: Vec<[i16; COEFFS]>,
}

impl Default for Progressive {
    fn default() -> Self {
        Self::new()
    }
}

/// Tuiles et rectangles d'une trame (FRAME_BEGIN … FRAME_END) : les rectangles d'une région
/// peuvent être couverts par des tuiles d'une autre, on peint donc à la fin de la trame.
struct Frame {
    rects: Vec<(usize, usize, usize, usize)>,
    tiles: Vec<u32>,
}

/// Surface de destination.
struct Surface<'a> {
    px: &'a mut [u8],
    w: usize,
    h: usize,
}

impl Progressive {
    pub fn new() -> Self {
        Self { contexts: BTreeMap::new(), work: vec![[0; COEFFS]; 5] }
    }

    /// Décode un flux progressif sur une surface RGBA (stride = surface_width*4). Renvoie les
    /// rectangles mis à jour (coordonnées surface, (x, y, w, h)) pour le rafraîchissement.
    pub fn decode(
        &mut self,
        context_id: u32,
        src: &[u8],
        surface: &mut [u8],
        surface_width: u32,
        surface_height: u32,
    ) -> Result<Vec<Rect>, Error> {
        let (w, h) = (surface_width as usize, surface_height as usize);
        let need = w.checked_mul(h).and_then(|n| n.checked_mul(4));
        if need.is_none_or(|n| surface.len() < n) {
            return Err(Error::Invalid("progressif : surface plus petite que ses dimensions"));
        }
        let mut surf = Surface { px: surface, w, h };
        let Self { contexts, work } = self;
        let ctx = contexts.entry(context_id).or_default();
        let mut frame: Option<Frame> = None;
        let mut updated = Vec::new();
        let mut rest = src;
        while !rest.is_empty() {
            let (kind, body, next) = block(rest)?;
            rest = next;
            match kind {
                WBT_CONTEXT => {
                    let b = body.get(..4).ok_or(Error::Truncated("RFX_PROGRESSIVE_CONTEXT"))?;
                    if u16::from_le_bytes([b[1], b[2]]) != TILE as u16 {
                        return Err(Error::Invalid("progressif : tuiles autres que 64×64"));
                    }
                }
                WBT_FRAME_BEGIN => {
                    if body.len() < 6 {
                        return Err(Error::Truncated("RFX_PROGRESSIVE_FRAME_BEGIN"));
                    }
                    if let Some(f) = frame.take() {
                        paint(ctx, work, f, &mut surf, &mut updated);
                    }
                    frame = Some(Frame { rects: Vec::new(), tiles: Vec::new() });
                }
                WBT_FRAME_END => {
                    if let Some(f) = frame.take() {
                        paint(ctx, work, f, &mut surf, &mut updated);
                    }
                }
                // Une région hors FRAME_BEGIN … FRAME_END est ignorée (2.2.4.2.1.5).
                WBT_REGION => {
                    if let Some(f) = frame.as_mut() {
                        region(ctx, work, body, f, &surf)?;
                    }
                }
                // SYNC (facultatif), tuiles hors région, types inconnus : ignorés.
                _ => {}
            }
        }
        if let Some(f) = frame.take() {
            paint(ctx, work, f, &mut surf, &mut updated);
        }
        Ok(updated)
    }

    /// Oublie un contexte (RDPGFX_DELETE_ENCODING_CONTEXT_PDU).
    pub fn delete_context(&mut self, context_id: u32) {
        self.contexts.remove(&context_id);
    }
}

/// Découpe un RFX_PROGRESSIVE_DATABLOCK : (type, contenu, reste).
fn block(src: &[u8]) -> Result<(u16, &[u8], &[u8]), Error> {
    let h = src.get(..6).ok_or(Error::Truncated("bloc progressif"))?;
    let kind = u16::from_le_bytes([h[0], h[1]]);
    let len = u32::from_le_bytes([h[2], h[3], h[4], h[5]]) as usize;
    if len < 6 {
        return Err(Error::Invalid("progressif : longueur de bloc inférieure à 6"));
    }
    if len > src.len() {
        return Err(Error::Truncated("bloc progressif"));
    }
    Ok((kind, &src[6..len], &src[len..]))
}

fn u16_at(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}

/// RFX_COMPONENT_CODEC_QUANT (5 octets, nibble bas d'abord) vers l'ordre linéaire.
fn read_quant(b: &[u8]) -> Quant {
    // Ordre sur le fil : LL3 HL3 LH3 HH3 HL2 LH2 HH2 HL1 LH1 HH1.
    const WIRE_TO_LINEAR: [usize; 10] = [9, 6, 7, 8, 3, 4, 5, 0, 1, 2];
    let mut q = [0; 10];
    for (i, &d) in WIRE_TO_LINEAR.iter().enumerate() {
        let byte = b[i / 2];
        q[d] = if i % 2 == 0 { byte & 0x0F } else { byte >> 4 };
    }
    q
}

/// Décalages de déquantification d'une passe : q + BitPos − 1.
fn shifts(quant: &Quant, bitpos: &Quant) -> Quant {
    core::array::from_fn(|b| (quant[b] + bitpos[b]).saturating_sub(1))
}

/// RFX_PROGRESSIVE_REGION : rectangles, tables de quantification, puis tuiles.
fn region(
    ctx: &mut Context,
    work: &mut [[i16; COEFFS]],
    body: &[u8],
    frame: &mut Frame,
    surf: &Surface,
) -> Result<(), Error> {
    let h = body.get(..12).ok_or(Error::Truncated("RFX_PROGRESSIVE_REGION"))?;
    if h[0] as usize != TILE {
        return Err(Error::Invalid("progressif : tuiles autres que 64×64"));
    }
    let num_rects = u16_at(h, 1) as usize;
    let (num_quant, num_prog, flags) = (h[3] as usize, h[4] as usize, h[5]);
    let num_tiles = u16_at(h, 6);
    let tiles_len = u32::from_le_bytes([h[8], h[9], h[10], h[11]]) as usize;
    let mut rest = &body[12..];
    let mut take = |n: usize| -> Result<&[u8], Error> {
        let part = rest.get(..n).ok_or(Error::Truncated("RFX_PROGRESSIVE_REGION"))?;
        rest = &rest[n..];
        Ok(part)
    };
    let rects = take(num_rects * 8)?;
    let quants: Vec<Quant> = take(num_quant * 5)?.as_chunks::<5>().0.iter().map(|q| read_quant(q)).collect();
    // RFX_PROGRESSIVE_CODEC_QUANT : qualité (ignorée) puis Y, Cb, Cr.
    let progs: Vec<[Quant; 3]> = take(num_prog * 16)?
        .as_chunks::<16>()
        .0
        .iter()
        .map(|p| [read_quant(&p[1..6]), read_quant(&p[6..11]), read_quant(&p[11..16])])
        .collect();
    let mut tiles = take(tiles_len)?;
    let extrapolate = flags & RFX_DWT_REDUCE_EXTRAPOLATE != 0;

    for r in rects.as_chunks::<8>().0 {
        let (x, y) = (u16_at(r, 0) as usize, u16_at(r, 2) as usize);
        let (x2, y2) = ((x + u16_at(r, 4) as usize).min(surf.w), (y + u16_at(r, 6) as usize).min(surf.h));
        if x < x2 && y < y2 {
            frame.rects.push((x, y, x2 - x, y2 - y));
        }
    }

    for _ in 0..num_tiles {
        if tiles.is_empty() {
            break;
        }
        let (kind, tb, next) = block(tiles)?;
        tiles = next;
        if !matches!(kind, WBT_TILE_SIMPLE | WBT_TILE_FIRST | WBT_TILE_UPGRADE) {
            continue;
        }
        let hdr = tb.get(..7).ok_or(Error::Truncated("tuile progressive"))?;
        let quant = [hdr[0], hdr[1], hdr[2]].map(|i| quants.get(i as usize).copied());
        let [Some(qy), Some(qcb), Some(qcr)] = quant else {
            return Err(Error::Invalid("progressif : index de quantification hors table"));
        };
        let quant = [qy, qcb, qcr];
        let (x_idx, y_idx) = (u16_at(hdr, 3), u16_at(hdr, 5));
        let prog = |q: u8| -> Result<[Quant; 3], Error> {
            if q == FULL_QUALITY {
                Ok([[0; 10]; 3])
            } else {
                progs.get(q as usize).copied().ok_or(Error::Invalid("progressif : qualité hors table"))
            }
        };
        let (prog, flags, lens, data) = match kind {
            WBT_TILE_SIMPLE => {
                let f = tb.get(..16).ok_or(Error::Truncated("RFX_PROGRESSIVE_TILE_SIMPLE"))?;
                ([[0; 10]; 3], f[7], [u16_at(f, 8), u16_at(f, 10), u16_at(f, 12)], &tb[16..])
            }
            WBT_TILE_FIRST => {
                let f = tb.get(..17).ok_or(Error::Truncated("RFX_PROGRESSIVE_TILE_FIRST"))?;
                (prog(f[8])?, f[7], [u16_at(f, 9), u16_at(f, 11), u16_at(f, 13)], &tb[17..])
            }
            _ => {
                let f = tb.get(..20).ok_or(Error::Truncated("RFX_PROGRESSIVE_TILE_UPGRADE"))?;
                let lens: [u16; 6] = core::array::from_fn(|i| u16_at(f, 8 + 2 * i));
                let parts = split(&tb[20..], &lens, "RFX_PROGRESSIVE_TILE_UPGRADE")?;
                let key = tile_key(x_idx, y_idx, surf);
                if let Some(key) = key {
                    upgrade(ctx, key, &quant, &prog(f[7])?, &parts)?;
                    frame.tiles.push(key);
                }
                continue;
            }
        };
        let parts = split(data, &lens, "tuile progressive")?;
        if let Some(key) = tile_key(x_idx, y_idx, surf) {
            let diff = flags & RFX_TILE_DIFFERENCE != 0;
            first(ctx, &mut work[0], key, &quant, &prog, diff, extrapolate, [parts[0], parts[1], parts[2]]);
            frame.tiles.push(key);
        }
    }
    Ok(())
}

/// Découpe `data` en morceaux de longueurs `lens` (le reste, tailData, est ignoré).
fn split<'a, const N: usize>(
    data: &'a [u8],
    lens: &[u16; N],
    what: &'static str,
) -> Result<[&'a [u8]; N], Error> {
    let mut rest = data;
    let mut out = [&data[..0]; N];
    for (o, &l) in out.iter_mut().zip(lens) {
        *o = rest.get(..l as usize).ok_or(Error::Truncated(what))?;
        rest = &rest[l as usize..];
    }
    Ok(out)
}

/// Clé de la tuile, ou `None` si elle tombe hors de la surface.
fn tile_key(x_idx: u16, y_idx: u16, surf: &Surface) -> Option<u32> {
    let inside = (x_idx as usize) * TILE < surf.w && (y_idx as usize) * TILE < surf.h;
    inside.then_some((u32::from(y_idx) << 16) | u32::from(x_idx))
}

/// TILE_SIMPLE ou TILE_FIRST : première passe (MS-RDPEGFX 3.3.8.2.1.1).
#[allow(clippy::too_many_arguments)]
fn first(
    ctx: &mut Context,
    buf: &mut [i16; COEFFS],
    key: u32,
    quant: &[Quant; 3],
    prog: &[Quant; 3],
    diff: bool,
    extrapolate: bool,
    data: [&[u8]; 3],
) {
    let tile = ctx.tiles.entry(key).or_insert_with(|| Tile {
        coeffs: vec![[0; COEFFS]; 3],
        sign: Vec::new(),
        bitpos: [[0; 10]; 3],
        extrapolate,
    });
    let complete = prog.iter().flatten().all(|&b| b == 0);
    if complete {
        tile.sign = Vec::new();
    } else if tile.sign.is_empty() {
        tile.sign = vec![[0; COEFFS]; 3];
    }
    let bands = rfx::bands(extrapolate);
    for c in 0..3 {
        rfx::rlgr_decode(Rlgr::Rlgr1, data[c], buf);
        first_pass(buf, &mut tile.coeffs[c], tile.sign.get_mut(c), bands, &shifts(&quant[c], &prog[c]), diff);
    }
    tile.bitpos = *prog;
    tile.extrapolate = extrapolate;
}

/// Première passe d'une composante : `buf` contient la sortie RLGR1 (ProgQ, deltas pour LL),
/// `bands` les bandes (début, longueur) avec LL en dernier.
fn first_pass(
    buf: &mut [i16],
    cur: &mut [i16],
    sign: Option<&mut [i8; COEFFS]>,
    bands: &[(usize, usize)],
    shifts: &[u8],
    diff: bool,
) {
    if let Some(sign) = sign {
        for (s, &v) in sign.iter_mut().zip(buf.iter()) {
            *s = v.signum() as i8;
        }
    }
    let Some(&(ll, ll_len)) = bands.last() else { return };
    // Les deltas de LL3 sont cumulés, même pour une tuile de différence.
    rfx::differential_decode(&mut buf[ll..ll + ll_len]);
    for (&(start, len), &s) in bands.iter().zip(shifts) {
        let (src, dst) = (&buf[start..start + len], &mut cur[start..start + len]);
        for (d, &v) in dst.iter_mut().zip(src) {
            let v = i32::from(v).wrapping_shl(u32::from(s));
            *d = if diff { i32::from(*d).wrapping_add(v) } else { v } as i16;
        }
    }
}

/// TILE_UPGRADE : passe de raffinement (MS-RDPEGFX 3.3.8.2.1.2). Une tuile inconnue est ignorée.
fn upgrade(
    ctx: &mut Context,
    key: u32,
    quant: &[Quant; 3],
    prog: &[Quant; 3],
    parts: &[&[u8]; 6],
) -> Result<(), Error> {
    let Some(tile) = ctx.tiles.get_mut(&key) else { return Ok(()) };
    let mut nbits = [[0u8; 10]; 3];
    for c in 0..3 {
        for b in 0..10 {
            nbits[c][b] = tile.bitpos[c][b]
                .checked_sub(prog[c][b])
                .ok_or(Error::Invalid("progressif : passe de raffinement qui recule"))?;
        }
    }
    // Plus de signes = qualité finale déjà atteinte : aucun bit ne peut encore arriver.
    if tile.sign.len() == 3 {
        let bands = rfx::bands(tile.extrapolate);
        for c in 0..3 {
            let (srl, raw) = (parts[2 * c], parts[2 * c + 1]);
            let sh = shifts(&quant[c], &prog[c]);
            upgrade_pass(&mut tile.coeffs[c], &mut tile.sign[c], bands, &nbits[c], &sh, srl, raw);
        }
    }
    tile.bitpos = *prog;
    if prog.iter().flatten().all(|&b| b == 0) {
        tile.sign = Vec::new();
    }
    Ok(())
}

/// Passe de raffinement d'une composante. LL (dernière bande) : toujours des bits bruts ajoutés.
/// Ailleurs : signe connu → bits bruts (magnitude) ; signe nul → valeur SRL, qui fixe le signe.
fn upgrade_pass(
    cur: &mut [i16],
    sign: &mut [i8],
    bands: &[(usize, usize)],
    nbits: &[u8],
    shifts: &[u8],
    srl: &[u8],
    raw: &[u8],
) {
    let mut srl = Srl::new(srl);
    let mut raw = BitReader::new(raw);
    let last = bands.len() - 1;
    for (b, &(start, len)) in bands.iter().enumerate() {
        let (n, s) = (u32::from(nbits[b]), u32::from(shifts[b]));
        if n == 0 {
            continue;
        }
        let range = start..start + len;
        for (v, sg) in cur[range.clone()].iter_mut().zip(&mut sign[range]) {
            let input = if b == last || *sg > 0 {
                raw.bits(n) as i32
            } else if *sg < 0 {
                -(raw.bits(n) as i32)
            } else {
                let x = srl.next(n);
                *sg = x.signum() as i8;
                x
            };
            *v = i32::from(*v).wrapping_add(input.wrapping_shl(s)) as i16;
        }
    }
}

/// Décodeur SRL (MS-RDPEGFX 3.1.8.1.5) : séries de zéros comme RLGR, valeurs en unaire.
struct Srl<'a> {
    bits: BitReader<'a>,
    kp: u32,
    zeros: u32,
    unary: bool,
}

impl<'a> Srl<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { bits: BitReader::new(data), kp: 8, zeros: 0, unary: false }
    }

    /// Prochain élément ; `nbits` (1 à 15) borne la magnitude à 2^nbits − 1.
    fn next(&mut self, nbits: u32) -> i32 {
        if self.zeros > 0 {
            self.zeros -= 1;
            return 0;
        }
        if !self.unary {
            let k = self.kp / 8;
            if self.bits.bit() == 0 {
                // Série complète de 1 << k zéros, la série continue.
                self.zeros = (1 << k) - 1;
                self.kp = (self.kp + 4).min(80);
                return 0;
            }
            self.zeros = self.bits.bits(k);
            self.kp = self.kp.saturating_sub(6);
            self.unary = true;
            if self.zeros > 0 {
                self.zeros -= 1;
                return 0;
            }
        }
        self.unary = false;
        let negative = self.bits.bit() == 1;
        let max = (1u32 << nbits.min(15)) - 1;
        let mut mag = 1;
        while mag < max && self.bits.bit() == 0 {
            mag += 1;
        }
        if negative { -(mag as i32) } else { mag as i32 }
    }
}

/// Peint les tuiles de la trame, découpées par ses rectangles.
fn paint(
    ctx: &Context,
    work: &mut [[i16; COEFFS]],
    mut frame: Frame,
    surf: &mut Surface,
    updated: &mut Vec<Rect>,
) {
    frame.tiles.sort_unstable();
    frame.tiles.dedup();
    let [planes @ .., tmp] = work else { return };
    let Some(planes) = planes.get_mut(1..4) else { return };
    for key in &frame.tiles {
        let Some(tile) = ctx.tiles.get(key) else { continue };
        let (tx, ty) = ((key & 0xFFFF) as usize * TILE, (key >> 16) as usize * TILE);
        let clip = |&(x, y, w, h): &(usize, usize, usize, usize)| {
            let (x0, y0) = (x.max(tx), y.max(ty));
            let (x1, y1) = ((x + w).min(tx + TILE), (y + h).min(ty + TILE));
            (x0 < x1 && y0 < y1).then_some((x0, y0, x1 - x0, y1 - y0))
        };
        if !frame.rects.iter().any(|r| clip(r).is_some()) {
            continue;
        }
        for (p, c) in planes.iter_mut().zip(&tile.coeffs) {
            *p = *c;
            rfx::idwt(p, tmp, tile.extrapolate);
        }
        for (x, y, w, h) in frame.rects.iter().filter_map(clip) {
            let dst = &mut surf.px[(y * surf.w + x) * 4..];
            rfx::ycbcr_to_rgba(&planes[0], &planes[1], &planes[2], (x - tx, y - ty, w, h), dst, surf.w * 4);
        }
    }
    updated.extend(frame.rects.iter().map(|&(x, y, w, h)| (x as u32, y as u32, w as u32, h as u32)));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MS-RDPEGFX 4.1.2 : une composante de 14 coefficients, bandes HL (5), LH (5), LL (4) ;
    /// BitPos 25 % = (4, 3, 2), 50 % = (0, 1, 2), 100 % = 0. Les décalages valent BitPos
    /// (l'exemple ne déquantifie que par PQF).
    #[test]
    fn spec_example_passes() {
        const BANDS: [(usize, usize); 3] = [(0, 5), (5, 5), (10, 4)];
        let mut cur = [0i16; 14];
        let mut sign = [0i8; COEFFS];
        let mut buf = [0i16; 14];

        // Trame 1 à 25 % (4.1.2.2.1) : tuile d'origine.
        rfx::rlgr_decode(Rlgr::Rlgr1, &[0xA8, 0x62, 0x6D, 0xFF, 0xF7, 0x00], &mut buf);
        first_pass(&mut buf, &mut cur, Some(&mut sign), &BANDS, &[4, 3, 2], false);
        assert_eq!(cur, [-32, 0, 0, 0, 0, 0, 0, 0, 0, 8, 12, 16, -12, 12]);
        assert_eq!(sign[..10], [-1, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        // Trame 1 à 50 % (4.1.2.2.2).
        let srl = [0xA0, 0x01, 0x80, 0x00, 0xC9, 0x49, 0xE0];
        upgrade_pass(&mut cur, &mut sign, &BANDS, &[4, 2, 0], &[0, 1, 2], &srl, &[0x20]);
        assert_eq!(cur, [-34, -13, 15, -3, 0, 0, -6, 4, -2, 8, 12, 16, -12, 12]);
        assert_eq!(sign[..10], [-1, -1, 1, -1, 0, 0, -1, 1, -1, 1]);

        // Trame 2 à 25 % (4.1.2.2.3) : tuile de différence, LL cumulé quand même.
        rfx::rlgr_decode(Rlgr::Rlgr1, &[0x88, 0x76, 0xBD, 0xFF, 0xFE, 0xF2], &mut buf);
        first_pass(&mut buf, &mut cur, Some(&mut sign), &BANDS, &[4, 3, 2], true);
        assert_eq!(cur, [-2, -13, 15, -3, 0, 0, -6, 4, -2, 8, 24, 12, 16, 4]);
        assert_eq!(sign[..10], [1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        // Trame 2 à 50 % (4.1.2.2.4) puis 100 % (4.1.2.2.5). Erratum : les octets SRL donnés par
        // 4.1.2.1.4 (80 07 00 16 9C) ne codent pas les valeurs de ses propres tables (ils donnent
        // −2 au lieu de 1 en 5e position) ; ceux-ci sont l'encodage de ces valeurs selon 3.1.8.1.5,
        // méthode qui reproduit à l'octet près l'exemple de la trame 1 (A0 01 80 00 C9 49 E0).
        upgrade_pass(
            &mut cur,
            &mut sign,
            &BANDS,
            &[4, 2, 0],
            &[0, 1, 2],
            &[0x80, 0x07, 0x00, 0x15, 0xA7, 0x00],
            &[0],
        );
        assert_eq!(cur, [-2, -2, 3, -3, 1, 2, -6, 4, -2, 2, 24, 12, 16, 4]);
        assert_eq!(sign[..10], [1, 1, -1, 0, 1, 1, 0, 0, 0, -1]);
        upgrade_pass(&mut cur, &mut sign, &BANDS, &[0, 1, 2], &[0, 0, 0], &[0xB0], &[0xC6, 0x40]);
        assert_eq!(cur, [-2, -2, 3, -3, 1, 3, -7, 5, -2, 1, 24, 13, 18, 5]);
        assert_eq!(sign[..10], [1, 1, -1, 0, 1, 1, -1, 1, 0, -1]);
    }

    fn blk(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut v = kind.to_le_bytes().to_vec();
        v.extend_from_slice(&(body.len() as u32 + 6).to_le_bytes());
        v.extend_from_slice(body);
        v
    }

    /// Région 64×64 extrapolée, quant 6 partout, une table progressive à BitPos 2 partout.
    fn region_blk(rect: (u16, u16, u16, u16), tiles: &[Vec<u8>]) -> Vec<u8> {
        let tiles: Vec<u8> = tiles.concat();
        let mut b = vec![64];
        b.extend_from_slice(&1u16.to_le_bytes()); // numRects
        b.extend_from_slice(&[1, 1, RFX_DWT_REDUCE_EXTRAPOLATE]);
        b.extend_from_slice(&1u16.to_le_bytes()); // numTiles (une ou plusieurs, borné par la taille)
        b.extend_from_slice(&(tiles.len() as u32).to_le_bytes());
        for v in [rect.0, rect.1, rect.2, rect.3] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&[0x66; 5]);
        b.push(50);
        b.extend_from_slice(&[0x22; 15]);
        b.extend_from_slice(&tiles);
        blk(WBT_REGION, &b)
    }

    fn frame(regions: &[Vec<u8>]) -> Vec<u8> {
        let mut s = blk(0xCCC0, &[0xCA, 0xAC, 0xCC, 0xCA, 0x00, 0x01]);
        s.extend(blk(WBT_CONTEXT, &[0, 64, 0, 0]));
        s.extend(blk(WBT_FRAME_BEGIN, &[0, 0, 0, 0, regions.len() as u8, 0]));
        for r in regions {
            s.extend_from_slice(r);
        }
        s.extend(blk(WBT_FRAME_END, &[]));
        s
    }

    /// Tuile SIMPLE ou FIRST (qualité 0) ; LL3 constant = `dc` en Y.
    fn tile(kind: u16, x: u16, y: u16, dc: i16) -> Vec<u8> {
        let mut coeffs = [0i16; COEFFS];
        coeffs[4015] = dc; // premier delta de LL3 (disposition extrapolée), le reste nul
        let yd = rfx::rlgr1_encode(&coeffs);
        let mut b = vec![0, 0, 0];
        b.extend_from_slice(&x.to_le_bytes());
        b.extend_from_slice(&y.to_le_bytes());
        b.push(0);
        if kind == WBT_TILE_FIRST {
            b.push(0);
        }
        for l in [yd.len() as u16, 0, 0, 0] {
            b.extend_from_slice(&l.to_le_bytes());
        }
        b.extend_from_slice(&yd);
        blk(kind, &b)
    }

    fn px(s: &[u8], w: usize, x: usize, y: usize) -> [u8; 4] {
        s[(y * w + x) * 4..][..4].try_into().unwrap()
    }

    #[test]
    fn simple_tile_painted_inside_rect_only() {
        let (w, h) = (100usize, 80usize);
        let mut surf = vec![0u8; w * h * 4];
        let mut p = Progressive::new();
        // DC 10 avec q = 6 (décalage 5) → Y = 10 + 128 partout dans la tuile (1, 0).
        let s = frame(&[region_blk((70, 10, 40, 20), &[tile(WBT_TILE_SIMPLE, 1, 0, 10)])]);
        let rects = p.decode(7, &s, &mut surf, w as u32, h as u32).unwrap();
        assert_eq!(rects, [(70, 10, 30, 20)]);
        assert_eq!(px(&surf, w, 70, 10), [138, 138, 138, 255]);
        assert_eq!(px(&surf, w, 99, 29), [138, 138, 138, 255]);
        assert_eq!(px(&surf, w, 69, 10), [0; 4]);
        assert_eq!(px(&surf, w, 70, 30), [0; 4]);
        assert!(p.contexts[&7].tiles[&1].sign.is_empty());
    }

    #[test]
    fn first_then_upgrade() {
        let (w, h) = (64usize, 64usize);
        let mut surf = vec![0u8; w * h * 4];
        let mut p = Progressive::new();
        // Passe 1 : BitPos 2 → décalage 6 + 2 − 1 = 7, DC 10 → Y = 40 + 128.
        let s = frame(&[region_blk((0, 0, 64, 64), &[tile(WBT_TILE_FIRST, 0, 0, 10)])]);
        p.decode(1, &s, &mut surf, 64, 64).unwrap();
        assert_eq!(px(&surf, w, 33, 17), [168, 168, 168, 255]);
        assert_eq!(p.contexts[&1].tiles[&0].sign.len(), 3);

        // Passe finale : 2 bits bruts « 01 » par coefficient LL3 (81) → +1 en Y ; SRL vide =
        // que des zéros pour les autres bandes.
        let mut raw = vec![0x55u8; 20];
        raw.push(0x40);
        let mut b = vec![0, 0, 0, 0, 0, 0, 0, FULL_QUALITY];
        for l in [0u16, raw.len() as u16, 0, 0, 0, 0] {
            b.extend_from_slice(&l.to_le_bytes());
        }
        b.extend_from_slice(&raw);
        let s = frame(&[region_blk((0, 0, 64, 64), &[blk(WBT_TILE_UPGRADE, &b)])]);
        p.decode(1, &s, &mut surf, 64, 64).unwrap();
        assert_eq!(px(&surf, w, 0, 0), [169, 169, 169, 255]);
        assert_eq!(px(&surf, w, 63, 63), [169, 169, 169, 255]);
        let t = &p.contexts[&1].tiles[&0];
        assert!(t.sign.is_empty() && t.bitpos == [[0; 10]; 3]);

        // Une passe qui recule est refusée ; après suppression du contexte, l'état disparaît.
        let s = frame(&[region_blk(
            (0, 0, 64, 64),
            &[blk(WBT_TILE_UPGRADE, &{
                let mut b = vec![0, 0, 0, 0, 0, 0, 0, 0];
                b.extend_from_slice(&[0; 12]);
                b
            })],
        )]);
        assert!(p.decode(1, &s, &mut surf, 64, 64).is_err());
        p.delete_context(1);
        assert!(p.contexts.is_empty());
    }

    #[test]
    fn tiles_outside_surface_and_bad_indexes() {
        let mut surf = vec![0u8; 64 * 64 * 4];
        let mut p = Progressive::new();
        let s = frame(&[region_blk((0, 0, 64, 64), &[tile(WBT_TILE_SIMPLE, 5, 9, 3)])]);
        assert!(p.decode(0, &s, &mut surf, 64, 64).is_ok());
        assert!(p.contexts[&0].tiles.is_empty());
        // Index de quantification 1 alors qu'il n'y a qu'une table.
        let mut t = tile(WBT_TILE_SIMPLE, 0, 0, 3);
        t[6] = 1;
        let s = frame(&[region_blk((0, 0, 64, 64), &[t])]);
        assert!(p.decode(0, &s, &mut surf, 64, 64).is_err());
        // Surface trop petite pour ses dimensions annoncées.
        assert!(p.decode(0, &s, &mut surf, 65, 64).is_err());
    }

    #[test]
    fn truncated_and_garbage_never_panic() {
        let mut surf = vec![0u8; 128 * 64 * 4];
        let s = frame(&[region_blk(
            (0, 0, 128, 64),
            &[tile(WBT_TILE_FIRST, 0, 0, 7), tile(WBT_TILE_SIMPLE, 1, 0, -4)],
        )]);
        let mut p = Progressive::new();
        assert!(p.decode(0, &s, &mut surf, 128, 64).is_ok());
        for n in 0..s.len() {
            let _ = p.decode(0, &s[..n], &mut surf, 128, 64);
        }
        // Octets aléatoires, avec ou sans en-têtes de blocs valides devant.
        let mut seed = 0xDEAD_BEEFu32;
        for round in 0..300 {
            let mut g = if round % 2 == 0 { s.clone() } else { Vec::new() };
            for _ in 0..64 {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                g.push((seed >> 24) as u8);
            }
            if round % 6 == 0 {
                let i = (seed as usize) % s.len();
                g[i] ^= 0x5A;
            }
            let _ = p.decode(round, &g, &mut surf, 128, 64);
        }
    }
}
