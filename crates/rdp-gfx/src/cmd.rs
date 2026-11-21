//! Commandes RDPGFX (MS-RDPEGFX 2.2.2) et leur effet sur les surfaces.

use alloc::{format, vec, vec::Vec};

use crate::{
    Cached, Error, Gfx, MAX_CACHE_BYTES, MAX_CACHE_SLOTS, MAX_PIXELS_PER_COMMAND, MAX_SIDE,
    MAX_SURFACE_BYTES, MAX_SURFACES, Out, PendingAvc, Rect, Surface,
};

mod id {
    pub const WIRE_TO_SURFACE_1: u16 = 0x0001;
    pub const WIRE_TO_SURFACE_2: u16 = 0x0002;
    pub const DELETE_ENCODING_CONTEXT: u16 = 0x0003;
    pub const SOLID_FILL: u16 = 0x0004;
    pub const SURFACE_TO_SURFACE: u16 = 0x0005;
    pub const SURFACE_TO_CACHE: u16 = 0x0006;
    pub const CACHE_TO_SURFACE: u16 = 0x0007;
    pub const EVICT_CACHE_ENTRY: u16 = 0x0008;
    pub const CREATE_SURFACE: u16 = 0x0009;
    pub const DELETE_SURFACE: u16 = 0x000A;
    pub const START_FRAME: u16 = 0x000B;
    pub const END_FRAME: u16 = 0x000C;
    pub const FRAME_ACKNOWLEDGE: u16 = 0x000D;
    pub const RESET_GRAPHICS: u16 = 0x000E;
    pub const MAP_SURFACE_TO_OUTPUT: u16 = 0x000F;
    pub const MAP_SURFACE_TO_SCALED_OUTPUT: u16 = 0x0017;
    pub const CAPS_ADVERTISE: u16 = 0x0012;
    pub const CAPS_CONFIRM: u16 = 0x0013;
}

mod codec {
    pub const UNCOMPRESSED: u16 = 0x0000;
    pub const CLEARCODEC: u16 = 0x0008;
    pub const PLANAR: u16 = 0x000A;
    pub const AVC420: u16 = 0x000B;
    pub const ALPHA: u16 = 0x000C;
    pub const AVC444: u16 = 0x000E;
    pub const AVC444V2: u16 = 0x000F;
}

/// H.264 demandé au serveur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Avc {
    /// Pas de H.264 : RemoteFX Progressive, ClearCodec, Planar.
    Off,
    /// AVC420 et AVC444 (v1/v2).
    Full,
}

/// Annonce des capacités, le serveur choisit la plus haute qu'il connaît :
/// - EGFX 10.7 : AVC420 et AVC444 (v1/v2), sauf AVC_DISABLED (0x20) sans décodeur H.264 ;
///   SCALEDMAP_DISABLE (0x80) : la sortie suit la taille des surfaces, le navigateur met à l'échelle ;
/// - EGFX 8.1 en repli : AVC420 avec SMALL_CACHE (seules combinaisons admises par la spec).
///
/// Pas de mode « AVC420 seul » : la 10.x ne sait pas exclure l'AVC444 (AVC_THINCLIENT le préfère),
/// et en 8.1 Windows ne réserve le H.264 qu'aux zones animées (mesuré le 21/10/2026).
pub fn caps_advertise(avc: Avc) -> Vec<u8> {
    let sets: &[(u32, u32)] = match avc {
        Avc::Full => &[(0x000A_0701, 0x02 | 0x80), (0x0008_0105, 0x02 | 0x10)],
        Avc::Off => &[(0x000A_0701, 0x02 | 0x20 | 0x80), (0x0008_0105, 0x02)],
    };
    let len = 8 + 2 + sets.len() * 12;
    let mut p = Vec::with_capacity(len);
    p.extend_from_slice(&id::CAPS_ADVERTISE.to_le_bytes());
    p.extend_from_slice(&0u16.to_le_bytes());
    p.extend_from_slice(&(len as u32).to_le_bytes());
    p.extend_from_slice(&(sets.len() as u16).to_le_bytes());
    for &(version, flags) in sets {
        p.extend_from_slice(&version.to_le_bytes());
        p.extend_from_slice(&4u32.to_le_bytes());
        p.extend_from_slice(&flags.to_le_bytes());
    }
    p
}

/// RFX_AVC420_BITMAP_STREAM : (régions, flux Annex B). La surface totale des régions entre dans
/// le budget de pixels d'une commande : chaque région coûte une conversion de couleur.
fn avc420_stream(data: &[u8], budget: &mut Budget) -> Result<(Vec<Rect>, Vec<u8>), Error> {
    let mut m = R { b: data, p: 0 };
    let n = m.u32()? as usize;
    if n > 4096 {
        return Err(Error::Invalid("trop de régions H.264"));
    }
    let mut rects = Vec::with_capacity(n);
    for _ in 0..n {
        let r = m.rect16()?;
        budget.spend(r.w, r.h)?;
        rects.push(r);
    }
    m.bytes(n * 2)?; // quantQualityVals, informatifs
    Ok((rects, data[m.p..].to_vec()))
}

struct R<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> R<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let s = self.b.get(self.p..self.p + n).ok_or(Error::Truncated("PDU RDPGFX"))?;
        self.p += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.bytes(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        let b = self.bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    /// RDPGFX_RECT16 : bords droit et bas exclusifs.
    fn rect16(&mut self) -> Result<Rect, Error> {
        let (l, t, r, b) = (self.u16()? as u32, self.u16()? as u32, self.u16()? as u32, self.u16()? as u32);
        if r < l || b < t {
            return Err(Error::Invalid("rectangle inversé"));
        }
        Ok(Rect { x: l, y: t, w: r - l, h: b - t })
    }
    fn point16(&mut self) -> Result<(u32, u32), Error> {
        Ok((self.u16()? as u32, self.u16()? as u32))
    }
}

/// Pixels qu'une commande a encore le droit de toucher.
struct Budget(u64);

impl Budget {
    fn new() -> Self {
        Budget(MAX_PIXELS_PER_COMMAND)
    }
    fn spend(&mut self, w: u32, h: u32) -> Result<(), Error> {
        self.0 = self.0.checked_sub(w as u64 * h as u64).ok_or(Error::Invalid("commande trop coûteuse"))?;
        Ok(())
    }
}

/// Copie une zone RGBA (stride `sw`) vers une autre (stride `dw`), bornée par l'appelant.
#[allow(clippy::too_many_arguments)]
fn blit(src: &[u8], sw: u32, sx: u32, sy: u32, dst: &mut [u8], dw: u32, dx: u32, dy: u32, w: u32, h: u32) {
    for row in 0..h {
        let so = (((sy + row) * sw + sx) * 4) as usize;
        let d = (((dy + row) * dw + dx) * 4) as usize;
        let n = (w * 4) as usize;
        dst[d..d + n].copy_from_slice(&src[so..so + n]);
    }
}

fn extract(s: &Surface, r: Rect) -> Vec<u8> {
    let mut v = vec![0u8; (r.w * r.h * 4) as usize];
    blit(&s.rgba, s.width, r.x, r.y, &mut v, r.w, 0, 0, r.w, r.h);
    v
}

impl Gfx {
    pub(crate) fn command(&mut self, pdu: &[u8], out: &mut Vec<Out>) -> Result<(), Error> {
        let mut r = R { b: pdu, p: 0 };
        let cmd = r.u16()?;
        r.bytes(6)?;
        match cmd {
            id::CAPS_CONFIRM | id::FRAME_ACKNOWLEDGE | id::CAPS_ADVERTISE => {}
            // L'état des tuiles Progressive vit avec la SURFACE : les tuiles « différence » d'un
            // nouveau contexte s'ajoutent aux coefficients déjà décodés au même endroit (mesuré sur
            // Windows : effacer l'état ici laisse des tuiles grises).
            id::DELETE_ENCODING_CONTEXT => {}
            id::RESET_GRAPHICS => {
                let (w, h) = (r.u32()?, r.u32()?);
                if w == 0 || h == 0 || w > MAX_SIDE || h > MAX_SIDE {
                    return Err(Error::Invalid("taille de sortie invalide"));
                }
                // TS_MONITOR_DEF (bords inclus, relatifs à l'écran principal, négatifs possibles).
                let count = r.u32()?.min(16) as usize;
                let mut defs = Vec::with_capacity(count);
                for _ in 0..count {
                    let mut i32_ = || -> Result<i32, Error> { Ok(r.u32()? as i32) };
                    let (left, top, right, bottom) = (i32_()?, i32_()?, i32_()?, i32_()?);
                    r.u32()?; // flags
                    if right >= left && bottom >= top {
                        defs.push((left, top, right, bottom));
                    }
                }
                let (min_x, min_y) = (
                    defs.iter().map(|d| d.0).min().unwrap_or(0),
                    defs.iter().map(|d| d.1).min().unwrap_or(0),
                );
                let monitors: Vec<Rect> = defs
                    .iter()
                    .filter_map(|&(l, t, rr, b)| {
                        // En i64 : des bords extrêmes (i32::MIN et i32::MAX) débordent en i32.
                        let sat = |v: i64| v.clamp(0, i64::from(u32::MAX)) as u32;
                        let (l, t, rr, b) = (i64::from(l), i64::from(t), i64::from(rr), i64::from(b));
                        Rect {
                            x: sat(l - i64::from(min_x)),
                            y: sat(t - i64::from(min_y)),
                            w: sat(rr - l + 1),
                            h: sat(b - t + 1),
                        }
                        .clip(w, h)
                    })
                    .collect();
                self.width = w;
                self.height = h;
                self.output = vec![0u8; (w * h * 4) as usize];
                for px in self.output.as_chunks_mut::<4>().0 {
                    px[3] = 0xFF;
                }
                for s in self.surfaces.values_mut() {
                    s.origin = None;
                }
                self.damage.clear();
                out.push(Out::Reset { width: w, height: h, monitors });
            }
            id::CREATE_SURFACE => {
                let (sid, w, h) = (r.u16()?, r.u16()? as u32, r.u16()? as u32);
                if w == 0 || h == 0 || w > MAX_SIDE || h > MAX_SIDE {
                    return Err(Error::Invalid("taille de surface invalide"));
                }
                let bytes = (w * h * 4) as usize;
                let replaced = self.surfaces.get(&sid).map_or(0, |s| s.rgba.len());
                let total = self.surface_bytes - replaced + bytes;
                if total > MAX_SURFACE_BYTES || (replaced == 0 && self.surfaces.len() >= MAX_SURFACES) {
                    return Err(Error::Invalid("trop de surfaces ou de mémoire de surface"));
                }
                let mut rgba = vec![0u8; bytes];
                for px in rgba.as_chunks_mut::<4>().0 {
                    px[3] = 0xFF;
                }
                self.surface_bytes = total;
                self.progressive.delete_context(sid as u32);
                if let Some(old) = self.surfaces.get(&sid).and_then(|s| s.p444.as_ref()) {
                    self.surface_bytes -= old.bytes();
                }
                self.surfaces.insert(sid, Surface { width: w, height: h, rgba, origin: None, p444: None });
            }
            id::DELETE_SURFACE => {
                let sid = r.u16()?;
                if let Some(s) = self.surfaces.remove(&sid) {
                    self.surface_bytes -= s.rgba.len() + s.p444.as_ref().map_or(0, |p| p.bytes());
                }
                self.progressive.delete_context(sid as u32);
            }
            id::MAP_SURFACE_TO_OUTPUT => {
                let sid = r.u16()?;
                r.u16()?;
                let (x, y) = (r.u32()?, r.u32()?);
                let s = self.surface_mut(sid)?;
                s.origin = Some((x, y));
                let full = Rect { x: 0, y: 0, w: s.width, h: s.height };
                self.touch(sid, full, Some((x, y)));
            }
            id::MAP_SURFACE_TO_SCALED_OUTPUT => {
                // Mesuré : Windows l'emploie en EGFX 10.x. Sans mise à l'échelle demandée (cible =
                // taille de la surface), c'est un placement ordinaire ; sinon placé à l'échelle 1.
                let sid = r.u16()?;
                r.u16()?;
                let (x, y, tw, th) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?);
                let s = self.surface_mut(sid)?;
                if (tw, th) != (s.width, s.height) {
                    out.push(Out::Ignored(format!(
                        "mise à l'échelle {}×{} → {tw}×{th} non gérée, placée telle quelle",
                        s.width, s.height
                    )));
                }
                let s = self.surface_mut(sid)?;
                s.origin = Some((x, y));
                let full = Rect { x: 0, y: 0, w: s.width, h: s.height };
                self.touch(sid, full, Some((x, y)));
            }
            id::START_FRAME => {}
            id::END_FRAME => {
                let frame_id = r.u32()?;
                self.frames_decoded = self.frames_decoded.wrapping_add(1);
                // queueDepth 0 = inconnu ; totalFramesDecoded est un COMPTEUR (mesuré : y mettre
                // l'identifiant d'image fait tomber le serveur en ERRINFO_GRAPHICSSUBSYSTEMFAILED).
                let mut ack = Vec::with_capacity(20);
                ack.extend_from_slice(&id::FRAME_ACKNOWLEDGE.to_le_bytes());
                ack.extend_from_slice(&0u16.to_le_bytes());
                ack.extend_from_slice(&20u32.to_le_bytes());
                ack.extend_from_slice(&0u32.to_le_bytes());
                ack.extend_from_slice(&frame_id.to_le_bytes());
                ack.extend_from_slice(&self.frames_decoded.to_le_bytes());
                out.push(Out::Present { damage: core::mem::take(&mut self.damage) });
                out.push(Out::Send(ack));
            }
            id::SOLID_FILL => {
                let sid = r.u16()?;
                let c = r.bytes(4)?;
                let px = [c[2], c[1], c[0], 0xFF];
                let n = r.u16()?;
                let s = self.surface_mut(sid)?;
                let (sw, sh, origin) = (s.width, s.height, s.origin);
                let mut touched = Vec::new();
                let mut budget = Budget::new();
                for _ in 0..n {
                    let Some(rect) = r.rect16()?.clip(sw, sh) else { continue };
                    budget.spend(rect.w, rect.h)?;
                    let s = self.surface_mut(sid)?;
                    for row in rect.y..rect.y + rect.h {
                        let o = ((row * sw + rect.x) * 4) as usize;
                        for p in s.rgba[o..o + (rect.w * 4) as usize].as_chunks_mut::<4>().0 {
                            p.copy_from_slice(&px);
                        }
                    }
                    touched.push(rect);
                }
                for t in touched {
                    self.touch(sid, t, origin);
                }
            }
            id::SURFACE_TO_SURFACE => {
                let (src_id, dst_id) = (r.u16()?, r.u16()?);
                let src_rect = r.rect16()?;
                let n = r.u16()?;
                let src = self.surfaces.get(&src_id).ok_or(Error::Invalid("surface source inconnue"))?;
                let Some(src_rect) = src_rect.clip(src.width, src.height) else { return Ok(()) };
                let pixels = extract(src, src_rect);
                let mut budget = Budget::new();
                for _ in 0..n {
                    let (x, y) = r.point16()?;
                    budget.spend(src_rect.w, src_rect.h)?;
                    self.put(dst_id, x, y, src_rect.w, src_rect.h, &pixels)?;
                }
            }
            id::SURFACE_TO_CACHE => {
                let sid = r.u16()?;
                r.bytes(8)?; // cacheKey
                let slot = r.u16()?;
                let rect = r.rect16()?;
                if slot == 0 || slot > MAX_CACHE_SLOTS {
                    return Err(Error::Invalid("emplacement de cache hors limites"));
                }
                let s = self.surfaces.get(&sid).ok_or(Error::Invalid("surface inconnue"))?;
                let Some(rect) = rect.clip(s.width, s.height) else { return Ok(()) };
                let bytes = (rect.w * rect.h * 4) as usize;
                let replaced = self.cache.get(&slot).map_or(0, |c| c.rgba.len());
                let total = self.cache_bytes - replaced + bytes;
                if total > MAX_CACHE_BYTES {
                    return Err(Error::Invalid("cache EGFX plein (le serveur doit évincer)"));
                }
                let rgba = extract(s, rect);
                self.cache_bytes = total;
                self.cache.insert(slot, Cached { width: rect.w, height: rect.h, rgba });
            }
            id::CACHE_TO_SURFACE => {
                let (slot, sid, n) = (r.u16()?, r.u16()?, r.u16()?);
                let c = self.cache.get(&slot).ok_or(Error::Invalid("emplacement de cache vide"))?;
                let (w, h, pixels) = (c.width, c.height, c.rgba.clone());
                let mut budget = Budget::new();
                for _ in 0..n {
                    let (x, y) = r.point16()?;
                    budget.spend(w, h)?;
                    self.put(sid, x, y, w, h, &pixels)?;
                }
            }
            id::EVICT_CACHE_ENTRY => {
                if let Some(c) = self.cache.remove(&r.u16()?) {
                    self.cache_bytes -= c.rgba.len();
                }
            }
            id::WIRE_TO_SURFACE_1 => self.wire_to_surface_1(&mut r, out)?,
            id::WIRE_TO_SURFACE_2 => {
                // RemoteFX Progressive (codecId 0x0009) : décodé directement dans la surface.
                let sid = r.u16()?;
                let codec_id = r.u16()?;
                let context = r.u32()?;
                let _pixel_format = r.u8()?;
                let len = r.u32()? as usize;
                let data = r.bytes(len)?;
                if codec_id != 0x0009 {
                    out.push(Out::Ignored(format!(
                        "WireToSurface2 codec 0x{codec_id:04x} non pris en charge"
                    )));
                    return Ok(());
                }
                let s = self.surfaces.get_mut(&sid).ok_or(Error::Invalid("surface inconnue"))?;
                let (w, h, origin) = (s.width, s.height, s.origin);
                let _ = context;
                let rects = self.progressive.decode(sid as u32, data, &mut s.rgba, w, h)?;
                for (x, y, rw, rh) in rects {
                    if let Some(rect) = (Rect { x, y, w: rw, h: rh }).clip(w, h) {
                        self.touch(sid, rect, origin);
                    }
                }
            }
            other => out.push(Out::Ignored(format!("commande RDPGFX 0x{other:04x} ignorée"))),
        }
        Ok(())
    }

    /// Pose un bloc RGBA `w`×`h` sur une surface en (x, y), découpé aux bords.
    fn put(&mut self, sid: u16, x: u32, y: u32, w: u32, h: u32, pixels: &[u8]) -> Result<(), Error> {
        let s = self.surface_mut(sid)?;
        let Some(dst) = (Rect { x, y, w, h }).clip(s.width, s.height) else { return Ok(()) };
        let sw = s.width;
        blit(pixels, w, 0, 0, &mut s.rgba, sw, dst.x, dst.y, dst.w, dst.h);
        let origin = s.origin;
        self.touch(sid, dst, origin);
        Ok(())
    }

    fn wire_to_surface_1(&mut self, r: &mut R, out: &mut Vec<Out>) -> Result<(), Error> {
        let sid = r.u16()?;
        let codec_id = r.u16()?;
        let _pixel_format = r.u8()?;
        let dest = r.rect16()?;
        let len = r.u32()? as usize;
        let data = r.bytes(len)?;
        let s = self.surface_mut(sid)?;
        let (sw, sh) = (s.width, s.height);
        if dest.x + dest.w > sw || dest.y + dest.h > sh {
            return Err(Error::Invalid("rectangle de destination hors surface"));
        }
        let (w, h) = (dest.w, dest.h);
        match codec_id {
            codec::UNCOMPRESSED => {
                if data.len() < (w * h * 4) as usize {
                    return Err(Error::Truncated("bitmap non compressé"));
                }
                let mut rgba = vec![0u8; (w * h * 4) as usize];
                for (d, s) in rgba.as_chunks_mut::<4>().0.iter_mut().zip(data.as_chunks::<4>().0) {
                    d.copy_from_slice(&[s[2], s[1], s[0], 0xFF]);
                }
                self.put(sid, dest.x, dest.y, w, h, &rgba)?;
            }
            codec::PLANAR => {
                let mut rgba = vec![0u8; (w * h * 4) as usize];
                rdp_codecs::planar::decode(data, w, h, &mut rgba)?;
                for p in rgba.as_chunks_mut::<4>().0 {
                    p[3] = 0xFF;
                }
                self.put(sid, dest.x, dest.y, w, h, &rgba)?;
            }
            codec::CLEARCODEC => {
                // ClearCodec compose sur le contenu existant : on lui passe la zone actuelle.
                let s = self.surface_mut(sid)?;
                let mut rgba = extract(s, dest);
                self.clear.decode(data, w, h, &mut rgba)?;
                self.put(sid, dest.x, dest.y, w, h, &rgba)?;
            }
            codec::ALPHA => {
                // Opacité seule ; le bureau est composé opaque, rien à afficher en plus.
            }
            codec::AVC420 => {
                let (rects, stream) = avc420_stream(data, &mut Budget::new())?;
                self.pending_avc = Some(PendingAvc { surface: sid, rects, aux: None });
                out.push(Out::Avc420 { data: stream });
            }
            codec::AVC444 | codec::AVC444V2 => {
                // avc420EncodedBitstreamInfo : taille du 1er sous-flux (30 bits) et LC (2 bits).
                let mut m = R { b: data, p: 0 };
                let info = m.u32()?;
                let (cb1, lc) = ((info & 0x3FFF_FFFF) as usize, info >> 30);
                let body = &data[4..];
                let (main, aux) = match lc {
                    0 => {
                        let first = body.get(..cb1).ok_or(Error::Truncated("sous-flux AVC444"))?;
                        (Some(first), Some(&body[cb1..]))
                    }
                    1 => (Some(body.get(..cb1).ok_or(Error::Truncated("sous-flux AVC444"))?), None),
                    2 => (None, Some(body)),
                    _ => return Err(Error::Invalid("AVC444 : LC invalide")),
                };
                let mut budget = Budget::new();
                let main = main.map(|d| avc420_stream(d, &mut budget)).transpose()?;
                let aux = aux.map(|d| avc420_stream(d, &mut budget)).transpose()?;
                let v2 = codec_id == codec::AVC444V2;
                self.pending_avc = Some(PendingAvc {
                    surface: sid,
                    rects: main.as_ref().map(|(r, _)| r.clone()).unwrap_or_default(),
                    aux: aux.as_ref().map(|(r, _)| (r.clone(), v2)),
                });
                out.push(Out::Avc444 { main: main.map(|(_, s)| s), aux: aux.map(|(_, s)| s) });
            }
            other => out.push(Out::Ignored(format!("codec EGFX 0x{other:04x} non pris en charge"))),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn caps_off_disables_avc() {
        let p = super::caps_advertise(super::Avc::Off);
        assert_eq!(&p[10..14], &0x000A_0701u32.to_le_bytes());
        assert_eq!(&p[18..22], &(0x02u32 | 0x20 | 0x80).to_le_bytes(), "AVC_DISABLED en 10.7");
        assert_eq!(&p[30..34], &0x02u32.to_le_bytes(), "8.1 sans AVC420_ENABLED");
    }

    use super::*;

    /// Emballe des PDU RDPGFX dans un segment ZGFX non compressé.
    fn wrap(pdus: &[Vec<u8>]) -> Vec<u8> {
        let mut v = vec![0xE0, 0x04];
        for p in pdus {
            v.extend_from_slice(p);
        }
        v
    }

    fn pdu(cmd: u16, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&cmd.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&((body.len() + 8) as u32).to_le_bytes());
        v.extend_from_slice(body);
        v
    }

    fn le(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    #[test]
    fn surface_fill_cache_and_present() {
        let mut g = Gfx::new();
        let reset = pdu(id::RESET_GRAPHICS, &le(&[&8u32.to_le_bytes(), &4u32.to_le_bytes(), &[0; 4]]));
        let create = pdu(
            id::CREATE_SURFACE,
            &le(&[&1u16.to_le_bytes(), &8u16.to_le_bytes(), &4u16.to_le_bytes(), &[0x20]]),
        );
        let map = pdu(
            id::MAP_SURFACE_TO_OUTPUT,
            &le(&[&1u16.to_le_bytes(), &[0, 0], &0u32.to_le_bytes(), &0u32.to_le_bytes()]),
        );
        // Remplit (0,0)-(2,2) en rouge (BGRA 00 00 FF FF).
        let fill = pdu(
            id::SOLID_FILL,
            &le(&[&1u16.to_le_bytes(), &[0, 0, 0xFF, 0xFF], &1u16.to_le_bytes(), &[0, 0, 0, 0, 2, 0, 2, 0]]),
        );
        let to_cache = pdu(
            id::SURFACE_TO_CACHE,
            &le(&[&1u16.to_le_bytes(), &[0; 8], &5u16.to_le_bytes(), &[0, 0, 0, 0, 2, 0, 2, 0]]),
        );
        let from_cache = pdu(
            id::CACHE_TO_SURFACE,
            &le(&[&5u16.to_le_bytes(), &1u16.to_le_bytes(), &1u16.to_le_bytes(), &[6, 0, 2, 0]]),
        );
        let end = pdu(id::END_FRAME, &7u32.to_le_bytes());
        let out = g.process(&wrap(&[reset, create, map, fill, to_cache, from_cache, end])).unwrap();
        assert_eq!(out[0], Out::Reset { width: 8, height: 4, monitors: vec![] });
        let (fb, w, _) = g.output();
        let px = |x: u32, y: u32| &fb[((y * w + x) * 4) as usize..((y * w + x) * 4 + 4) as usize];
        assert_eq!(px(1, 1), [0xFF, 0, 0, 0xFF]);
        assert_eq!(px(7, 3), [0xFF, 0, 0, 0xFF], "copie du cache en (6,2)");
        assert_eq!(px(4, 0), [0, 0, 0, 0xFF]);
        match &out[out.len() - 1] {
            Out::Send(ack) => {
                assert_eq!(&ack[12..16], &7u32.to_le_bytes(), "frameId");
                assert_eq!(&ack[16..20], &1u32.to_le_bytes(), "compteur d'images décodées");
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(&out[out.len() - 2], Out::Present { damage } if !damage.is_empty()));
    }

    #[test]
    fn avc_pauses_until_submitted() {
        let mut g = Gfx::new();
        let reset = pdu(id::RESET_GRAPHICS, &le(&[&16u32.to_le_bytes(), &16u32.to_le_bytes(), &[0; 4]]));
        let create = pdu(
            id::CREATE_SURFACE,
            &le(&[&0u16.to_le_bytes(), &16u16.to_le_bytes(), &16u16.to_le_bytes(), &[0x20]]),
        );
        let map = pdu(id::MAP_SURFACE_TO_OUTPUT, &le(&[&0u16.to_le_bytes(), &[0, 0], &[0; 8]]));
        let meta = le(&[&1u32.to_le_bytes(), &[0, 0, 0, 0, 16, 0, 16, 0], &[22, 100]]);
        let bitmap = le(&[&meta, &[0, 0, 0, 1, 0x65]]);
        let avc = pdu(
            id::WIRE_TO_SURFACE_1,
            &le(&[
                &0u16.to_le_bytes(),
                &codec::AVC420.to_le_bytes(),
                &[0x20],
                &[0, 0, 0, 0, 16, 0, 16, 0],
                &(bitmap.len() as u32).to_le_bytes(),
                &bitmap,
            ]),
        );
        let end = pdu(id::END_FRAME, &1u32.to_le_bytes());
        let out = g.process(&wrap(&[reset, create, map, avc, end])).unwrap();
        assert_eq!(out.last(), Some(&Out::Avc420 { data: vec![0, 0, 0, 1, 0x65] }));
        assert!(g.waiting_for_avc(), "pas d'accusé avant le décodage");
        let (y, u, v) = ([255u8; 256], [128u8; 64], [128u8; 64]);
        let frame = crate::Yuv420 { width: 16, height: 16, y: &y, u: &u, v: &v, y_stride: 16, uv_stride: 8 };
        let out = g.submit_yuv420(&frame).unwrap();
        assert!(matches!(out.last(), Some(Out::Send(_))));
        assert_eq!(&g.output().0[..4], &[255, 255, 255, 255]);
    }

    #[test]
    fn budgets_enforced() {
        // Surfaces : la 65e est refusée.
        let mut g = Gfx::new();
        let mut pdus = Vec::new();
        for sid in 0..65u16 {
            pdus.push(pdu(
                id::CREATE_SURFACE,
                &le(&[&sid.to_le_bytes(), &16u16.to_le_bytes(), &16u16.to_le_bytes(), &[0x20]]),
            ));
        }
        assert!(g.process(&wrap(&pdus)).is_err());
        // Cache : 16 Mo maximum, puis éviction et réutilisation possibles.
        let mut g = Gfx::new();
        let create = pdu(
            id::CREATE_SURFACE,
            &le(&[&0u16.to_le_bytes(), &2048u16.to_le_bytes(), &2048u16.to_le_bytes(), &[0x20]]),
        );
        let to_cache = |slot: u16| {
            pdu(
                id::SURFACE_TO_CACHE,
                &le(&[&0u16.to_le_bytes(), &[0; 8], &slot.to_le_bytes(), &[0, 0, 0, 0, 0, 8, 0, 4]]),
            )
        };
        // 2048×1024×4 = 8 Mo : deux passent, la troisième dépasse.
        assert!(g.process(&wrap(&[create, to_cache(1), to_cache(2)])).is_ok());
        assert!(g.process(&wrap(&[to_cache(3)])).is_err());
        let mut g2 = Gfx::new();
        let create = pdu(
            id::CREATE_SURFACE,
            &le(&[&0u16.to_le_bytes(), &2048u16.to_le_bytes(), &2048u16.to_le_bytes(), &[0x20]]),
        );
        let evict = pdu(id::EVICT_CACHE_ENTRY, &1u16.to_le_bytes());
        assert!(g2.process(&wrap(&[create, to_cache(1), to_cache(2), evict, to_cache(3)])).is_ok());
        // Copies : 65 535 destinations d'une zone 1024×1024 refusées.
        let mut g = Gfx::new();
        let create = pdu(
            id::CREATE_SURFACE,
            &le(&[&0u16.to_le_bytes(), &1024u16.to_le_bytes(), &1024u16.to_le_bytes(), &[0x20]]),
        );
        let mut body = le(&[
            &0u16.to_le_bytes(),
            &0u16.to_le_bytes(),
            &[0, 0, 0, 0, 0, 4, 0, 4],
            &u16::MAX.to_le_bytes(),
        ]);
        body.extend(core::iter::repeat_n(0u8, 4 * u16::MAX as usize));
        assert!(g.process(&wrap(&[create, pdu(id::SURFACE_TO_SURFACE, &body)])).is_err());
    }

    #[test]
    fn avc_region_budget() {
        // 4 096 régions de 8 192×8 192 : refusé dès l'analyse, aucune conversion lancée.
        let mut g = Gfx::new();
        let create = pdu(
            id::CREATE_SURFACE,
            &le(&[&0u16.to_le_bytes(), &64u16.to_le_bytes(), &64u16.to_le_bytes(), &[0x20]]),
        );
        let mut meta = 4096u32.to_le_bytes().to_vec();
        for _ in 0..4096 {
            meta.extend_from_slice(&[0, 0, 0, 0, 0, 0x20, 0, 0x20]);
        }
        meta.extend(core::iter::repeat_n(0u8, 2 * 4096));
        let avc = pdu(
            id::WIRE_TO_SURFACE_1,
            &le(&[
                &0u16.to_le_bytes(),
                &codec::AVC420.to_le_bytes(),
                &[0x20],
                &[0, 0, 0, 0, 64, 0, 64, 0],
                &(meta.len() as u32).to_le_bytes(),
                &meta,
            ]),
        );
        assert!(g.process(&wrap(&[create, avc])).is_err());
    }

    #[test]
    fn hostile_inputs_rejected() {
        let mut g = Gfx::new();
        let huge = pdu(
            id::CREATE_SURFACE,
            &le(&[&0u16.to_le_bytes(), &60000u16.to_le_bytes(), &60000u16.to_le_bytes(), &[0x20]]),
        );
        assert!(g.process(&wrap(&[huge])).is_err());
        let mut g = Gfx::new();
        let unknown = pdu(id::SOLID_FILL, &le(&[&9u16.to_le_bytes(), &[0; 4], &0u16.to_le_bytes()]));
        assert!(g.process(&wrap(&[unknown])).is_err());
        let mut g = Gfx::new();
        assert!(g.process(&[0xE0, 0x04, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00]).is_err());
    }

    #[test]
    fn rejected_pdu_not_counted_as_queued() {
        let mut g = Gfx::new();
        g.queued_bytes = crate::MAX_QUEUED_BYTES - 7;
        assert!(g.process(&wrap(&[pdu(id::CAPS_CONFIRM, &[])])).is_err());
        assert_eq!(g.queued_bytes, crate::MAX_QUEUED_BYTES - 7);
    }

    #[test]
    fn avc444_from_rgb_rebuilt_then_refused_for_good() {
        let surface = || {
            let mut g = Gfx::new();
            let create = pdu(
                id::CREATE_SURFACE,
                &le(&[&0u16.to_le_bytes(), &16u16.to_le_bytes(), &16u16.to_le_bytes(), &[0x20]]),
            );
            g.process(&wrap(&[create])).unwrap();
            g
        };
        let full = Rect { x: 0, y: 0, w: 16, h: 16 };
        let pending = |g: &mut Gfx| {
            g.pending_avc =
                Some(PendingAvc { surface: 0, rects: vec![full], aux: Some((vec![full], false)) });
        };
        fn rgba(d: &[u8]) -> crate::Rgba<'_> {
            crate::Rgba { width: 16, height: 16, data: d, stride: 64 }
        }
        let px = |g: &Gfx, x: usize, y: usize| g.surfaces[&0].rgba[(y * 16 + x) * 4..][..4].to_vec();
        // 4:4:4 à lignes alternées : Y = V = 128, U = 128 sur les lignes paires, 160 sur les
        // impaires. Principale : Ũ = 144 ; auxiliaire v1 : luma à 160 sur les lignes U, 128 sur les
        // lignes V, chroma neutre.
        let main = crate::yuv::to_rgb(128, 144, 128).repeat(256);
        let aux: Vec<u8> = (0..256)
            .flat_map(|i| if (i / 16) % 16 < 8 { [160, 160, 160, 255] } else { [128, 128, 128, 255] })
            .collect();
        // Conversion prouvée (posée ici : une surface de 16×16 n'en apporte pas la preuve).
        let mut g = surface();
        g.rgb = crate::Rgb444::Proven;
        pending(&mut g);
        let (_, shown) = g.submit_avc444_rgba(Some(&rgba(&main)), Some(&rgba(&aux))).unwrap();
        assert_eq!(shown, crate::Shown::Rebuilt);
        // Ligne impaire : la chroma de l'auxiliaire, pas celle de la principale.
        assert_eq!(px(&g, 1, 1), crate::yuv::to_rgb(128, 160, 128));
        assert_ne!(px(&g, 1, 1), crate::yuv::to_rgb(128, 144, 128));
        assert_eq!(px(&g, 1, 0), crate::yuv::to_rgb(128, 128, 128));
        // Chroma qui varie à l'intérieur des blocs 2×2 : interpolée par le navigateur. Refusée sans
        // consommer la commande, pour le repli sur la principale seule.
        let mut smooth = Vec::new();
        for y in 0..16u8 {
            for x in 0..16u8 {
                smooth.extend([8 + 16 * x, 100, 248 - 16 * y, 255]);
            }
        }
        pending(&mut g);
        assert!(g.submit_avc444_rgba(Some(&rgba(&smooth)), Some(&rgba(&aux))).is_err());
        assert!(g.waiting_for_avc() && g.rgb == crate::Rgb444::Refused);
        g.submit_rgba(&rgba(&smooth)).unwrap();
        assert!(!g.waiting_for_avc());
        assert_eq!(px(&g, 0, 0), [8, 100, 248, 255]);
        // Plus de recomposition pour la session, même sur une image inversible.
        pending(&mut g);
        assert!(g.submit_avc444_rgba(Some(&rgba(&main)), Some(&rgba(&aux))).is_err());
        // Image tronquée : refusée avant tout.
        let mut g = surface();
        pending(&mut g);
        assert!(g.submit_avc444_rgba(Some(&rgba(&main[..100])), None).is_err());
        assert!(g.waiting_for_avc() && g.rgb == crate::Rgb444::Unknown);
        // Chroma seule sans luma connue : refusée.
        assert!(g.submit_avc444_rgba(None, Some(&rgba(&aux))).is_err());
        // Mémoire de surface épuisée : la commande reste au repli.
        g.surface_bytes = crate::MAX_SURFACE_BYTES;
        assert!(g.submit_avc444_rgba(Some(&rgba(&main)), Some(&rgba(&aux))).is_err());
        assert!(g.waiting_for_avc());
        g.submit_rgba(&rgba(&main)).unwrap();
        assert_eq!(px(&g, 1, 1), crate::yuv::to_rgb(128, 144, 128));
    }

    #[test]
    fn rgba_check_rejects_short_stride_without_overflow() {
        let huge = crate::Rgba { width: u32::MAX, height: u32::MAX, data: &[], stride: u32::MAX };
        assert!(huge.check().is_err());
        let padded = crate::Rgba { width: 2, height: 2, data: &[0; 24], stride: 16 };
        assert!(padded.check().is_ok(), "remplissage en fin de ligne");
        let short = crate::Rgba { width: 2, height: 2, data: &[0; 24], stride: 4 };
        assert!(short.check().is_err());
    }

    #[test]
    fn avc444_planes_counted_even_if_the_frame_is_refused() {
        let mut g = Gfx::new();
        let create = pdu(
            id::CREATE_SURFACE,
            &le(&[&0u16.to_le_bytes(), &16u16.to_le_bytes(), &16u16.to_le_bytes(), &[0x20]]),
        );
        g.process(&wrap(&[create])).unwrap();
        let full = Rect { x: 0, y: 0, w: 16, h: 16 };
        g.pending_avc = Some(PendingAvc { surface: 0, rects: vec![full], aux: None });
        // Plans trop courts : refusée après la création des plans 4:4:4.
        let frame =
            crate::Yuv420 { width: 16, height: 16, y: &[], u: &[], v: &[], y_stride: 16, uv_stride: 8 };
        assert!(g.submit_avc444(Some(&frame), None).is_err());
        let s = &g.surfaces[&0];
        assert_eq!(g.surface_bytes, s.rgba.len() + s.p444.as_ref().unwrap().bytes());
        g.process(&wrap(&[pdu(id::DELETE_SURFACE, &0u16.to_le_bytes())])).unwrap();
        assert_eq!(g.surface_bytes, 0);
    }

    #[test]
    fn extreme_monitor_edges() {
        // Bords aux limites d'i32 : pas de débordement, rectangles saturés puis découpés.
        let mon = |l: i32, t: i32, r: i32, b: i32| {
            le(&[&l.to_le_bytes(), &t.to_le_bytes(), &r.to_le_bytes(), &b.to_le_bytes(), &[0; 4]])
        };
        let body = le(&[
            &16u32.to_le_bytes(),
            &16u32.to_le_bytes(),
            &3u32.to_le_bytes(),
            &mon(i32::MIN, 0, i32::MIN + 9, 9),
            &mon(i32::MAX - 9, 0, i32::MAX, 9),
            &mon(i32::MIN, 0, i32::MAX, 9),
        ]);
        let out = Gfx::new().process(&wrap(&[pdu(id::RESET_GRAPHICS, &body)])).unwrap();
        let full = Rect { x: 0, y: 0, w: 16, h: 10 };
        assert_eq!(
            out[0],
            Out::Reset { width: 16, height: 16, monitors: vec![Rect { w: 10, ..full }, full] }
        );
    }
}
