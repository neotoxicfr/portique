//! Décodeur ClearCodec (MS-RDPEGFX 2.2.4.1 et 3.3.8.1), codec 0x0008 d'EGFX.
//!
//! Jusqu'à trois couches posées dans l'ordre sur la zone : résidu (runs RGB), bandes de
//! V-Bars (avec caches de V-Bars et de V-Bars courtes), puis sous-codecs (brut, NSCodec,
//! RLEX). Les caches et le stockage des glyphes persistent d'un appel à l'autre : une
//! instance par canal EGFX. Couleurs du flux en BGR, sortie en RGBA (alpha 255).

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::{Error, nscodec};

const FLAG_GLYPH_INDEX: u8 = 0x01;
const FLAG_GLYPH_HIT: u8 = 0x02;
const FLAG_CACHE_RESET: u8 = 0x04;

/// Tailles des stockages (MS-RDPEGFX 3.3.1.9 à 3.3.1.13).
const VBAR_STORAGE: usize = 32_768;
const SHORT_VBAR_STORAGE: usize = 16_384;
const GLYPH_STORAGE: usize = 4_000;
/// Surface maximale d'un glyphe (2.2.4.1) et hauteur maximale d'une bande (2.2.4.1.1.2.1).
const GLYPH_MAX_AREA: usize = 1024;
const BAND_MAX_HEIGHT: usize = 52;

type Rgb = [u8; 3];

pub struct ClearCodec {
    /// V-Bars complètes (hauteur de leur bande), `None` tant que jamais écrites.
    vbars: Box<[Option<Vec<Rgb>>]>,
    vbar_cursor: usize,
    short_vbars: Box<[Option<Vec<Rgb>>]>,
    short_vbar_cursor: usize,
    /// Glyphes : flux linéaire de pixels RGBA, sans dimensions implicites (4.1.1.5).
    glyphs: Box<[Option<Vec<u8>>]>,
}

impl core::fmt::Debug for ClearCodec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClearCodec")
            .field("vbar_cursor", &self.vbar_cursor)
            .field("short_vbar_cursor", &self.short_vbar_cursor)
            .finish_non_exhaustive()
    }
}

impl Default for ClearCodec {
    fn default() -> Self {
        Self::new()
    }
}

/// Lecture bornée d'entiers petit-boutistes.
struct Reader<'a> {
    buf: &'a [u8],
    what: &'static str,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8], what: &'static str) -> Self {
        Self { buf, what }
    }

    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let b = self.buf.get(..n).ok_or(Error::Truncated(self.what))?;
        self.buf = &self.buf[n..];
        Ok(b)
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

    /// Pixel BGR du flux, rendu en RGB.
    fn bgr(&mut self) -> Result<Rgb, Error> {
        let b = self.bytes(3)?;
        Ok([b[2], b[1], b[0]])
    }

    /// Longueur de run sur 1, 2 ou 4 octets (runLengthFactor1/2/3, 2.2.4.1.1.1.1).
    fn run_length(&mut self) -> Result<usize, Error> {
        let f1 = self.u8()?;
        if f1 < 0xFF {
            return Ok(usize::from(f1));
        }
        let f2 = self.u16()?;
        if f2 < 0xFFFF {
            return Ok(usize::from(f2));
        }
        Ok(self.u32()? as usize)
    }
}

/// Zone de sortie RGBA : écritures hors bornes ignorées (découpage).
struct Canvas<'a> {
    out: &'a mut [u8],
    w: usize,
    h: usize,
}

impl Canvas<'_> {
    fn put(&mut self, x: usize, y: usize, [r, g, b]: Rgb) {
        if x < self.w && y < self.h {
            let i = (y * self.w + x) * 4;
            self.out[i..i + 4].copy_from_slice(&[r, g, b, 0xFF]);
        }
    }
}

impl ClearCodec {
    pub fn new() -> Self {
        Self {
            vbars: vec![None; VBAR_STORAGE].into_boxed_slice(),
            vbar_cursor: 0,
            short_vbars: vec![None; SHORT_VBAR_STORAGE].into_boxed_slice(),
            short_vbar_cursor: 0,
            glyphs: vec![None; GLYPH_STORAGE].into_boxed_slice(),
        }
    }

    /// Décode vers `out` RGBA (stride width*4). Les pixels non couverts gardent leur valeur
    /// d'entrée : l'appelant passe le contenu actuel de la zone (composition sur la surface).
    pub fn decode(&mut self, src: &[u8], width: u32, height: u32, out: &mut [u8]) -> Result<(), Error> {
        if width == 0 || height == 0 || width > 0xFFFF || height > 0xFFFF {
            return Err(Error::Invalid("ClearCodec : dimensions hors limites"));
        }
        let (w, h) = (width as usize, height as usize);
        if w.checked_mul(h).and_then(|n| n.checked_mul(4)) != Some(out.len()) {
            return Err(Error::Invalid("ClearCodec : tampon de sortie de mauvaise taille"));
        }
        let mut r = Reader::new(src, "en-tête ClearCodec");
        let flags = r.u8()?;
        // Le numéro de séquence n'est pas vérifié : le canal EGFX est fiable et ordonné.
        let _seq = r.u8()?;
        let glyph = if flags & FLAG_GLYPH_INDEX != 0 {
            let index = usize::from(r.u16()?);
            if index >= GLYPH_STORAGE {
                return Err(Error::Invalid("ClearCodec : index de glyphe hors limites"));
            }
            if w * h > GLYPH_MAX_AREA {
                return Err(Error::Invalid("ClearCodec : glyphe de plus de 1024 pixels"));
            }
            Some(index)
        } else if flags & FLAG_GLYPH_HIT != 0 {
            return Err(Error::Invalid("ClearCodec : GLYPH_HIT sans GLYPH_INDEX"));
        } else {
            None
        };
        if flags & FLAG_CACHE_RESET != 0 {
            self.vbar_cursor = 0;
            self.short_vbar_cursor = 0;
        }

        if let Some(index) = glyph
            && flags & FLAG_GLYPH_HIT != 0
        {
            // Flux linéaire réutilisable sous toute forme de même surface (4.1.1.5).
            let stored =
                self.glyphs[index].as_ref().ok_or(Error::Invalid("ClearCodec : glyphe absent du cache"))?;
            let pixels = stored.get(..out.len()).ok_or(Error::Invalid("ClearCodec : glyphe trop petit"))?;
            out.copy_from_slice(pixels);
            return Ok(());
        }

        let mut r = Reader::new(r.buf, "charge composite ClearCodec");
        let residual_len = r.u32()? as usize;
        let bands_len = r.u32()? as usize;
        let subcodec_len = r.u32()? as usize;
        let residual = r.bytes(residual_len)?;
        let bands = r.bytes(bands_len)?;
        let subcodecs = r.bytes(subcodec_len)?;

        let mut canvas = Canvas { out, w, h };
        if !residual.is_empty() {
            decode_residual(residual, &mut canvas)?;
        }
        if !bands.is_empty() {
            self.decode_bands(bands, &mut canvas)?;
        }
        if !subcodecs.is_empty() {
            decode_subcodecs(subcodecs, &mut canvas)?;
        }
        if let Some(index) = glyph {
            self.glyphs[index] = Some(canvas.out.to_vec());
        }
        Ok(())
    }

    /// Couche 2 : bandes de V-Bars (2.2.4.1.1.2).
    fn decode_bands(&mut self, data: &[u8], canvas: &mut Canvas) -> Result<(), Error> {
        let mut r = Reader::new(data, "bande ClearCodec");
        while !r.is_empty() {
            let x_start = usize::from(r.u16()?);
            let x_end = usize::from(r.u16()?);
            let y_start = usize::from(r.u16()?);
            let y_end = usize::from(r.u16()?);
            let bkg = r.bgr()?;
            if x_end < x_start || y_end < y_start {
                return Err(Error::Invalid("ClearCodec : bande à coordonnées inversées"));
            }
            let height = y_end - y_start + 1;
            if height > BAND_MAX_HEIGHT {
                return Err(Error::Invalid("ClearCodec : bande de plus de 52 pixels"));
            }
            for x in x_start..=x_end {
                let header = r.u16()?;
                let vbar = if header & 0xC000 == 0x4000 {
                    // SHORT_VBAR_CACHE_HIT : V-Bar reconstruite depuis une V-Bar courte.
                    let index = usize::from(header & 0x3FFF);
                    let y_on = usize::from(r.u8()?);
                    let short = self.short_vbars[index]
                        .as_ref()
                        .ok_or(Error::Invalid("ClearCodec : V-Bar courte absente du cache"))?;
                    let vbar = expand(short, y_on, height, bkg)?;
                    self.store_vbar(vbar)
                } else if header & 0x8000 != 0 {
                    // VBAR_CACHE_HIT.
                    let vbar = self.vbars[usize::from(header & 0x7FFF)]
                        .as_ref()
                        .ok_or(Error::Invalid("ClearCodec : V-Bar absente du cache"))?;
                    if vbar.len() != height {
                        return Err(Error::Invalid("ClearCodec : V-Bar du cache de mauvaise hauteur"));
                    }
                    vbar
                } else {
                    // SHORT_VBAR_CACHE_MISS : pixels de la V-Bar courte dans le flux.
                    let y_on = usize::from(header & 0xFF);
                    let y_off = usize::from((header >> 8) & 0x3F);
                    let count = y_off
                        .checked_sub(y_on)
                        .ok_or(Error::Invalid("ClearCodec : V-Bar courte inversée"))?;
                    let short = (0..count).map(|_| r.bgr()).collect::<Result<Vec<_>, _>>()?;
                    let vbar = expand(&short, y_on, height, bkg)?;
                    self.short_vbars[self.short_vbar_cursor] = Some(short);
                    self.short_vbar_cursor = (self.short_vbar_cursor + 1) % SHORT_VBAR_STORAGE;
                    self.store_vbar(vbar)
                };
                for (dy, &px) in vbar.iter().enumerate() {
                    canvas.put(x, y_start + dy, px);
                }
            }
        }
        Ok(())
    }

    /// Range une V-Bar au curseur (qui reboucle après 32 767) et la renvoie.
    fn store_vbar(&mut self, vbar: Vec<Rgb>) -> &Vec<Rgb> {
        let slot = self.vbar_cursor;
        self.vbar_cursor = (slot + 1) % VBAR_STORAGE;
        self.vbars[slot].insert(vbar)
    }
}

/// V-Bar complète : fond, V-Bar courte à partir de `y_on`, fond (2.2.4.1.1.2.1.1.2).
fn expand(short: &[Rgb], y_on: usize, height: usize, bkg: Rgb) -> Result<Vec<Rgb>, Error> {
    if y_on + short.len() > height {
        return Err(Error::Invalid("ClearCodec : V-Bar courte plus haute que la bande"));
    }
    let mut vbar = vec![bkg; height];
    vbar[y_on..y_on + short.len()].copy_from_slice(short);
    Ok(vbar)
}

/// Couche 1 : runs RGB, de gauche à droite puis de haut en bas (2.2.4.1.1.1).
fn decode_residual(data: &[u8], canvas: &mut Canvas) -> Result<(), Error> {
    let total = canvas.w * canvas.h;
    let mut r = Reader::new(data, "résidu ClearCodec");
    let mut pos = 0;
    while !r.is_empty() {
        let px = r.bgr()?;
        let run = r.run_length()?;
        if run > total - pos {
            return Err(Error::Invalid("ClearCodec : résidu plus long que l'image"));
        }
        for i in pos..pos + run {
            canvas.put(i % canvas.w, i / canvas.w, px);
        }
        pos += run;
    }
    Ok(())
}

/// Couche 3 : sous-codecs placés dans la zone (2.2.4.1.1.3).
fn decode_subcodecs(data: &[u8], canvas: &mut Canvas) -> Result<(), Error> {
    let mut r = Reader::new(data, "sous-codec ClearCodec");
    while !r.is_empty() {
        let x0 = usize::from(r.u16()?);
        let y0 = usize::from(r.u16()?);
        let w = usize::from(r.u16()?);
        let h = usize::from(r.u16()?);
        let len = r.u32()? as usize;
        let id = r.u8()?;
        let bitmap = r.bytes(len)?;
        // Rectangle borné par la zone : borne aussi les allocations et les multiplications.
        if x0 + w > canvas.w || y0 + h > canvas.h {
            return Err(Error::Invalid("ClearCodec : sous-codec hors de la zone"));
        }
        if len > 3 * w * h {
            return Err(Error::Invalid("ClearCodec : sous-codec plus long que 3 × surface"));
        }
        if w == 0 || h == 0 {
            continue;
        }
        let mut put = |i: usize, px: Rgb| canvas.put(x0 + i % w, y0 + i / w, px);
        match id {
            0 => {
                if len != 3 * w * h {
                    return Err(Error::Invalid("ClearCodec : sous-codec brut de mauvaise taille"));
                }
                let mut p = Reader::new(bitmap, "sous-codec brut");
                for i in 0..w * h {
                    put(i, p.bgr()?);
                }
            }
            1 => {
                let mut tmp = vec![0u8; w * h * 4];
                nscodec::decode(bitmap, w as u32, h as u32, &mut tmp)?;
                for (i, px) in tmp.as_chunks::<4>().0.iter().enumerate() {
                    put(i, [px[0], px[1], px[2]]);
                }
            }
            2 => {
                rlex(bitmap, w * h, &mut put)?;
            }
            _ => return Err(Error::Invalid("ClearCodec : sous-codec inconnu")),
        }
    }
    Ok(())
}

/// RLEX (2.2.4.1.1.3.1.1) : palette, puis segments « run de startColor, suite de startIndex à
/// stopIndex ». Renvoie le nombre de pixels écrits.
fn rlex(data: &[u8], total: usize, put: &mut impl FnMut(usize, Rgb)) -> Result<usize, Error> {
    let mut r = Reader::new(data, "RLEX ClearCodec");
    let count = usize::from(r.u8()?);
    if count == 0 || count > 0x7F {
        return Err(Error::Invalid("ClearCodec : palette RLEX hors de 1..127"));
    }
    let palette = (0..count).map(|_| r.bgr()).collect::<Result<Vec<_>, _>>()?;
    // Bits de stopIndex : de quoi écrire count - 1 (au moins 1).
    let bits = (1..8).find(|&b| 1usize << b >= count).unwrap_or(7);
    let mut pos = 0;
    while !r.is_empty() {
        let byte = r.u8()?;
        let stop = usize::from(byte) & ((1 << bits) - 1);
        let depth = usize::from(byte) >> bits;
        let run = r.run_length()?;
        let start =
            stop.checked_sub(depth).ok_or(Error::Invalid("ClearCodec : suite RLEX avant l'index 0"))?;
        if stop >= count {
            return Err(Error::Invalid("ClearCodec : index RLEX hors de la palette"));
        }
        if run.checked_add(depth + 1).is_none_or(|n| n > total - pos) {
            return Err(Error::Invalid("ClearCodec : RLEX plus long que le bitmap"));
        }
        for _ in 0..run {
            put(pos, palette[start]);
            pos += 1;
        }
        for &px in &palette[start..=stop] {
            put(pos, px);
            pos += 1;
        }
    }
    Ok(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }

    fn px(out: &[u8], w: usize, x: usize, y: usize) -> [u8; 4] {
        let i = (y * w + x) * 4;
        [out[i], out[i + 1], out[i + 2], out[i + 3]]
    }

    /// MS-RDPEGFX 4.1.1.2 : 78×17, une couche de sous-codec RLEX à 14 couleurs.
    const EXAMPLE_2: &str = "000d000000000000000082000000000000004e00110075000000020effffff000000dbffff\
        003a90ffb66666b6ffb6660090dbff00003adb903a3a90db660000ffffb66464641104114c114c114c114c114c\
        0047130001010400010000471600110200472900110100490a00010004000100004a0a000900010000470500\
        01011c000100114c114c114c00470d4d004d";

    #[test]
    fn spec_example_2_rlex() {
        let src = unhex(EXAMPLE_2);
        assert_eq!(src.len(), 144);
        // Le RLEX couvre exactement les 78 × 17 pixels.
        let rlex_data = &src[27..];
        assert_eq!(rlex_data.len(), 117);
        assert_eq!(rlex(rlex_data, 78 * 17, &mut |_, _| ()), Ok(78 * 17));

        let mut out = vec![0u8; 78 * 17 * 4];
        ClearCodec::new().decode(&src, 78, 17, &mut out).unwrap();
        let white = [0xFF, 0xFF, 0xFF, 0xFF];
        let black = [0, 0, 0, 0xFF];
        // Premier segment : 0, 0, 0, 0, 0, 1 ; second : 76 × 0 puis 0, 1.
        for x in 0..5 {
            assert_eq!(px(&out, 78, x, 0), white);
        }
        assert_eq!(px(&out, 78, 5, 0), black);
        for i in 6..83 {
            assert_eq!(px(&out, 78, i % 78, i / 78), white, "pixel {i}");
        }
        assert_eq!(px(&out, 78, 83 % 78, 1), black);
    }

    /// MS-RDPEGFX 4.1.1.4 : 7×15, glyphe 120, une V-Bar courte manquée puis six V-Bars du
    /// cache (indices 0x1146 à 0x114A et 0x111B), préremplies ici faute du paquet précédent.
    const EXAMPLE_4: &str = "010b78000000000046000000000000000000060000000e00000000000fffffffffff\
        ffffffffb6ffffffffffffffffffb666ffffffffffffffb666db903affffb6ffffffffffffffffff469147914891\
        49914a911b91";

    #[test]
    fn spec_example_4_bands_and_glyph() {
        let src = unhex(EXAMPLE_4);
        assert_eq!(src.len(), 86);
        let mut codec = ClearCodec::new();
        // Sans les V-Bars du cache : erreur, sans panique.
        let mut out = vec![0u8; 7 * 15 * 4];
        assert!(codec.decode(&src, 7, 15, &mut out).is_err());

        let mut codec = ClearCodec::new();
        for (k, index) in [0x1146, 0x1147, 0x1148, 0x1149, 0x114A, 0x111B].into_iter().enumerate() {
            codec.vbars[index] = Some(vec![[k as u8, 0x10, 0x20]; 15]);
        }
        codec.decode(&src, 7, 15, &mut out).unwrap();
        // Colonne 0 : 11e pixel (0, 10) = bleu 0xdb, vert 0x90, rouge 0x3a.
        assert_eq!(px(&out, 7, 0, 10), [0x3a, 0x90, 0xdb, 0xFF]);
        assert_eq!(px(&out, 7, 0, 0), [0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(px(&out, 7, 3, 7), [2, 0x10, 0x20, 0xFF]);
        assert_eq!(px(&out, 7, 6, 14), [5, 0x10, 0x20, 0xFF]);
        // Curseurs avancés, V-Bar rangée au curseur 0, glyphe 120 rempli.
        assert_eq!((codec.vbar_cursor, codec.short_vbar_cursor), (1, 1));
        assert_eq!(codec.vbars[0].as_ref().unwrap()[10], [0x3a, 0x90, 0xdb]);
        assert_eq!(codec.glyphs[120].as_deref(), Some(&out[..]));

        // 4.1.1.1 : GLYPH_INDEX | GLYPH_HIT, glyphe 120 relu sous une autre forme (15×7).
        let mut again = vec![0u8; 7 * 15 * 4];
        codec.decode(&[0x03, 0xc3, 120, 0], 15, 7, &mut again).unwrap();
        assert_eq!(again, out);
        // Glyphe absent : erreur.
        assert!(codec.decode(&[0x03, 0xc4, 17, 0], 15, 7, &mut again).is_err());
    }

    /// Résidu seul : 3 pixels rouges, 1 bleu (run sur 2 octets testé à part) ; les pixels
    /// non couverts gardent leur valeur.
    #[test]
    fn residual_only() {
        let mut src = vec![0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        src.extend_from_slice(&[0, 0, 0xFF, 3, 0xFF, 0, 0, 1]);
        let mut out = vec![7u8; 6 * 4];
        ClearCodec::new().decode(&src, 3, 2, &mut out).unwrap();
        assert_eq!(&out[..12], [255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255]);
        assert_eq!(&out[12..16], [0, 0, 255, 255]);
        assert_eq!(&out[16..], [7; 8]);

        let mut r = Reader::new(&[0xFF, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0x05, 0, 1, 0], "t");
        assert_eq!(r.run_length(), Ok(256));
        assert_eq!(r.run_length(), Ok(0x0001_0005));
        // Résidu qui dépasse l'image.
        let mut src = vec![0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        src.extend_from_slice(&[0, 0, 0xFF, 7]);
        assert!(ClearCodec::new().decode(&src, 3, 2, &mut out).is_err());
    }

    /// Bande 2×3 : V-Bar courte manquée (1 pixel à y = 1), puis réutilisation par
    /// SHORT_VBAR_CACHE_HIT (décalée à y = 2) et VBAR_CACHE_HIT d'un second paquet.
    #[test]
    fn bands_short_and_full_cache() {
        let band = |vbars: &[u8]| {
            let mut b = vec![0, 0, 1, 0, 0, 0, 2, 0, 0x30, 0x20, 0x10]; // x 0..1, y 0..2, fond
            b.extend_from_slice(vbars);
            let mut src = vec![0, 0, 0, 0, 0, 0];
            src.extend_from_slice(&(b.len() as u32).to_le_bytes());
            src.extend_from_slice(&[0, 0, 0, 0]);
            src.extend_from_slice(&b);
            src
        };
        let bkg = [0x10, 0x20, 0x30, 0xFF];
        let red = [0xFF, 0, 0, 0xFF];
        let mut codec = ClearCodec::new();
        let mut out = vec![0u8; 2 * 3 * 4];
        // Colonne 0 : miss yOn = 1, yOff = 2, pixel rouge. Colonne 1 : short hit index 0, yOn 2.
        let src = band(&[0x01, 0x02, 0, 0, 0xFF, 0x00, 0x40, 0x02]);
        codec.decode(&src, 2, 3, &mut out).unwrap();
        assert_eq!([px(&out, 2, 0, 0), px(&out, 2, 0, 1), px(&out, 2, 0, 2)], [bkg, red, bkg]);
        assert_eq!([px(&out, 2, 1, 0), px(&out, 2, 1, 1), px(&out, 2, 1, 2)], [bkg, bkg, red]);
        assert_eq!(codec.vbar_cursor, 2);

        // VBAR_CACHE_HIT des V-Bars 1 puis 0 : colonnes échangées.
        let src = band(&[0x01, 0x80, 0x00, 0x80]);
        let mut out2 = vec![0u8; 2 * 3 * 4];
        codec.decode(&src, 2, 3, &mut out2).unwrap();
        assert_eq!(px(&out2, 2, 0, 2), red);
        assert_eq!(px(&out2, 2, 1, 1), red);
        assert_eq!(codec.vbar_cursor, 2);

        // CACHE_RESET : curseurs remis à zéro.
        let mut src = band(&[0x01, 0x80, 0x00, 0x80]);
        src[0] = FLAG_CACHE_RESET;
        codec.decode(&src, 2, 3, &mut out2).unwrap();
        assert_eq!(codec.vbar_cursor, 0);

        // V-Bar courte plus haute que la bande, V-Bar absente, V-Bar courte absente.
        assert!(codec.decode(&band(&[0x02, 0x04, 1, 2, 3, 4, 5, 6]), 2, 3, &mut out).is_err());
        assert!(codec.decode(&band(&[0x05, 0x80, 0x05, 0x80]), 2, 3, &mut out).is_err());
        assert!(codec.decode(&band(&[0x05, 0x40, 0x00]), 2, 3, &mut out).is_err());
    }

    /// Sous-codec brut 2×1 placé en (1, 1) d'une zone 3×2 ; autres pixels intacts.
    #[test]
    fn subcodec_raw() {
        let mut sub = vec![1, 0, 1, 0, 2, 0, 1, 0, 6, 0, 0, 0, 0];
        sub.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        let mut src = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        src.extend_from_slice(&(sub.len() as u32).to_le_bytes());
        src.extend_from_slice(&sub);
        let mut out = vec![9u8; 3 * 2 * 4];
        ClearCodec::new().decode(&src, 3, 2, &mut out).unwrap();
        assert_eq!(px(&out, 3, 1, 1), [3, 2, 1, 255]);
        assert_eq!(px(&out, 3, 2, 1), [6, 5, 4, 255]);
        assert_eq!(px(&out, 3, 0, 1), [9; 4]);
        // Sous-codec inconnu.
        let mut bad = src.clone();
        bad[26] = 3;
        assert!(ClearCodec::new().decode(&bad, 3, 2, &mut out).is_err());
        // Rectangle hors de la zone.
        let mut bad = src.clone();
        bad[14] = 2;
        assert!(ClearCodec::new().decode(&bad, 3, 2, &mut out).is_err());
    }

    #[test]
    fn truncated_and_invalid() {
        for hex in [EXAMPLE_2, EXAMPLE_4] {
            let src = unhex(hex);
            for n in 0..src.len() {
                let mut out = vec![0u8; 78 * 17 * 4];
                // Tailles différentes selon l'exemple : seule l'absence de panique compte ici,
                // et une erreur pour toute coupure dans l'en-tête ou les longueurs annoncées.
                let (w, h) = if hex == EXAMPLE_2 { (78, 17) } else { (7, 15) };
                out.truncate(w * h * 4);
                assert!(ClearCodec::new().decode(&src[..n], w as u32, h as u32, &mut out).is_err());
            }
        }
        let mut out = vec![0u8; 4];
        // GLYPH_HIT sans GLYPH_INDEX, index hors limites, glyphe trop grand.
        assert!(ClearCodec::new().decode(&[0x02, 0], 1, 1, &mut out).is_err());
        assert!(ClearCodec::new().decode(&[0x03, 0, 0xA0, 0x0F], 1, 1, &mut out).is_err());
        let mut big = vec![0u8; 33 * 32 * 4];
        assert!(ClearCodec::new().decode(&[0x01, 0, 0, 0], 33, 32, &mut big).is_err());
        // Mauvaise taille de sortie.
        assert!(ClearCodec::new().decode(&[0; 14], 2, 1, &mut out).is_err());
    }
}
