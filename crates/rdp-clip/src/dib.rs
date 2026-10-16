//! CF_DIB / CF_DIBV5 : BITMAPINFOHEADER (ou V4/V5) suivi des pixels, lignes alignées sur 4 octets,
//! de bas en haut si la hauteur est positive. Pris en charge : 16, 24 et 32 bpp, BI_RGB,
//! BI_BITFIELDS et BI_ALPHABITFIELDS ; pas de palette ni de compression RLE/JPEG/PNG.

use alloc::vec::Vec;

use crate::{Error, MAX_DATA, MAX_DIM, le16, le32};

const BI_RGB: u32 = 0;
const BI_BITFIELDS: u32 = 3;
const BI_ALPHABITFIELDS: u32 = 6;
const HEADER: usize = 40;

/// Composante 8 bits d'un pixel selon un masque contigu.
fn channel(px: u32, mask: u32) -> u8 {
    if mask == 0 {
        return 0;
    }
    let shift = mask.trailing_zeros();
    let bits = (mask >> shift).count_ones();
    let v = (px & mask) >> shift;
    if bits >= 8 { (v >> (bits - 8)) as u8 } else { (v * 255 / ((1 << bits) - 1)) as u8 }
}

/// Décode un DIB en RGBA (stride largeur*4, de haut en bas) : (largeur, hauteur, pixels).
/// Un canal alpha entièrement nul (cas courant de l'octet « réservé » en 32 bpp) vaut opaque.
pub fn dib_to_rgba(dib: &[u8]) -> Result<(u32, u32, Vec<u8>), Error> {
    let size = le32(dib, 0).ok_or(Error::Truncated("en-tête DIB"))? as usize;
    if size < HEADER || size > dib.len() {
        return Err(Error::Invalid("en-tête DIB non pris en charge"));
    }
    let width = le32(dib, 4).unwrap_or(0) as i32;
    let height = le32(dib, 8).unwrap_or(0) as i32;
    let bpp = le16(dib, 14).unwrap_or(0);
    let compression = le32(dib, 16).unwrap_or(0);
    let clr_used = le32(dib, 32).unwrap_or(0) as usize;
    if width <= 0 || height == 0 {
        return Err(Error::Invalid("dimensions DIB"));
    }
    let (w, h) = (width as usize, height.unsigned_abs() as usize);
    if w > MAX_DIM || h > MAX_DIM || w * h * 4 > MAX_DATA {
        return Err(Error::Invalid("image trop grande"));
    }
    let top_down = height < 0;

    // Masques (R, G, B, A) et début des pixels.
    let mut offset = size;
    let masks = match (compression, bpp) {
        (BI_RGB, 32) => [0x00FF_0000, 0xFF00, 0xFF, 0xFF00_0000],
        (BI_RGB, 24) => [0; 4],
        (BI_RGB, 16) => [0x7C00, 0x03E0, 0x001F, 0],
        (BI_BITFIELDS | BI_ALPHABITFIELDS, 16 | 32) => {
            let n = if compression == BI_ALPHABITFIELDS { 4 } else { 3 };
            // En-tête de 40 octets : masques à la suite. V4/V5 : masques dans l'en-tête (alpha compris).
            let in_header = size >= HEADER + 4 * n;
            let at = |i: usize| le32(dib, HEADER + 4 * i).ok_or(Error::Truncated("masques DIB"));
            let alpha = if n == 4 || (in_header && size >= HEADER + 16) { at(3)? } else { 0 };
            if !in_header {
                offset += 4 * n;
            }
            [at(0)?, at(1)?, at(2)?, alpha]
        }
        _ => return Err(Error::Invalid("format DIB non pris en charge")),
    };
    // Palette facultative (inutilisée au-delà de 8 bpp) entre l'en-tête et les pixels.
    offset =
        clr_used.checked_mul(4).and_then(|p| offset.checked_add(p)).ok_or(Error::Invalid("palette DIB"))?;

    let bytes_pp = usize::from(bpp / 8);
    let stride = (w * usize::from(bpp)).div_ceil(32) * 4;
    let last_row = w * bytes_pp;
    let needed = offset.checked_add(stride * (h - 1) + last_row);
    if needed.is_none_or(|n| dib.len() < n) {
        return Err(Error::Truncated("pixels DIB"));
    }

    let mut out = Vec::with_capacity(w * h * 4);
    let mut any_alpha = false;
    for y in 0..h {
        let src_y = if top_down { y } else { h - 1 - y };
        let row = &dib[offset + src_y * stride..][..last_row];
        for px in row.chunks_exact(bytes_pp) {
            let rgba = match bytes_pp {
                3 => [px[2], px[1], px[0], 255],
                _ => {
                    let v = if bytes_pp == 2 {
                        u32::from(u16::from_le_bytes([px[0], px[1]]))
                    } else {
                        u32::from_le_bytes([px[0], px[1], px[2], px[3]])
                    };
                    let a = channel(v, masks[3]);
                    any_alpha |= a != 0;
                    [channel(v, masks[0]), channel(v, masks[1]), channel(v, masks[2]), a]
                }
            };
            out.extend_from_slice(&rgba);
        }
    }
    if bytes_pp != 3 && !any_alpha {
        out.as_chunks_mut::<4>().0.iter_mut().for_each(|p| p[3] = 255);
    }
    Ok((w as u32, h as u32, out))
}

/// Encode du RGBA (stride largeur*4) en DIB 32 bpp BI_RGB, de bas en haut (BGRA).
pub fn rgba_to_dib(width: u32, height: u32, rgba: &[u8]) -> Result<Vec<u8>, Error> {
    let (w, h) = (width as usize, height as usize);
    if w == 0 || h == 0 || w > MAX_DIM || h > MAX_DIM || w * h * 4 > MAX_DATA {
        return Err(Error::Invalid("dimensions de l'image"));
    }
    if rgba.len() != w * h * 4 {
        return Err(Error::Invalid("taille des pixels RGBA"));
    }
    let image = (w * h * 4) as u32;
    let mut out = Vec::with_capacity(HEADER + w * h * 4);
    out.extend_from_slice(&(HEADER as u32).to_le_bytes());
    out.extend_from_slice(&width.to_le_bytes());
    out.extend_from_slice(&height.to_le_bytes()); // positif : de bas en haut
    out.extend_from_slice(&1u16.to_le_bytes()); // biPlanes
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&BI_RGB.to_le_bytes());
    out.extend_from_slice(&image.to_le_bytes());
    out.extend_from_slice(&[0; 16]); // résolution, biClrUsed, biClrImportant
    for row in rgba.chunks_exact(w * 4).rev() {
        for p in row.as_chunks::<4>().0 {
            out.extend_from_slice(&[p[2], p[1], p[0], p[3]]);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn header(w: i32, h: i32, bpp: u16, compression: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&40u32.to_le_bytes());
        v.extend_from_slice(&w.to_le_bytes());
        v.extend_from_slice(&h.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes());
        v.extend_from_slice(&bpp.to_le_bytes());
        v.extend_from_slice(&compression.to_le_bytes());
        v.extend_from_slice(&[0; 20]);
        v
    }

    #[test]
    fn rgba_roundtrip_32bpp() {
        let rgba: Vec<u8> = (0..2 * 3 * 4).map(|i| i as u8 * 7 + 1).collect();
        let dib = rgba_to_dib(2, 3, &rgba).unwrap();
        assert_eq!(dib.len(), 40 + 24);
        // Première ligne stockée = dernière ligne de l'image, en BGRA.
        assert_eq!(&dib[40..44], &[rgba[18], rgba[17], rgba[16], rgba[19]]);
        assert_eq!(dib_to_rgba(&dib).unwrap(), (2, 3, rgba));
    }

    #[test]
    fn bottom_up_24bpp_with_padding() {
        // 3×2, 24 bpp : 9 octets utiles + 3 de remplissage par ligne. Ligne du bas d'abord.
        let mut dib = header(3, 2, 24, BI_RGB);
        dib.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0]); // bas (BGR)
        dib.extend_from_slice(&[10, 11, 12, 13, 14, 15, 16, 17, 18, 0, 0, 0]); // haut
        let (w, h, px) = dib_to_rgba(&dib).unwrap();
        assert_eq!((w, h), (3, 2));
        assert_eq!(&px[..4], &[12, 11, 10, 255]);
        assert_eq!(&px[12..16], &[3, 2, 1, 255]);
        assert_eq!(&px[20..24], &[9, 8, 7, 255]);
        // Sans le remplissage de la dernière ligne lue : toléré.
        dib.truncate(dib.len() - 3);
        assert!(dib_to_rgba(&dib).is_ok());
    }

    #[test]
    fn top_down_32bpp_zero_alpha_is_opaque() {
        let mut dib = header(1, -2, 32, BI_RGB);
        dib.extend_from_slice(&[1, 2, 3, 0, 4, 5, 6, 0]);
        assert_eq!(dib_to_rgba(&dib).unwrap().2, vec![3, 2, 1, 255, 6, 5, 4, 255]);
    }

    #[test]
    fn bitfields_after_header_and_v5() {
        // BI_BITFIELDS, en-tête de 40 octets : masques R, G, B à la suite (ici 0x000000FF = R).
        let mut dib = header(1, 1, 32, BI_BITFIELDS);
        for m in [0xFFu32, 0xFF00, 0xFF_0000] {
            dib.extend_from_slice(&m.to_le_bytes());
        }
        dib.extend_from_slice(&[10, 20, 30, 0]);
        assert_eq!(dib_to_rgba(&dib).unwrap().2, vec![10, 20, 30, 255]);

        // BITMAPV5HEADER (124 octets) : masques et alpha dans l'en-tête.
        let mut v5 = header(1, 1, 32, BI_BITFIELDS);
        v5[..4].copy_from_slice(&124u32.to_le_bytes());
        for m in [0xFF_0000u32, 0xFF00, 0xFF, 0xFF00_0000] {
            v5.extend_from_slice(&m.to_le_bytes());
        }
        v5.resize(124, 0);
        v5.extend_from_slice(&[30, 20, 10, 128]);
        assert_eq!(dib_to_rgba(&v5).unwrap().2, vec![10, 20, 30, 128]);

        // 16 bpp 565.
        let mut d16 = header(1, 1, 16, BI_BITFIELDS);
        for m in [0xF800u32, 0x07E0, 0x001F] {
            d16.extend_from_slice(&m.to_le_bytes());
        }
        d16.extend_from_slice(&0xF81Fu16.to_le_bytes());
        d16.extend_from_slice(&[0, 0]);
        assert_eq!(dib_to_rgba(&d16).unwrap().2, vec![255, 0, 255, 255]);
    }

    #[test]
    fn hostile_dibs_rejected() {
        assert!(dib_to_rgba(&[]).is_err());
        assert!(dib_to_rgba(&header(0, 1, 32, BI_RGB)).is_err());
        assert!(dib_to_rgba(&header(1, i32::MIN, 32, BI_RGB)).is_err());
        assert!(dib_to_rgba(&header(20_000, 1, 32, BI_RGB)).is_err());
        assert!(dib_to_rgba(&header(4, 4, 32, BI_RGB)).is_err()); // pixels absents
        assert!(dib_to_rgba(&header(1, 1, 8, BI_RGB)).is_err()); // palette
        let mut huge_palette = header(1, 1, 32, BI_RGB);
        huge_palette[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
        huge_palette.extend_from_slice(&[0; 4]);
        assert!(dib_to_rgba(&huge_palette).is_err());
        let mut big_size = header(1, 1, 32, BI_RGB);
        big_size[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(dib_to_rgba(&big_size).is_err());
        assert!(rgba_to_dib(2, 2, &[0; 15]).is_err());
        assert!(rgba_to_dib(0, 2, &[]).is_err());
    }
}
