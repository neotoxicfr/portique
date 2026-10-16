//! Décodeur NSCodec (MS-RDPNSC 2.2.2 et 3.1.8.4), utilisé comme sous-codec 1 de ClearCodec.
//!
//! Quatre plans (luma, chroma orange, chroma verte, alpha facultatif), chacun brut ou compressé
//! en RLE selon que sa taille annoncée égale ou non sa taille attendue. Les chromas subissent la
//! réduction de perte de couleur (CLL) et, au besoin, le sous-échantillonnage ; les plans
//! sous-échantillonnés sont alors rembourrés (largeur multiple de 8, hauteur multiple de 2).

use alloc::vec::Vec;

use crate::Error;

const HEADER_LEN: usize = 20;

/// Décode un bitmap NSCodec vers RGBA (stride width*4), alpha 255 sauf plan alpha.
pub fn decode(src: &[u8], width: u32, height: u32, out: &mut [u8]) -> Result<(), Error> {
    if width == 0 || height == 0 {
        return Err(Error::Invalid("NSCodec : dimensions nulles"));
    }
    let (w, h) = (width as usize, height as usize);
    let size = w.checked_mul(h).ok_or(Error::Invalid("NSCodec : dimensions trop grandes"))?;
    if size.checked_mul(4) != Some(out.len()) {
        return Err(Error::Invalid("NSCodec : tampon de sortie de mauvaise taille"));
    }
    let header = src.get(..HEADER_LEN).ok_or(Error::Truncated("en-tête NSCodec"))?;
    let count =
        |i: usize| u32::from_le_bytes([header[i], header[i + 1], header[i + 2], header[i + 3]]) as usize;
    let counts = [count(0), count(4), count(8), count(12)]; // Y, Co, Cg, A
    let cll = header[16];
    if !(1..=7).contains(&cll) {
        return Err(Error::Invalid("NSCodec : niveau de perte de couleur hors de 1..7"));
    }
    let cs = header[17] != 0;

    // Dimensions des plans (2.2.2) : rembourrés seulement en cas de sous-échantillonnage.
    let (lw, cw, ch) = if cs {
        let lw = w.next_multiple_of(8);
        (lw, lw / 2, h.div_ceil(2))
    } else {
        (w, w, h)
    };
    let mut rest = &src[HEADER_LEN..];
    let mut take = |n: usize| -> Result<&[u8], Error> {
        let part = rest.get(..n).ok_or(Error::Truncated("plan NSCodec"))?;
        rest = &rest[n..];
        Ok(part)
    };
    let luma_len = lw.checked_mul(h).ok_or(Error::Invalid("NSCodec : dimensions trop grandes"))?;
    let luma = plane(take(counts[0])?, luma_len)?;
    let co = plane(take(counts[1])?, cw * ch)?;
    let cg = plane(take(counts[2])?, cw * ch)?;
    let alpha = if counts[3] == 0 { None } else { Some(plane(take(counts[3])?, size)?) };

    for (i, px) in out.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let (x, y) = (i % w, i / w);
        let c = if cs { (y / 2) * cw + x / 2 } else { i };
        let (r, g, b) = ycocg_to_rgb(luma[y * lw + x], co[c], cg[c], cll);
        *px = [r, g, b, alpha.as_ref().map_or(0xFF, |a| a[i])];
    }
    Ok(())
}

/// AYCoCg → RGB (MS-RDPEGDI 3.1.9.1.2), sans la permutation R/B propre au codec Planar.
/// L'octet de chroma décalé de `cll - 1` bits puis lu en `i8` vaut Co/2 (ou Cg/2).
fn ycocg_to_rgb(luma: u8, co: u8, cg: u8, cll: u8) -> (u8, u8, u8) {
    let half = |v: u8| i16::from((u32::from(v) << (cll - 1)) as u8 as i8);
    let (y, co, cg) = (i16::from(luma), half(co), half(cg));
    let t = y - cg;
    let clamp = |v: i16| v.clamp(0, 255) as u8;
    (clamp(t + co), clamp(y + cg), clamp(t - co))
}

/// Un plan : brut si sa taille est celle attendue, RLE si elle est plus petite (2.2.2).
fn plane(data: &[u8], expected: usize) -> Result<Vec<u8>, Error> {
    match data.len() {
        n if n == expected => Ok(data.to_vec()),
        n if n > expected => Err(Error::Invalid("NSCodec : plan plus grand qu'attendu")),
        _ => rle(data, expected),
    }
}

/// NSCODEC_RLE_SEGMENTS (2.2.2.1) : segments puis les 4 derniers octets du plan en clair.
/// Run : valeur répétée deux fois, puis longueur - 2 sur un octet (ou 0xFF et longueur sur
/// 32 bits) ; littéral : un octet suivi d'une valeur différente, ou dernier segment.
fn rle(data: &[u8], expected: usize) -> Result<Vec<u8>, Error> {
    if data.len() < 4 || expected < 4 {
        return Err(Error::Truncated("plan RLE NSCodec"));
    }
    let (segments, end) = data.split_at(data.len() - 4);
    let body = expected - 4;
    let mut out = Vec::with_capacity(expected);
    let mut i = 0;
    while i < segments.len() {
        let value = segments[i];
        i += 1;
        if segments.get(i) != Some(&value) {
            out.push(value);
        } else {
            let factor = *segments.get(i + 1).ok_or(Error::Truncated("run RLE NSCodec"))?;
            i += 2;
            let len = if factor < 0xFF {
                usize::from(factor) + 2
            } else {
                let b = segments.get(i..i + 4).ok_or(Error::Truncated("run RLE NSCodec"))?;
                i += 4;
                u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
            };
            if len > body - out.len().min(body) {
                return Err(Error::Invalid("NSCodec : run RLE au-delà du plan"));
            }
            out.resize(out.len() + len, value);
        }
        if out.len() > body {
            return Err(Error::Invalid("NSCodec : plan RLE trop long"));
        }
    }
    if out.len() != body {
        return Err(Error::Invalid("NSCodec : plan RLE incomplet"));
    }
    out.extend_from_slice(end);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn unhex(lines: &[&str]) -> Vec<u8> {
        let s: Vec<u8> = lines.concat().into_bytes();
        s.chunks(2).map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap()).collect()
    }

    fn run(src: &[u8], w: u32, h: u32) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; (w * h * 4) as usize];
        decode(src, w, h, &mut out).map(|()| out)
    }

    /// Exemple de MS-RDPNSC 4 : 15×10, CLL = 3, sous-échantillonnage, quatre plans RLE.
    const SPEC_IN: &[&str] = &[
        "71000000070000000b000000070000000301000063630164640063630264640063630064640163630164640163",
        "630164640063630064640163630064640c63630064640c63630064640c63630064640c6364640463646363006464",
        "036364640363630064636300646403656364640163646400656464066364640063630064640464656565222222",
        "222222223737193637370637373737ffff90ffffffff",
    ];
    /// Sortie attendue de la spec, en BGRA.
    const SPEC_OUT_BGRA: &[&str] = &[
        "ff3f0fffff3f0fffff3f0fffff4010ffff4010ffff3f0fffff3f0fffff3f0fffff3f0fffff4010ffff4010ffff3f0fff",
        "ff3f0fffff4010ffff4010ffff3f0fffff3f0fffff3f0fffff4010ffff4010ffff4010ffff3f0fffff3f0fffff3f0fff",
        "ff4010ffff4010ffff3f0fffff3f0fffff4010ffff4010ffff3f0fffff3f0fffff4010ffff4010ffff4010ffff4010ff",
        "ff4010ffff4010ffff4010ffff4010ffff4010ffff4010ffff4010ffff4010ffff4010ffff3f0fffff3f0fffff4010ff",
        "ff4010ffff4010ffff4010ffff4010ffff4010ffff4010ffff4010ffff4010ffff4010ffff4010ffff4010ffff4010ff",
        "ff3f0fffff3f0fffff4010ffff4010ffff4010ffff4010ffff4010ffff4010ffff4010ffff4010ffff4010ffff4010ff",
        "ff4010ffff4010ffff4010ffff3f0fffff3f0fffff4010ffff4010ffff4010ffff4010ffff4010ffff4010ffff4010ff",
        "ff4010ffff4010ffff4010ffff4010ffff4010ffff4010ffff3f0fffff4010ffff4010ffff4010ffff4010ffff4010ff",
        "ff3c14ffff3b13ffff4010ffff3f0fffff3f0fffff4010ffff4010ffff4010ffff4010ffff3f0fffff4010ffff4010ff",
        "ff4010ffff4010ffff4010ffff3b13ffff3b13ffff4010ffff3f0fffff3f0fffff4010ffff4010ffff4010ffff4010ff",
        "ff4111ffff3f0fffff4010ffff4010ffff4010ffff3f0fffff4010ffff4010ffff4111ffff4010ffff4010ffff4010ff",
        "ff4010ffff4010ffff4010ffff4010ffff3f0fffff4010ffff4010ffff3f0fffff3f0fffff4010ffff4010ffff4010ff",
        "ff4010ffff4010ffff4010ffff4010ffff4111ffff4111ff",
    ];

    #[test]
    fn spec_example() {
        let src = unhex(SPEC_IN);
        assert_eq!(src.len(), 158);
        let mut want = unhex(SPEC_OUT_BGRA);
        for px in want.chunks_mut(4) {
            px.swap(0, 2); // BGRA → RGBA
        }
        assert_eq!(run(&src, 15, 10).unwrap(), want);
    }

    /// Exemples de 3.1.8.1, transposés en octets (A = 1, B = 2...).
    #[test]
    fn rle_spec_streams() {
        // ABCDDDTTTTGFRRRRRRRRRRRABCD → ABCDD1TT2GFRR9ABCD.
        let enc = b"ABCDD\x01TT\x02GFRR\x09ABCD";
        assert_eq!(rle(enc, 27).unwrap(), b"ABCDDDTTTTGFRRRRRRRRRRRABCD");
        // Run long : 0xFF puis longueur sur 32 bits.
        let enc = [7, 7, 0xFF, 0x2C, 0x01, 0, 0, 1, 2, 3, 4];
        let dec = rle(&enc, 304).unwrap();
        assert!(dec[..300].iter().all(|&v| v == 7));
        assert_eq!(dec[300..], [1, 2, 3, 4]);
    }

    /// Plans bruts sans sous-échantillonnage, sans alpha : gris pur.
    #[test]
    fn raw_planes() {
        let mut src = vec![2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0];
        src.extend_from_slice(&[10, 200, 0, 0, 0, 0]);
        assert_eq!(run(&src, 2, 1).unwrap(), [10, 10, 10, 255, 200, 200, 200, 255]);
    }

    #[test]
    fn invalid_or_truncated() {
        let src = unhex(SPEC_IN);
        for n in 0..src.len() {
            assert!(run(&src[..n], 15, 10).is_err(), "tronqué à {n}");
        }
        // CLL nul.
        let mut bad = src.clone();
        bad[16] = 0;
        assert!(run(&bad, 15, 10).is_err());
        // Plan annoncé plus grand qu'attendu.
        let mut bad = src.clone();
        bad[12] = 151;
        assert!(run(&bad, 15, 10).is_err());
        // Run qui déborde du plan.
        assert!(rle(&[5, 5, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 1, 2, 3, 4], 10).is_err());
        // Plan RLE incomplet.
        assert!(rle(&[5, 1, 2, 3, 4], 10).is_err());
    }
}
