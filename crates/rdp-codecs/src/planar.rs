//! Décodeur Planar (« RDP 6.0 Bitmap Compression », MS-RDPEGDI 2.2.2.5.1 et 3.1.9), codec
//! 0x000A d'EGFX (MS-RDPEGFX 2.2.2.1).
//!
//! Flux : un octet d'en-tête (CLL, CS, RLE, NA), puis les plans dans l'ordre alpha (si NA = 0),
//! luma ou rouge, chroma orange ou vert, chroma verte ou bleu ; en brut, un octet de bourrage
//! facultatif termine le flux. Les lignes vont de haut en bas (pas de retournement en EGFX).
//! Ce que la surface fait de l'alpha (ignoré hors codec Alpha) relève de l'appelant.

use alloc::vec;
use alloc::vec::Vec;

use crate::Error;

/// En-tête (MS-RDPEGDI 2.2.2.5.1).
const CLL_MASK: u8 = 0x07;
const CS: u8 = 0x08;
const RLE: u8 = 0x10;
const NA: u8 = 0x20;

/// Décode un flux Planar `width`×`height` vers `out` (RGBA, stride = width*4, len = width*height*4).
/// Sans plan alpha (NA=1), alpha = 255.
pub fn decode(src: &[u8], width: u32, height: u32, out: &mut [u8]) -> Result<(), Error> {
    if width == 0 || height == 0 {
        return Err(Error::Invalid("Planar : dimensions nulles"));
    }
    let (w, h) = (width as usize, height as usize);
    let size = w.checked_mul(h).ok_or(Error::Invalid("Planar : dimensions trop grandes"))?;
    if size.checked_mul(4) != Some(out.len()) {
        return Err(Error::Invalid("Planar : tampon de sortie de mauvaise taille"));
    }
    let (&header, mut rest) = src.split_first().ok_or(Error::Truncated("en-tête Planar"))?;
    let cll = header & CLL_MASK;
    let cs = header & CS != 0;
    if cs && cll == 0 {
        // Le sous-échantillonnage ne s'applique qu'à l'espace AYCoCg.
        return Err(Error::Invalid("Planar : sous-échantillonnage sans perte de couleur"));
    }
    let alpha = header & NA == 0;
    // Plans de chroma sous-échantillonnés : moitié de la taille, arrondie au supérieur (3.1.9.1.3).
    let (cw, ch) = if cs { (w.div_ceil(2), h.div_ceil(2)) } else { (w, h) };
    let dims = [(w, h), (w, h), (cw, ch), (cw, ch)]; // A, Y/R, Co/G, Cg/B

    let mut planes: [Vec<u8>; 4] = Default::default();
    for (i, &(pw, ph)) in dims.iter().enumerate() {
        if i == 0 && !alpha {
            continue;
        }
        let mut plane = vec![0u8; pw * ph];
        if header & RLE != 0 {
            let used = rle_plane(rest, pw, ph, &mut plane)?;
            rest = &rest[used..];
        } else {
            let raw = rest.get(..plane.len()).ok_or(Error::Truncated("plan Planar brut"))?;
            plane.copy_from_slice(raw);
            rest = &rest[plane.len()..];
        }
        planes[i] = plane;
    }
    // Reste : l'octet de bourrage du mode brut, ignoré comme tout octet en trop.

    let [a, p1, p2, p3] = &planes;
    for (i, px) in out.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let (x, y) = (i % w, i / w);
        px[3] = if alpha { a[i] } else { 0xFF };
        if cll == 0 {
            px[0] = p1[i];
            px[1] = p2[i];
            px[2] = p3[i];
        } else {
            let c = if cs { (y / 2) * cw + x / 2 } else { i };
            let (r, g, b) = ycocg_to_rgb(p1[i], p2[c], p3[c], cll);
            px[0] = r;
            px[1] = g;
            px[2] = b;
        }
    }
    Ok(())
}

/// AYCoCg → RGB (3.1.9.1.2 et 3.1.9.1.4). L'octet de chroma porte la valeur sur 9 bits décalée
/// de `cll` bits vers la droite (zéros en tête) : le décaler de `cll - 1` bits vers la gauche
/// puis le lire comme un `i8` donne directement Co/2 (ou Cg/2), signe compris.
/// R et B sont permutés après la transformation, comme la spec l'exige pour compenser
/// l'encodage erroné des serveurs Microsoft.
fn ycocg_to_rgb(luma: u8, co: u8, cg: u8, cll: u8) -> (u8, u8, u8) {
    let half = |v: u8| i16::from((u32::from(v) << (cll - 1)) as u8 as i8);
    let (y, co, cg) = (i16::from(luma), half(co), half(cg));
    let t = y - cg;
    let clamp = |v: i16| v.clamp(0, 255) as u8;
    (clamp(t - co), clamp(y + cg), clamp(t + co))
}

/// Décode un plan RLE (RDP6_RLE_SEGMENTS, 2.2.2.5.1.1 et 3.1.9.2.3) de `w`×`h` octets dans `dst`.
/// Renvoie le nombre d'octets lus. Première ligne en valeurs absolues, les suivantes en deltas
/// par rapport à la ligne du dessus ; un segment ne déborde jamais sur la ligne suivante.
fn rle_plane(src: &[u8], w: usize, h: usize, dst: &mut [u8]) -> Result<usize, Error> {
    let mut pos = 0;
    for y in 0..h {
        let (above, line) = dst.split_at_mut(y * w);
        let line = &mut line[..w];
        let above = if y == 0 { None } else { Some(&above[(y - 1) * w..]) };
        // Dernière valeur brute (absolue en première ligne, delta décodé ensuite), répétée par
        // le RUN ; elle se transmet d'un segment à l'autre de la même ligne.
        let mut last = 0u8;
        let mut x = 0;
        while x < w {
            let control = *src.get(pos).ok_or(Error::Truncated("segment RLE Planar"))?;
            pos += 1;
            if control == 0 {
                return Err(Error::Invalid("Planar : octet de contrôle RLE nul"));
            }
            let (mut run, mut raw) = (usize::from(control & 0x0F), usize::from(control >> 4));
            // Valeurs 1 et 2 : RUN long (16 ou 32 + cRawBytes), sans octet brut (2.2.2.5.1.2).
            if run == 1 || run == 2 {
                run = run * 16 + raw;
                raw = 0;
            }
            if raw + run > w - x {
                return Err(Error::Invalid("Planar : segment RLE plus long que la ligne"));
            }
            let raws = src.get(pos..pos + raw).ok_or(Error::Truncated("segment RLE Planar"))?;
            pos += raw;
            for &v in raws {
                last = if above.is_some() { delta(v) } else { v };
                put(line, above, x, last);
                x += 1;
            }
            for _ in 0..run {
                put(line, above, x, last);
                x += 1;
            }
        }
    }
    Ok(pos)
}

/// Delta encodé (3.1.9.2.3) : pair → v/2 ; impair → 255 - (v-1)/2, c'est-à-dire -(v/2 + 1).
fn delta(v: u8) -> u8 {
    if v & 1 == 0 { v >> 1 } else { 255 - (v >> 1) }
}

fn put(line: &mut [u8], above: Option<&[u8]>, x: usize, v: u8) {
    line[x] = match above {
        Some(a) => a[x].wrapping_add(v),
        None => v,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(src: &[u8], w: u32, h: u32) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; (w * h * 4) as usize];
        decode(src, w, h, &mut out).map(|()| out)
    }

    /// Exemple de MS-RDPEGDI 3.1.9.2.3 : plan 6×3, première ligne absolue, deltas ensuite
    /// (dont des négatifs : 0x01 → -1).
    const SPEC_PLANE: [u8; 19] = [
        0x13, 0xFF, 0x20, 0xFE, 0xFD, 0x60, 0x01, 0x7D, 0xF5, 0xC2, 0x9A, 0x38, 0x60, 0x01, 0x67, 0x8B, 0xA3,
        0x78, 0xAF,
    ];
    const SPEC_DECODED: [u8; 18] = [
        255, 255, 255, 255, 254, 253, //
        254, 192, 132, 96, 75, 25, //
        253, 140, 62, 14, 135, 193,
    ];

    #[test]
    fn rle_spec_example() {
        let mut plane = [0u8; 18];
        assert_eq!(rle_plane(&SPEC_PLANE, 6, 3, &mut plane), Ok(19));
        assert_eq!(plane, SPEC_DECODED);
    }

    /// Exemple de 3.1.9.2.2 : « A » répété 100 fois, RUN longs de 47 et 37.
    #[test]
    fn rle_extra_long_runs() {
        let mut plane = [0u8; 100];
        assert_eq!(rle_plane(&[0x1F, 0x41, 0xF2, 0x52], 100, 1, &mut plane), Ok(4));
        assert!(plane.iter().all(|&v| v == 0x41));
    }

    /// Un RUN sans octet brut en ligne de deltas répète le dernier delta de la ligne.
    #[test]
    fn rle_run_repeats_delta() {
        // Ligne 1 : 10, 10, 10, 10 (1 brut + RUN 3). Ligne 2 : delta 0x03 (= -2) puis RUN 3.
        let mut plane = [0u8; 8];
        rle_plane(&[0x13, 10, 0x13, 0x03], 4, 2, &mut plane).unwrap();
        assert_eq!(plane, [10, 10, 10, 10, 8, 8, 8, 8]);
    }

    /// ARGB brut 2×2 sans alpha, avec l'octet de bourrage final.
    #[test]
    fn raw_rgb_no_alpha() {
        let src = [NA, 1, 2, 3, 4, 10, 20, 30, 40, 100, 110, 120, 130, 0xAA];
        let out = run(&src, 2, 2).unwrap();
        assert_eq!(out, [1, 10, 100, 255, 2, 20, 110, 255, 3, 30, 120, 255, 4, 40, 130, 255]);
        // Sans bourrage aussi.
        assert_eq!(run(&src[..13], 2, 2).unwrap(), out);
    }

    /// ARGB brut 1×2 avec plan alpha en tête.
    #[test]
    fn raw_rgb_with_alpha() {
        let src = [0x00, 0x80, 0x00, 1, 2, 3, 4, 5, 6];
        assert_eq!(run(&src, 1, 2).unwrap(), [1, 3, 5, 0x80, 2, 4, 6, 0x00]);
    }

    /// Le plan de la spec sert de plan rouge, vert et bleu d'une image RLE 6×3.
    #[test]
    fn rle_image() {
        let mut src = vec![RLE | NA];
        for _ in 0..3 {
            src.extend_from_slice(&SPEC_PLANE);
        }
        let out = run(&src, 6, 3).unwrap();
        for (px, &v) in out.chunks(4).zip(SPEC_DECODED.iter()) {
            assert_eq!(px, [v, v, v, 255]);
        }
    }

    /// AYCoCg, CLL = 1 : Co = ±20 → octet = Co >> 1 (logique sur 9 bits), Cg = 0.
    /// Avec la permutation R/B de la spec : R = Y - Co/2, B = Y + Co/2.
    #[test]
    fn ycocg_cll1() {
        // Co = +20 → 10 ; Co = -20 → 0x1EC >> 1 = 0xF6.
        let src = [NA | 1, 100, 100, 10, 0xF6, 0, 0];
        let out = run(&src, 2, 1).unwrap();
        assert_eq!(out, [90, 100, 110, 255, 110, 100, 90, 255]);
    }

    /// AYCoCg, CLL = 3 : Co = -24 sur 9 bits = 0x1E8, >> 3 = 0x3D ; Cg = +16 → 0x02.
    #[test]
    fn ycocg_cll3_and_clamp() {
        // Y = 100 : T = Y - Cg/2 = 92 ; R = T - Co/2 = 104, G = Y + Cg/2 = 108, B = T + Co/2 = 80.
        assert_eq!(ycocg_to_rgb(100, 0x3D, 0x02, 3), (104, 108, 80));
        // Débordements ramenés dans 0..=255.
        assert_eq!(ycocg_to_rgb(250, 0x7F, 0x7F, 1), (0, 255, 250));
        assert_eq!(ycocg_to_rgb(5, 0x80, 0x80, 1), (255, 0, 5));
    }

    /// Sous-échantillonnage 3×3 : chroma 2×2, chaque valeur couvre un bloc 2×2 (tronqué au bord).
    #[test]
    fn chroma_subsampling() {
        let mut src = vec![NA | CS | 1];
        src.extend_from_slice(&[100; 9]); // Y
        src.extend_from_slice(&[0, 2, 4, 6]); // Co : demi-valeurs 0, 2, 4, 6
        src.extend_from_slice(&[0; 4]); // Cg
        let out = run(&src, 3, 3).unwrap();
        let reds: Vec<u8> = out.chunks(4).map(|p| p[0]).collect();
        assert_eq!(reds, [100, 100, 98, 100, 100, 98, 96, 96, 94]);
        // Plans tronqués : erreur.
        assert!(run(&src[..src.len() - 1], 3, 3).is_err());
    }

    #[test]
    fn truncated_inputs_fail_cleanly() {
        let mut rle = vec![RLE];
        for _ in 0..4 {
            rle.extend_from_slice(&SPEC_PLANE);
        }
        for n in 0..rle.len() {
            assert!(run(&rle[..n], 6, 3).is_err(), "RLE tronqué à {n}");
        }
        assert!(run(&rle, 6, 3).is_ok());
        let raw = [0u8; 1 + 4 * 4];
        for n in 0..raw.len() {
            assert!(run(&raw[..n], 2, 2).is_err(), "brut tronqué à {n}");
        }
        assert!(run(&raw, 2, 2).is_ok());
    }

    #[test]
    fn invalid_inputs() {
        // Segment qui dépasse la ligne (1 brut + RUN 3 sur une ligne de 3).
        let mut plane = [0u8; 3];
        assert!(rle_plane(&[0x13, 1], 3, 1, &mut plane).is_err());
        // Octet de contrôle nul.
        assert!(rle_plane(&[0x00], 3, 1, &mut plane).is_err());
        // CS sans CLL.
        assert!(run(&[NA | CS, 0, 0, 0], 1, 1).is_err());
        // Tampon de sortie de mauvaise taille, dimensions nulles.
        assert!(decode(&[NA, 0, 0, 0], 1, 1, &mut [0u8; 3]).is_err());
        assert!(decode(&[NA], 0, 1, &mut []).is_err());
    }
}
