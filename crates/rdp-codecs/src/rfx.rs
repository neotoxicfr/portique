//! Briques communes RemoteFX (MS-RDPRFX 3.1.8.2) : entropie RLGR1/RLGR3, déquantification,
//! DWT inverse 5/3 sur trois niveaux, conversion YCbCr → RGBA. Partagées par le codec
//! progressif (MS-RDPEGFX 2.2.4.2) qui ajoute la variante « reduce-extrapolate » de la DWT.
//!
//! Une composante de tuile = 4096 coefficients `i16`, bandes linéarisées dans l'ordre HL1, LH1,
//! HH1, HL2, LH2, HH2, HL3, LH3, HH3, LL3 (MS-RDPRFX 3.1.8.1.6). Les coefficients sont gardés en
//! virgule fixe 11.5 (RDP 7.1/8.0) : la déquantification décale de `q - 1` au lieu de `q - 6`
//! et la conversion de couleur retire les 5 bits fractionnaires.

/// Côté d'une tuile.
pub const TILE: usize = 64;
/// Coefficients par composante de tuile.
pub const COEFFS: usize = TILE * TILE;

/// Bandes (début, longueur) dans l'ordre linéaire, disposition classique 32/16/8.
const BANDS_CLASSIC: [(usize, usize); 10] = [
    (0, 1024),
    (1024, 1024),
    (2048, 1024),
    (3072, 256),
    (3328, 256),
    (3584, 256),
    (3840, 64),
    (3904, 64),
    (3968, 64),
    (4032, 64),
];
/// Disposition « reduce-extrapolate » (MS-RDPEGFX 3.2.8.1.2.2) : L/H = 33/31, 17/16, 9/8.
const BANDS_EXTRAPOLATE: [(usize, usize); 10] = [
    (0, 1023),
    (1023, 1023),
    (2046, 961),
    (3007, 272),
    (3279, 272),
    (3551, 256),
    (3807, 72),
    (3879, 72),
    (3951, 64),
    (4015, 81),
];
/// Niveaux (début du sous-tampon, nombre de basses, nombre de hautes), du 1er au 3e.
const LEVELS_CLASSIC: [(usize, usize, usize); 3] = [(0, 32, 32), (3072, 16, 16), (3840, 8, 8)];
const LEVELS_EXTRAPOLATE: [(usize, usize, usize); 3] = [(0, 33, 31), (3007, 17, 16), (3807, 9, 8)];

/// Bandes (début, longueur) dans l'ordre linéaire pour la disposition choisie.
pub const fn bands(extrapolate: bool) -> &'static [(usize, usize); 10] {
    if extrapolate { &BANDS_EXTRAPOLATE } else { &BANDS_CLASSIC }
}

/// Variante d'entropie RLGR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rlgr {
    Rlgr1,
    Rlgr3,
}

/// Lecteur de bits, octet de poids fort d'abord. Au-delà de la fin, lit des zéros : les
/// boucles de décodage restent bornées par le nombre de termes attendus.
pub(crate) struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BitReader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    #[inline]
    pub(crate) fn bit(&mut self) -> u32 {
        let b = self.data.get(self.pos >> 3).map_or(0, |b| (b >> (7 - (self.pos & 7))) & 1);
        self.pos += 1;
        b as u32
    }

    /// `n` bits (n ≤ 32).
    #[inline]
    pub(crate) fn bits(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        let n = n.min(32);
        let byte = self.pos >> 3;
        let mut acc = 0u64;
        for i in 0..5 {
            acc = (acc << 8) | u64::from(self.data.get(byte + i).copied().unwrap_or(0));
        }
        let off = (self.pos & 7) as u32;
        self.pos += n as usize;
        ((acc >> (40 - off - n)) & ((1u64 << n) - 1)) as u32
    }
}

const KPMAX: i32 = 80;
const LSGR: u32 = 3;
const UP_GR: i32 = 4;
const DN_GR: i32 = 6;
const UQ_GR: i32 = 3;
const DQ_GR: i32 = 3;

#[inline]
fn update(param: &mut i32, delta: i32) -> u32 {
    *param = (*param + delta).clamp(0, KPMAX);
    (*param as u32) >> LSGR
}

/// Code de Golomb-Rice (MS-RDPRFX 3.1.8.1.7.3.1, GetGRCode).
#[inline]
fn gr_code(bs: &mut BitReader, krp: &mut i32, kr: &mut u32) -> u32 {
    let mut vk = 0u32;
    while bs.bit() == 1 {
        vk += 1;
    }
    let mag = vk.wrapping_shl(*kr) | bs.bits(*kr);
    if vk == 0 {
        *kr = update(krp, -2);
    } else if vk != 1 {
        *kr = update(krp, vk.min(KPMAX as u32) as i32);
    }
    mag
}

/// (2 × magnitude − signe) → entier.
#[inline]
fn from_2ms(v: u32) -> i16 {
    let mag = (v >> 1) + (v & 1);
    (if v & 1 == 1 { (mag as i32).wrapping_neg() } else { mag as i32 }) as i16
}

/// Décode un flux RLGR1/RLGR3 (MS-RDPRFX 3.1.8.1.7.3.1) en remplissant tout `dst`. Un flux trop
/// court donne des zéros pour les termes manquants (le bourrage de fin est fait de zéros).
pub fn rlgr_decode(mode: Rlgr, src: &[u8], dst: &mut [i16]) {
    let mut bs = BitReader::new(src);
    let (mut k, mut kp) = (1u32, 1i32 << LSGR);
    let (mut kr, mut krp) = (1u32, 1i32 << LSGR);
    let n = dst.len();
    let mut i = 0;
    while i < n {
        if k != 0 {
            // Mode RL : chaque « 0 » vaut une série de 1 << k zéros.
            while i < n && bs.bit() == 0 {
                let run = (1usize << k).min(n - i);
                dst[i..i + run].fill(0);
                i += run;
                k = update(&mut kp, UP_GR);
            }
            if i >= n {
                break;
            }
            let run = (bs.bits(k) as usize).min(n - i);
            dst[i..i + run].fill(0);
            i += run;
            if i >= n {
                break;
            }
            let negative = bs.bit() == 1;
            let mag = gr_code(&mut bs, &mut krp, &mut kr).wrapping_add(1) as i32;
            dst[i] = (if negative { mag.wrapping_neg() } else { mag }) as i16;
            i += 1;
            k = update(&mut kp, -DN_GR);
        } else {
            let mag = gr_code(&mut bs, &mut krp, &mut kr);
            match mode {
                Rlgr::Rlgr1 => {
                    dst[i] = from_2ms(mag);
                    i += 1;
                    k = update(&mut kp, if mag == 0 { UQ_GR } else { -DQ_GR });
                }
                Rlgr::Rlgr3 => {
                    // Somme de deux termes ; le premier suit sur autant de bits que la somme.
                    let v1 = bs.bits(32 - mag.leading_zeros());
                    let v2 = mag.wrapping_sub(v1);
                    if v1 != 0 && v2 != 0 {
                        k = update(&mut kp, -2 * DQ_GR);
                    } else if v1 == 0 && v2 == 0 {
                        k = update(&mut kp, 2 * UQ_GR);
                    }
                    dst[i] = from_2ms(v1);
                    i += 1;
                    if i < n {
                        dst[i] = from_2ms(v2);
                        i += 1;
                    }
                }
            }
        }
    }
}

/// Décodage différentiel de LL3 (MS-RDPRFX 3.1.8.2.2) : somme cumulée.
pub fn differential_decode(buf: &mut [i16]) {
    for i in 1..buf.len() {
        buf[i] = buf[i].wrapping_add(buf[i - 1]);
    }
}

/// Déquantification : décalage à gauche par bande (ordre linéaire), `q - 1` en RemoteFX.
pub fn dequantize(buf: &mut [i16; COEFFS], extrapolate: bool, shifts: &[u8; 10]) {
    for (&(start, len), &s) in bands(extrapolate).iter().zip(shifts) {
        if s != 0 {
            for v in &mut buf[start..start + len] {
                *v = i32::from(*v).wrapping_shl(u32::from(s)) as i16;
            }
        }
    }
}

/// DWT inverse sur trois niveaux, en place ; `tmp` sert de tampon de travail.
pub fn idwt(buf: &mut [i16; COEFFS], tmp: &mut [i16; COEFFS], extrapolate: bool) {
    let levels = if extrapolate { &LEVELS_EXTRAPOLATE } else { &LEVELS_CLASSIC };
    for &(start, nl, nh) in levels.iter().rev() {
        // Premier niveau extrapolé : une 32e haute fréquence nulle, la 65e sortie est jetée.
        let ext = extrapolate && start == 0;
        let w = if ext { TILE } else { nl + nh };
        idwt_level(&mut buf[start..], tmp, nl, nh, ext, w);
    }
}

/// Un niveau : bandes HL (nh × nl lignes), LH (nl × nh), HH (nh × nh), LL (nl × nl) en tête de
/// `b` ; résultat w × w écrit au début de `b`. Horizontal d'abord, puis vertical.
fn idwt_level(b: &mut [i16], tmp: &mut [i16], nl: usize, nh: usize, ext: bool, w: usize) {
    let (hl, lh, hh, ll) = (0, nh * nl, 2 * nh * nl, 2 * nh * nl + nh * nh);
    for r in 0..nl {
        idwt_1d(&b[ll + r * nl..][..nl], &b[hl + r * nh..][..nh], ext, &mut tmp[r * w..][..w]);
    }
    for r in 0..nh {
        idwt_1d(&b[lh + r * nl..][..nl], &b[hh + r * nh..][..nh], ext, &mut tmp[(nl + r) * w..][..w]);
    }

    // Vertical, ligne par ligne : lignes basses 0..nl puis hautes nl..nl+nh dans `tmp`.
    let nh_eff = nh + usize::from(ext);
    let full = nl + nh_eff;
    let hrow = |i: usize| (i < nh).then(|| &tmp[(nl + i) * w..][..w]);
    let mut spare = [0i16; TILE]; // 65e ligne (extrapolation), utile à la 64e puis jetée
    for n in 0..nl {
        let low = &tmp[n * w..][..w];
        let (hp, hn) = (hrow(n.saturating_sub(1)), hrow(n.min(nh_eff - 1)));
        let dst = if 2 * n < w { &mut b[2 * n * w..][..w] } else { &mut spare[..w] };
        for x in 0..w {
            let h = hp.map_or(0, |r| i32::from(r[x])) + hn.map_or(0, |r| i32::from(r[x]));
            dst[x] = (i32::from(low[x]) - ((h + 1) >> 1)) as i16;
        }
    }
    for n in 0..nh_eff {
        let next = if 2 * n + 2 < full { 2 * n + 2 } else { 2 * n };
        let high = hrow(n);
        for x in 0..w {
            let e0 = i32::from(b[2 * n * w + x]);
            let e1 = i32::from(if next < w { b[next * w + x] } else { spare[x] });
            let h = high.map_or(0, |r| i32::from(r[x]));
            b[(2 * n + 1) * w + x] = (2 * h + ((e0 + e1) >> 1)) as i16;
        }
    }
}

/// DWT 5/3 inverse à une dimension (MS-RDPRFX 3.1.8.2.4) avec miroir aux bords. `low` a autant
/// de termes que `high` (sortie paire) ou un de plus (sortie impaire, MS-RDPEGFX 3.3.8.2.2) ;
/// `ext` ajoute une haute fréquence nulle. La sortie est tronquée à `out.len()`.
fn idwt_1d(low: &[i16], high: &[i16], ext: bool, out: &mut [i16]) {
    let nl = low.len();
    let nh = high.len() + usize::from(ext);
    let full = nl + nh;
    let h = |i: usize| high.get(i).map_or(0, |&v| i32::from(v));
    let mut x = [0i32; 2 * TILE + 2];
    for n in 0..nl {
        let sum = h(n.saturating_sub(1)) + h(n.min(nh - 1));
        x[2 * n] = i32::from((i32::from(low[n]) - ((sum + 1) >> 1)) as i16);
    }
    for n in 0..nh {
        let next = if 2 * n + 2 < full { x[2 * n + 2] } else { x[2 * n] };
        x[2 * n + 1] = 2 * h(n) + ((x[2 * n] + next) >> 1);
    }
    for (o, &v) in out.iter_mut().zip(&x) {
        *o = v as i16;
    }
}

/// Convertit la zone (sx, sy, w, h) d'une tuile YCbCr 11.5 en RGBA (alpha 255) vers `dst`, dont
/// les lignes sont espacées de `stride` octets. Ne fait rien si la zone sort de la tuile ou de `dst`.
pub fn ycbcr_to_rgba(
    y: &[i16; COEFFS],
    cb: &[i16; COEFFS],
    cr: &[i16; COEFFS],
    (sx, sy, w, h): (usize, usize, usize, usize),
    dst: &mut [u8],
    stride: usize,
) {
    // Comparé à la place restante : `sx + w` pourrait déborder.
    if w == 0 || h == 0 || sx >= TILE || sy >= TILE || w > TILE - sx || h > TILE - sy {
        return;
    }
    match (h - 1).checked_mul(stride).and_then(|n| n.checked_add(w * 4)) {
        Some(need) if need <= dst.len() => {}
        _ => return,
    }
    // Matrice de MS-RDPRFX 3.1.8.2.5 en virgule fixe 2^14 ; 5 bits fractionnaires en plus.
    const SHIFT: u32 = 14 + 5;
    const ROUND: i32 = 1 << (SHIFT - 1);
    let clamp = |v: i32| ((v + ROUND) >> SHIFT).clamp(0, 255) as u8;
    for row in 0..h {
        let s = (sy + row) * TILE + sx;
        let line = &mut dst[row * stride..][..w * 4];
        for (i, px) in line.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            let l = (i32::from(y[s + i]) + (128 << 5)) << 14;
            let (b, r) = (i32::from(cb[s + i]), i32::from(cr[s + i]));
            px[0] = clamp(l + 22979 * r);
            px[1] = clamp(l - 5632 * b - 11705 * r);
            px[2] = clamp(l + 28998 * b);
            px[3] = 0xFF;
        }
    }
}

/// Encodeur RLGR1 de test (MS-RDPRFX 3.1.8.1.7.3.2), pour fabriquer des flux.
#[cfg(test)]
pub(crate) fn rlgr1_encode(input: &[i16]) -> alloc::vec::Vec<u8> {
    struct W {
        out: alloc::vec::Vec<u8>,
        n: usize,
    }
    impl W {
        fn bit(&mut self, b: u32) {
            if self.n.is_multiple_of(8) {
                self.out.push(0);
            }
            if b != 0 {
                *self.out.last_mut().unwrap() |= 0x80 >> (self.n % 8);
            }
            self.n += 1;
        }
        fn bits(&mut self, n: u32, v: u32) {
            for i in (0..n).rev() {
                self.bit((v >> i) & 1);
            }
        }
    }
    fn code_gr(w: &mut W, krp: &mut i32, val: u32) {
        let kr = (*krp as u32) >> LSGR;
        let vk = val >> kr;
        for _ in 0..vk {
            w.bit(1);
        }
        w.bit(0);
        w.bits(kr, val & ((1 << kr) - 1));
        if vk == 0 {
            update(krp, -2);
        } else if vk > 1 {
            update(krp, vk as i32);
        }
    }
    let mut w = W { out: alloc::vec::Vec::new(), n: 0 };
    let (mut k, mut kp, mut krp) = (1u32, 8i32, 8i32);
    let mut i = 0;
    while i < input.len() {
        if k != 0 {
            let mut zeros = 0u32;
            while i < input.len() && input[i] == 0 {
                zeros += 1;
                i += 1;
            }
            while zeros >= 1 << k {
                w.bit(0);
                zeros -= 1 << k;
                k = update(&mut kp, UP_GR);
            }
            if i >= input.len() {
                if zeros > 0 {
                    w.bit(0);
                }
                break;
            }
            w.bit(1);
            w.bits(k, zeros);
            let v = i32::from(input[i]);
            i += 1;
            w.bit(u32::from(v < 0));
            code_gr(&mut w, &mut krp, v.unsigned_abs() - 1);
            k = update(&mut kp, -DN_GR);
        } else {
            let v = i32::from(input[i]);
            i += 1;
            let two_ms = 2 * v.unsigned_abs() - u32::from(v < 0);
            code_gr(&mut w, &mut krp, two_ms);
            k = update(&mut kp, if two_ms == 0 { UQ_GR } else { -DQ_GR });
        }
    }
    w.out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn unhex(lines: &[&str]) -> Vec<u8> {
        let s: Vec<u8> = lines.concat().into_bytes();
        s.chunks(2).map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap()).collect()
    }

    fn fnv(v: &[i16]) -> u64 {
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for b in v.iter().flat_map(|x| x.to_le_bytes()) {
            h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
        h
    }

    /// TS_RFX_CODEC_QUANT (ordre LL3 LH3 HL3 HH3 LH2 HL2 HH2 LH1 HL1 HH1, nibble bas d'abord)
    /// → décalages `q - 1` en ordre linéaire.
    fn rfx_shifts(q: &[u8; 5]) -> [u8; 10] {
        const WIRE_TO_LINEAR: [usize; 10] = [9, 7, 6, 8, 4, 3, 5, 1, 0, 2];
        let mut s = [0; 10];
        for (i, &d) in WIRE_TO_LINEAR.iter().enumerate() {
            let b = q[i / 2];
            s[d] = if i % 2 == 0 { b & 0x0F } else { b >> 4 } - 1;
        }
        s
    }

    /// Tuile de MS-RDPRFX 4.2.4.1 (RLGR3, quant 66 66 77 88 98) : YData, CbData, CrData.
    fn spec_tile() -> [Vec<u8>; 3] {
        let all = unhex(SPEC_TILE);
        assert_eq!(all.len(), 942 + 975 + 915);
        [all[..942].to_vec(), all[942..942 + 975].to_vec(), all[942 + 975..].to_vec()]
    }

    fn decode_component(data: &[u8]) -> [i16; COEFFS] {
        let mut c = [0i16; COEFFS];
        rlgr_decode(Rlgr::Rlgr3, data, &mut c);
        c
    }

    #[test]
    fn rlgr3_spec_components() {
        // Empreintes FNV-1a des dumps de MS-RDPRFX 4.2.4.2.1 à 4.2.4.2.3.
        let [y, cb, cr] = spec_tile();
        assert_eq!(fnv(&decode_component(&y)), 0xae4f_6feb_5895_2a44);
        assert_eq!(fnv(&decode_component(&cb)), 0x1f6e_a303_b694_44ef);
        assert_eq!(fnv(&decode_component(&cr)), 0x0d1a_6143_4da1_7838);
    }

    #[test]
    fn ll3_and_idwt_spec() {
        let [y, _, _] = spec_tile();
        let mut c = decode_component(&y);
        differential_decode(&mut c[4032..]);
        dequantize(&mut c, false, &rfx_shifts(&[0x66, 0x66, 0x77, 0x88, 0x98]));
        // LL3 en 11.5 (MS-RDPRFX 4.2.4.3.1.1), début et fin.
        assert_eq!(c[4032..4040], [-32, 0, -32, -480, -384, -384, -608, -736]);
        assert_eq!(c[4088..], [1888, 1664, 1248, 960, 1120, 1696, 480, -96]);
        let mut tmp = [0i16; COEFFS];
        idwt(&mut c, &mut tmp, false);
        // LL0 (composante Y reconstruite, 4.2.4.3.3.7).
        assert_eq!(c[..4], [-32, 16, 64, 272]);
        // Lignes 1 et 63 : le dump arrondit vers le haut quelques termes impairs (16 sur 1024
        // dans LL1, ex. (-272 - 119) / 2 → -195) sans règle lisible ; tolérance de 1.
        const ROW1: [i16; 64] = [
            68, 120, 172, 240, 53, 55, 57, 43, 30, 32, 34, 36, 38, 20, 2, -16, -34, -36, -38, -40, -42, -68,
            -94, -120, -146, -148, -151, -186, -220, -227, -233, -240, -247, -254, -261, -268, -275, -302,
            -329, -356, -384, -403, -423, -443, -463, -484, -506, -528, -550, -572, -594, -616, -639, -673,
            -707, -709, -712, -733, -754, -775, -796, -796, -796, -796,
        ];
        const ROW63: [i16; 64] = [
            1536, 1514, 1492, 1470, 1448, 1402, 1356, 1310, 1264, 1246, 1230, 1212, 1196, 1178, 1162, 1144,
            1128, 1086, 1046, 1004, 964, 938, 914, 888, 864, 834, 806, 776, 748, 710, 674, 636, 600, 588,
            576, 564, 552, 420, 288, 348, 408, 350, 294, 300, 308, 274, 242, 208, 176, 158, 142, 124, 108,
            82, 58, 32, 8, -24, -56, -88, -120, -120, -120, -120,
        ];
        for (got, want) in c[64..128].iter().chain(&c[4032..]).zip(ROW1.iter().chain(&ROW63)) {
            assert!(got.abs_diff(*want) <= 1, "{got} au lieu de {want}");
        }
    }

    #[test]
    fn spec_image() {
        let shifts = rfx_shifts(&[0x66, 0x66, 0x77, 0x88, 0x98]);
        let mut tmp = [0i16; COEFFS];
        let planes = spec_tile().map(|d| {
            let mut c = decode_component(&d);
            differential_decode(&mut c[4032..]);
            dequantize(&mut c, false, &shifts);
            idwt(&mut c, &mut tmp, false);
            c
        });
        let mut out = vec![0u8; COEFFS * 4];
        ycbcr_to_rgba(&planes[0], &planes[1], &planes[2], (0, 0, 64, 64), &mut out, 256);
        // Pixels XRGB de 4.2.4.4 (calculés en flottant par la spec : tolérance de 1).
        let expect: [(usize, u32); 14] = [
            (0, 0x229cdf),
            (1, 0x249de0),
            (63, 0x0d7ed6),
            (64, 0x259fe1),
            (65, 0x27a1e2),
            (700, 0x088cdc),
            (1000, 0x9dd638),
            (1500, 0xfcf5dd),
            (2080, 0x37b2f5),
            (2600, 0xfefed8),
            (3000, 0x1aa2f2),
            (3333, 0x54d0fa),
            (4032, 0x55d0f9),
            (4095, 0x129bf5),
        ];
        for (i, rgb) in expect {
            let px = &out[i * 4..i * 4 + 4];
            let want = [(rgb >> 16) as u8, (rgb >> 8) as u8, rgb as u8];
            for c in 0..3 {
                assert!(px[c].abs_diff(want[c]) <= 1, "pixel {i} : {px:?} au lieu de {want:?}");
            }
            assert_eq!(px[3], 0xFF);
        }
    }

    #[test]
    fn rlgr1_spec_examples() {
        // MS-RDPEGFX 4.1.2.1.1 et 4.1.2.1.3 : 14 coefficients.
        let mut out = [0i16; 14];
        rlgr_decode(Rlgr::Rlgr1, &[0xA8, 0x62, 0x6D, 0xFF, 0xF7, 0x00], &mut out);
        assert_eq!(out, [-2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 1, -7, 6]);
        rlgr_decode(Rlgr::Rlgr1, &[0x88, 0x76, 0xBD, 0xFF, 0xFE, 0xF2], &mut out);
        assert_eq!(out, [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, -4, 8, -9]);
        // L'encodeur de test reproduit les octets de la spec (bourrage final compris).
        assert_eq!(
            rlgr1_encode(&[-2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 1, -7, 6])[..5],
            [0xA8, 0x62, 0x6D, 0xFF, 0xF7]
        );
    }

    #[test]
    fn rlgr1_roundtrip() {
        let mut seed = 0x1234_5678u32;
        let mut input = [0i16; COEFFS];
        for v in input.iter_mut() {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            let r = (seed >> 16) % 100;
            *v = if r < 70 { 0 } else { ((seed >> 8) % 600) as i16 - 300 };
        }
        let enc = rlgr1_encode(&input);
        let mut out = [0i16; COEFFS];
        rlgr_decode(Rlgr::Rlgr1, &enc, &mut out);
        assert_eq!(out, input);
    }

    #[test]
    fn hostile_rlgr_never_panics() {
        let mut out = [0i16; COEFFS];
        for data in [&[][..], &[0xFF; 300][..], &[0x00; 10][..], &[0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]] {
            rlgr_decode(Rlgr::Rlgr1, data, &mut out);
            rlgr_decode(Rlgr::Rlgr3, data, &mut out);
        }
        rlgr_decode(Rlgr::Rlgr1, &[], &mut out);
        assert!(out.iter().all(|&v| v == 0));
    }

    #[test]
    fn extrapolate_reconstructs_ramp() {
        // Une rampe linéaire n'a aucune haute fréquence, extrapolation comprise : LL3 seule
        // (9 × 9, pas de 8 pixels) doit redonner f(x, y) = 32 (3x + 5y) + 64 sur 64 × 64.
        let f = |x: i32, y: i32| (32 * (3 * x + 5 * y) + 64) as i16;
        let mut c = [0i16; COEFFS];
        for i in 0..9 {
            for j in 0..9 {
                c[4015 + i * 9 + j] = f(8 * j as i32, 8 * i as i32);
            }
        }
        let mut tmp = [0i16; COEFFS];
        idwt(&mut c, &mut tmp, true);
        for y in 0..64 {
            for x in 0..64 {
                assert_eq!(c[y * 64 + x], f(x as i32, y as i32), "({x}, {y})");
            }
        }
    }

    #[test]
    fn color_clips_and_respects_bounds() {
        let y = [0i16; COEFFS];
        let (cb, cr) = ([0i16; COEFFS], [0i16; COEFFS]);
        let mut out = vec![7u8; 4 * 4 * 2];
        ycbcr_to_rgba(&y, &cb, &cr, (60, 62, 4, 2), &mut out, 16);
        assert!(out.chunks(4).all(|p| p == [128, 128, 128, 255]));
        // Zone hors tuile ou tampon trop court : rien n'est écrit.
        let mut small = vec![7u8; 8];
        ycbcr_to_rgba(&y, &cb, &cr, (62, 0, 4, 1), &mut small, 16);
        ycbcr_to_rgba(&y, &cb, &cr, (0, 0, 4, 1), &mut small, 16);
        ycbcr_to_rgba(&y, &cb, &cr, (usize::MAX, 0, 2, 1), &mut small, 16);
        ycbcr_to_rgba(&y, &cb, &cr, (0, usize::MAX, 1, 2), &mut small, 16);
        assert!(small.iter().all(|&b| b == 7));
    }

    const SPEC_TILE: &[&str] = &[
        "c00101154899c741a1126811dc222974effd2092e04ea8693bfd4183bf28530c1fe2540c777ca3057c30d09ce809391a",
        "5dffe2012213809087d29ffdfd50090d24a08fabfe3c0484c69cdef880c32250af4c2a7ffee05ca9528a067d3d090365",
        "a3afd2611f7204508d3e164a3ffffd414287243706172e56059c1cb3846afffb438ba37a324328e11f5054fccaa5dfff",
        "0804481561d97643f82a07e965f7c6892d40a1c3358df5edf591ae2fcc01ce0348c08d63f4fd50202d0c9bb08d13c08a",
        "09521b026e423bd0134e840126886a0484342aa500ba544858ea5402b41da7fa4782ec7a77fd0092666204a69bfff680",
        "c06901c23e9014202ffc409659580cb11368202eb5f5dffff8fc5688602453b541465ff8f17ede4a0897e055038fe575",
        "6103f2e19001a28e88049805936bffeac060a1880449bff7ff8cb4599080306453fff5c448dadacb80386157b2af00e8",
        "7b46e6d802038a0618143283d08aeebc81b428c47ff9a1690091c551fffe3fe9f170302410a7cb1f8a2493ed83003620",
        "d150e7d8ad5820092280d0ca5d1ad7f160752af2d7f8c0324586004301fe80f7428174844ca1604ccb1458014d18a1aa",
        "470e111a407d4102e330cd338134064683a2471c04aa2012a28b81c49ca02e0632f8868501e870f946096abfe0f5a4c8",
        "78e7d2970bbc3c97ffd54094b2c11818111f43c118c3837f9a31c48e7056daf617ded1020d422113dc3a3c409ef40143",
        "ea0c4673a27b0c80ffe4ad2e09b463b08c5459faac76361005f098888342002071ccc1a9973e5a0d04509223200d0a1c",
        "57d7ff10f2030f581ba511f8f1b412db1a48561fe3c750e916b4bcb04093eab55b2ffc500a6fcc25e006ab5f24fe8bcb",
        "42437e690225c738006ee580a8a43044158fe90cd3a6c214344afe037f06a5910254f1a1a153bf11f28f836780090812",
        "3ffd4491c28330500702824d31340641796ff0cc0379002c0524ec8d2915af44c8eb4fe1fdf141488108affe5148cee7",
        "f9b60a308311f00c3bd2a62424ef25fa5a3e923e790e3561c8aa1c2e9a277ffff07d305bbc91fffe43242866a7709928",
        "6e2b182bd4a1773b969ff7ebbe1f0434758431424c65aa0950a0c45131d3263a1bf46e4a4e172584787d2c3f4618ca5f",
        "f9e5382fd8719494e2cca315b0daa9cb58e41877938a51c623c44e6dd9141e9b8dbccb9dc41805f5a929f86d2938c744",
        "e53acdba61984a5702964202d93711de2dd43ffe61e733d7894addb03447f4dcadaac99d7e6d4bccdc178957fdbb3775",
        "475aec2c6e3c159254642cab9eab2bdd3c66a08f475e931a3716f489230000b03356fa141eff487a7e0f101ff491c810",
        "5684ff08ecb4ac0e0fffadc5e01a2f82049f91c20efe483679014214fffe30f00818f181459a60c179f0141210ceea31",
        "5afffc2013822fc9021f81cb00e110d2b4be87ffb01e2781b704063cc204f6060e28bc40bf121e86d46a7f181b96854c",
        "1680df2ca58d86a34a8ab41ba138a9d5ffffea0620d2951ef42fb2120e61784a17525de4251ffec0b31fffffec028280",
        "904188de482c42520b2f437e5078f2677841343dc80f67a1eb21fec01f2260416c00924b6010d00d0135050e87a2a05d",
        "1fa3af7ff1be8fcda5001c104015768105efee0060840099404a8217e9fcc47ffffd04800606dcafa77e9475740100e0",
        "9100857f8ed60b202130ca628e0704e945405f474a301541cbdffffcbfc3b4466a0140d0a73418241c2a45fea8050861",
        "fda8807101259cc1471737027a15fff301457fd680608367f89d2ff4dd8c30015142bc437a6b9f841e0048c1e0b7e07e",
        "99f24ae9400281c300243ac5520f91c868254099a4251a04d0a291ddeb93002149248b40753814a1fd3f8825bf3200e3",
        "19fcb9f86f81c001b3932009082584e134d41b488811a01559d70781813ba1402e2f487009c476490f2e502e4619a416",
        "a21b84a28958fc4f3f40904ca301320902809c91132cbade5d99f2ffff3d5a1fa902908ff308bd01f8d02a95410c400a",
        "20c4d4cc6b0ff080b15d283d08c2f8310249881428ede8863b009f95063715a459c880b610f0e5b81800561cff95210e",
        "7f2bc5085910e146318dece0a199bb21fffe3010d005e30850fcf30e008d688e07a6803442ed1f8800f08a21aef7fb80",
        "28860fffff82ea479591e00401440c29ff0e33e8c0540423fc815bf03c07107030d8216fefde460943fa5fff0d7230dd",
        "00dbe44824970846b149c44d801260ffa4a6fff68c00400502b40ff03efc843881948bfe49efc010498828a21c2a8b64",
        "d486d7ffffffeb916b111000694cbfb41cd800071680600a1c8242278243c90a64205a5f4ebf8c388236020772790723",
        "b4bb575fe804dd39e90795be042bdd8e22dc142c61a3a9cd4f825da044dff496fff52bfffe0119d2a29e43a57ff04c4c",
        "2b3c33e255ff0406292c0d225d7c93ba18aff932a6c3994679e306a6388b92224bdb1b3620b06c20ce3742e166d44934",
        "428bfa9c1299dc0687fa46f82f04a9d88207a6300fc0df35e890f0ffffa8e0d702601ac32028a231293ceb04a5dd480e",
        "82a4b656220657e0da1027310e1177fe02601648818c0d05177fcbbb7e252a41fd8a7fc9367ce0987e92ef7e0603133e",
        "203abf4cc30f2e8074bf393cf0a6b2e93f41551f2cf5d27e8cae4eaa613cbc3fc4c736dc23c8b852e28a80180000b246",
        "a2560d1294aabd0107fffa340c5ff80c1250afd6d18940a4ffe0cec449259dc1ff7e60245dcc10c0be5a12d3c3fe2d40",
        "7c289e7101d26e860bc8f29b45084c04527ef27ed9cc0b1c2080aeaffeb06d23f241e32e20114b7489ddffa838a39582",
        "15f0d0d5f1928eeec02681e947ffee0d2034313aef40b22947197f0427f1908509867d42e2545d5fe80ed02caa16bf04",
        "a7f8a2460b087a79e928627c33f40b1482fa61ebc1ff4ca4117f036844c11f813a6c7795022b5380e5101e90e8fd1fa6",
        "400b13ff4e4d7f52e8af9ac1800f0a14023cc00913e7dcc01a28a0e4838e0388d5af1abd9100b74ebadff8dbcc0243c4",
        "142a3fc80d091c44f4013cca285680a68500ea3e8feb9ffc6e07c4e03078a01e6f547851ff564a0147024c213bfb900a",
        "cc1dd247fffc701822c0b92fe97f91d3662f802c24a7fa8451ab6b7200ab3304cf43ff1751840c0150108f9034414484",
        "8e081904485084383d0252f97cd2d01f1342a02141c402023d09c8fd607d354f7ffff9976ad800c3830009504b908ac7",
        "944d47c16232282409522e2e1c9644a009c8ce64a91c190e523e3e1993a0362622089a00dd663a93d589d14006d4a822",
        "737b3d3fe30494ffffffff0c5677ace0c4061fb8a580fd681c321603de712a3d1419bec288d924925fc5900a85c23f87",
        "03a82617c406861287760a4816ed9693ec1b3073e81a3fff4dce40f30c514b849e672b15401aa0fc100fd8813587ff98",
        "0f4000bac071e2001828b382cc806aa043ff2dd6048a68fffffffc1af31a2a06c001400c30c1d0d74fcb741f07d3b40d",
        "8898eada9fce2b3c55b34014ffffffeadb9b92d868080b410926408cf1b09a98c0808bf03de7ec19682103297fe16d4c",
        "0f01d151011a502a592780c16e33f180e14908e917ffffff805a1010365ecaf83a001eb0068401f3071b4ac01e21438e",
        "a55577c7657cc2df5e0c4220d24861c81c65f8fe4c88711f825081a35409132852f5e082c3067ffa2ccff8f47ffffd01",
        "49a4b8de6284feed651f3c3cb25076305b03c008a66490c8cd146e69467ac61c87d7487b49052d5e7fcb67f0d90d1e9e",
        "53b764a5a5103906113fb1a9a6e84d4777da437689450970c2380f096fe72d823507fe64182eb80442548043126c9a55",
        "c90aa0794752652aff5011c94efe5b30a4e83063ff21121bdc1c0141511ffffac3e355f166e2d5785efa4df261012615",
        "a9f9d9324190364eaee30b16568c6e425dd81efe1d403a509f0914eb6e487a91887b7d8f724239b01c6518238b603000",
    ];
}
