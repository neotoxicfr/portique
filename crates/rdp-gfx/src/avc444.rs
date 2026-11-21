//! Recombinaison AVC444 (MS-RDPEGFX 3.3.8.3.2 pour la v1, 3.3.8.3.3 pour la v2).
//!
//! Un image 4:4:4 arrive en deux sous-images 4:2:0 décodées par le même décodeur : la vue
//! principale (luma + chroma moyennée) et la vue auxiliaire (chroma manquante). On garde les plans
//! reconstitués par surface : une sous-image chroma seule (LC=2) se combine avec la dernière luma.

use alloc::{vec, vec::Vec};

use crate::{Error, Rect, Yuv420};

/// Plans pleine résolution d'une surface en mode 4:4:4.
pub struct Planes444 {
    pub width: u32,
    pub height: u32,
    pub y: Vec<u8>,
    /// Chroma de la vue principale, demi-résolution : moyenne des 2×2 (Ũ, Ṽ).
    pub mu: Vec<u8>,
    pub mv: Vec<u8>,
    /// Chroma pleine résolution ; les positions paires-paires sont reconstruites à la demande.
    pub u: Vec<u8>,
    pub v: Vec<u8>,
}

impl Planes444 {
    pub fn new(width: u32, height: u32) -> Self {
        let full = (width * height) as usize;
        let half = (width.div_ceil(2) * height.div_ceil(2)) as usize;
        Self {
            width,
            height,
            y: vec![0; full],
            mu: vec![128; half],
            mv: vec![128; half],
            u: vec![128; full],
            v: vec![128; full],
        }
    }

    pub fn bytes(&self) -> usize {
        self.y.len() + self.mu.len() + self.mv.len() + self.u.len() + self.v.len()
    }

    fn hw(&self) -> usize {
        self.width.div_ceil(2) as usize
    }

    /// Vue principale : luma et chroma moyennée, sur les rectangles donnés.
    pub fn apply_main(&mut self, f: &Yuv420<'_>, rects: &[Rect]) -> Result<(), Error> {
        f.check()?;
        let hw = self.hw();
        for r in rects {
            let Some(r) = r.clip(self.width.min(f.width), self.height.min(f.height)) else { continue };
            for row in r.y..r.y + r.h {
                let (dst, src) = ((row * self.width) as usize, (row * f.y_stride) as usize);
                self.y[dst + r.x as usize..dst + (r.x + r.w) as usize]
                    .copy_from_slice(&f.y[src + r.x as usize..src + (r.x + r.w) as usize]);
            }
            for cy in r.y / 2..(r.y + r.h).div_ceil(2) {
                for cx in r.x / 2..(r.x + r.w).div_ceil(2) {
                    let s = (cy * f.uv_stride + cx) as usize;
                    self.mu[cy as usize * hw + cx as usize] = f.u[s];
                    self.mv[cy as usize * hw + cx as usize] = f.v[s];
                }
            }
        }
        Ok(())
    }

    /// Vue auxiliaire (chroma manquante), sur les rectangles donnés.
    pub fn apply_aux(&mut self, f: &Yuv420<'_>, rects: &[Rect], v2: bool) -> Result<(), Error> {
        f.check()?;
        self.aux_with(rects, v2, |s| f.at(s).map(|v| (v, true)));
        Ok(())
    }

    fn aux_with(&mut self, rects: &[Rect], v2: bool, at: impl Fn(Src) -> Option<(u8, bool)>) {
        let (w, h, hw) = (self.width, self.height, self.hw());
        for r in rects {
            let Some(r) = r.clip(w, h) else { continue };
            for y in r.y..r.y + r.h {
                for x in r.x..r.x + r.w {
                    let Some((su, sv)) = aux_src(x, y, w, v2) else { continue };
                    let (i, c) = ((y * w + x) as usize, (y / 2) as usize * hw + (x / 2) as usize);
                    if let Some((u, ok)) = at(su) {
                        self.u[i] = if ok { u } else { self.mu[c] };
                    }
                    if let Some((v, ok)) = at(sv) {
                        self.v[i] = if ok { v } else { self.mv[c] };
                    }
                }
            }
        }
    }

    /// Conversion 4:2:0 (zones de luma seule) : Y + chroma principale suréchantillonnée.
    pub fn to_rgba_420(&self, r: Rect, dst: &mut [u8], dst_width: u32) {
        let hw = self.hw();
        for y in r.y..r.y + r.h {
            for x in r.x..r.x + r.w {
                let c = (y / 2) as usize * hw + (x / 2) as usize;
                let px = crate::yuv::to_rgb(self.y[(y * self.width + x) as usize], self.mu[c], self.mv[c]);
                let o = ((y * dst_width + x) * 4) as usize;
                dst[o..o + 4].copy_from_slice(&px);
            }
        }
    }

    /// Conversion 4:4:4 (zones de chroma) avec le filtre inverse des positions paires-paires.
    pub fn to_rgba_444(&self, r: Rect, dst: &mut [u8], dst_width: u32) {
        let (w, h, hw) = (self.width, self.height, self.hw());
        for y in r.y..r.y + r.h {
            for x in r.x..r.x + r.w {
                let i = (y * w + x) as usize;
                let (mut u, mut v) = (self.u[i], self.v[i]);
                if x.is_multiple_of(2) && y.is_multiple_of(2) && x + 1 < w && y + 1 < h {
                    let c = (y / 2) as usize * hw + (x / 2) as usize;
                    u = reverse(self.mu[c], &self.u, i, w as usize);
                    v = reverse(self.mv[c], &self.v, i, w as usize);
                }
                let px = crate::yuv::to_rgb(self.y[i], u, v);
                let o = ((y * dst_width + x) * 4) as usize;
                dst[o..o + 4].copy_from_slice(&px);
            }
        }
    }
}

/// U444(2x,2y) = 4·Ũ − les trois voisins, gardé seulement si l'écart dépasse 30 (sinon Ũ).
fn reverse(avg: u8, plane: &[u8], i: usize, w: usize) -> u8 {
    let others = plane[i + 1] as i32 + plane[i + w] as i32 + plane[i + w + 1] as i32;
    let rec = (avg as i32 * 4 - others).clamp(0, 255);
    if (rec - avg as i32).abs() > 30 { rec as u8 } else { avg }
}

/// Échantillon d'une sous-image : plan et position.
#[derive(Clone, Copy)]
enum Src {
    Y(u32, u32),
    U(u32, u32),
    V(u32, u32),
}

impl Yuv420<'_> {
    fn at(&self, s: Src) -> Option<u8> {
        let (cw, ch) = (self.width.div_ceil(2), self.height.div_ceil(2));
        match s {
            Src::Y(x, y) => {
                (x < self.width && y < self.height).then(|| self.y[(y * self.y_stride + x) as usize])
            }
            Src::U(x, y) => (x < cw && y < ch).then(|| self.u[(y * self.uv_stride + x) as usize]),
            Src::V(x, y) => (x < cw && y < ch).then(|| self.v[(y * self.uv_stride + x) as usize]),
        }
    }
}

/// Échantillons de la vue auxiliaire qui portent U et V du pixel (x, y), s'il en porte.
fn aux_src(x: u32, y: u32, w: u32, v2: bool) -> Option<(Src, Src)> {
    if !v2 {
        if !y.is_multiple_of(2) {
            // B4/B5 : lignes impaires, entrelacées par blocs de 16 lignes dans la luma auxiliaire.
            let k = y / 16;
            let i = (y % 16) / 2;
            return Some((Src::Y(x, 16 * k + i), Src::Y(x, 16 * k + 8 + i)));
        }
        if !x.is_multiple_of(2) {
            // B6/B7 : lignes paires, colonnes impaires.
            return Some((Src::U(x / 2, y / 2), Src::V(x / 2, y / 2)));
        }
        return None;
    }
    let (hw, qw) = (w / 2, w / 4);
    if !x.is_multiple_of(2) {
        // B4/B5 : colonnes impaires, toutes les lignes ; U à gauche, V à droite.
        return Some((Src::Y(x / 2, y), Src::Y(hw + x / 2, y)));
    }
    if !y.is_multiple_of(2) {
        // B6..B9 : lignes impaires, colonnes paires (4x dans U aux, 4x+2 dans V aux).
        let (cx, cy) = (x / 4, y / 2);
        return Some(if x.is_multiple_of(4) {
            (Src::U(cx, cy), Src::U(qw + cx, cy))
        } else {
            (Src::V(cx, cy), Src::V(qw + cx, cy))
        });
    }
    None
}

/// Plans YUV420 d'une sous-image retrouvés depuis le RGB du navigateur (BT.709 pleine plage
/// inversé), en supposant qu'il a répété la chroma sur chaque bloc 2×2 (plus proche voisin).
pub struct FromRgb {
    pub width: u32,
    pub height: u32,
    pub y: Vec<u8>,
    pub u: Vec<u8>,
    pub v: Vec<u8>,
    /// Canaux libres de chaque pixel (un canal à 0 ou 255 a pu être borné) : 0, luma inconnue ;
    /// 3, luma exacte.
    y_free: Vec<u8>,
    /// Chroma de chaque bloc : 0, non calculée (hors des zones) ; 1, calculée ; 2, exacte (4 pixels
    /// libres).
    uv_state: Vec<u8>,
    /// Blocs dont les 4 pixels sont libres, et parmi eux ceux dont la chroma varie : le navigateur
    /// a alors interpolé la chroma, ce que l'inversion ne sait pas défaire.
    pub blocks_free: u32,
    pub blocks_interpolated: u32,
    /// Dernier bloc borné résolu : les aplats saturés répètent le même bloc.
    last: Option<Solved>,
}

/// Pixels d'un bloc, chroma attendue, chroma retenue.
type Solved = ([[u8; 3]; 4], [f64; 2], [f64; 2]);

// RGB → YUV BT.709 pleine plage en virgule fixe (×2^16) ; chaque ligne de chroma est de somme nulle.
const YR: i32 = 13_933;
const YG: i32 = 46_871;
const YB: i32 = 4_732;
const UC: [i32; 3] = [-7_509, -25_259, 32_768];
const VC: [i32; 3] = [32_768, -29_763, -3_005];
/// Part de (U−128, V−128) dans R, G et B (coefficients de `yuv::to_rgb`).
const CHROMA: [[f64; 2]; 3] = [[0.0, 1.5748], [-0.1873, -0.4681], [1.8556, 0.0]];

fn luma(p: [u8; 3]) -> u8 {
    ((YR * p[0] as i32 + YG * p[1] as i32 + YB * p[2] as i32 + (1 << 15)) >> 16) as u8
}

fn chroma(p: [u8; 3], c: [i32; 3]) -> i32 {
    c[0] * p[0] as i32 + c[1] * p[1] as i32 + c[2] * p[2] as i32
}

fn to_u8(x: f64) -> u8 {
    (x + 0.5).clamp(0.0, 255.0) as u8
}

fn free(c: u8) -> bool {
    c != 0 && c != 255
}

/// Chroma centrée (U−128, V−128) d'un bloc 2×2 dont des canaux sont bornés. Chaque pixel aux canaux
/// libres j et k donne (cⱼ − cₖ)·(U, V) = j − k : moindres carrés, `prior` fixant ce que ces
/// équations laissent libre, puis corrigé juste assez pour que les canaux bornés le restent
/// (observé à 255 : au moins 255) et que Y reste dans [0, 255].
fn clamped_chroma(px: &[(usize, [u8; 3])], prior: [f64; 2]) -> [f64; 2] {
    const LAMBDA: f64 = 1e-3;
    let (mut m00, mut m01, mut m11, mut r0, mut r1) = (0.0, 0.0, 0.0, 0.0, 0.0);
    for (_, p) in px {
        let mut chans = (0..3).filter(|&j| free(p[j]));
        let Some(j0) = chans.next() else { continue };
        for j in chans {
            let d = [CHROMA[j][0] - CHROMA[j0][0], CHROMA[j][1] - CHROMA[j0][1]];
            let delta = p[j] as f64 - p[j0] as f64;
            (m00, m01, m11) = (m00 + d[0] * d[0], m01 + d[0] * d[1], m11 + d[1] * d[1]);
            (r0, r1) = (r0 + d[0] * delta, r1 + d[1] * delta);
        }
    }
    let (e00, e11) = (m00 + LAMBDA, m11 + LAMBDA);
    let (e0, e1) = (r0 + LAMBDA * prior[0], r1 + LAMBDA * prior[1]);
    let det = e00 * e11 - m01 * m01;
    let mut x = [(e11 * e0 - m01 * e1) / det, (e00 * e1 - m01 * e0) / det];
    let tr = m00 + m11;
    let rank1 = tr > 1e-9 && m00 * m11 - m01 * m01 < 1e-6 * tr * tr;
    if tr > 1e-9 && !rank1 {
        // Deux directions fixées : solution exacte.
        return [x[0].clamp(-128.0, 127.0), x[1].clamp(-128.0, 127.0)];
    }
    // Contraintes n·x ≥ off, tirées de chaque pixel ayant un canal libre j0 : Y = j0 − c₀·x.
    let mut cons = [([0.0; 2], 0.0); 4 * 4 + 4];
    let mut k = 0;
    for (_, p) in px {
        let Some(j0) = (0..3).find(|&j| free(p[j])) else { continue };
        let (c0, v) = (CHROMA[j0], p[j0] as f64);
        cons[k] = ([-c0[0], -c0[1]], -v); // Y ≥ 0
        cons[k + 1] = (c0, v - 255.0); // Y ≤ 255
        k += 2;
        for q in (0..3).filter(|&q| !free(p[q])) {
            let d = [CHROMA[q][0] - c0[0], CHROMA[q][1] - c0[1]];
            cons[k] = if p[q] == 255 { (d, 254.5 - v) } else { ([-d[0], -d[1]], v - 0.5) };
            k += 1;
        }
    }
    for nv in [[1.0, 0.0], [0.0, 1.0]] {
        cons[k] = (nv, -128.0); // ≥ −128
        cons[k + 1] = ([-nv[0], -nv[1]], -127.0); // ≤ 127
        k += 2;
    }
    let cons = &cons[..k];
    if rank1 {
        // Une seule direction fixée (les pixels bornent tous le même canal, cas des aplats
        // saturés) : on ne bouge que le long de la direction libre.
        let n = if m00 >= m11 { [-m01, m00] } else { [-m11, m01] };
        let (mut lo, mut hi) = (f64::NEG_INFINITY, f64::INFINITY);
        for &(nv, off) in cons {
            // nv·(x + t·n) ≥ off
            let (s, gap) = (nv[0] * n[0] + nv[1] * n[1], off - (nv[0] * x[0] + nv[1] * x[1]));
            if s > 1e-9 {
                lo = lo.max(gap / s);
            } else if s < -1e-9 {
                hi = hi.min(gap / s);
            }
        }
        if lo <= hi {
            let t = 0f64.clamp(lo, hi);
            x = [x[0] + t * n[0], x[1] + t * n[1]];
        }
    } else {
        // Aucune direction fixée (un seul canal libre par pixel) : projections successives.
        for _ in 0..8 {
            let mut moved = false;
            for &(nv, off) in cons {
                let gap = off - (nv[0] * x[0] + nv[1] * x[1]);
                if gap > 1e-6 {
                    let nn = nv[0] * nv[0] + nv[1] * nv[1];
                    x = [x[0] + gap / nn * nv[0], x[1] + gap / nn * nv[1]];
                    moved = true;
                }
            }
            if !moved {
                break;
            }
        }
    }
    [x[0].clamp(-128.0, 127.0), x[1].clamp(-128.0, 127.0)]
}

impl FromRgb {
    /// Inverse les blocs 2×2 qui couvrent `rects`. `prior(cx, cy)` : chroma attendue du bloc
    /// (cx, cy), qui départage les blocs dont les canaux libres ne fixent pas toute la chroma ;
    /// `None` : moyenne des 4 pixels.
    pub fn new(
        f: &crate::Rgba<'_>,
        rects: &[Rect],
        prior: impl Fn(u32, u32) -> Option<(u8, u8)>,
    ) -> Result<Self, Error> {
        f.check()?;
        let (w, h) = (f.width, f.height);
        let (cw, ch) = (w.div_ceil(2), h.div_ceil(2));
        let (full, half) = ((w * h) as usize, (cw * ch) as usize);
        let mut o = Self {
            width: w,
            height: h,
            y: vec![0; full],
            u: vec![128; half],
            v: vec![128; half],
            y_free: vec![0; full],
            uv_state: vec![0; half],
            blocks_free: 0,
            blocks_interpolated: 0,
            last: None,
        };
        for r in rects {
            let Some(r) = r.clip(w, h) else { continue };
            for cy in r.y / 2..(r.y + r.h).div_ceil(2) {
                for cx in r.x / 2..(r.x + r.w).div_ceil(2) {
                    o.block(f, cx, cy, &prior);
                }
            }
        }
        Ok(o)
    }

    fn block(
        &mut self,
        f: &crate::Rgba<'_>,
        cx: u32,
        cy: u32,
        prior: &impl Fn(u32, u32) -> Option<(u8, u8)>,
    ) {
        let (w, h) = (self.width, self.height);
        let (x, y) = (2 * cx, 2 * cy);
        let (s, i) = ((y * f.stride + x * 4) as usize, (y * w + x) as usize);
        let at = |s: usize, i: usize| (i, [f.data[s], f.data[s + 1], f.data[s + 2]]);
        let mut px = [(0usize, [0u8; 3]); 4];
        let n = if x + 1 < w && y + 1 < h {
            let (st, wu) = (f.stride as usize, w as usize);
            px = [at(s, i), at(s + 4, i + 1), at(s + st, i + wu), at(s + st + 4, i + wu + 1)];
            4
        } else {
            // Bord droit ou bas d'une image de taille impaire.
            let mut n = 0;
            for (dx, dy) in [(0, 0), (1, 0), (0, 1), (1, 1)] {
                if x + dx < w && y + dy < h {
                    px[n] = at(s + (dy * f.stride + dx * 4) as usize, i + (dy * w + dx) as usize);
                    n += 1;
                }
            }
            n
        };
        let px = &px[..n];
        let c = (cy * w.div_ceil(2) + cx) as usize;
        if px.iter().all(|(_, p)| p.iter().all(|&v| free(v))) {
            // Cas courant : rien n'est borné, chroma moyenne et luma exactes.
            let (mut su, mut sv) = (0, 0);
            let (mut umin, mut umax, mut vmin, mut vmax) = (i32::MAX, i32::MIN, i32::MAX, i32::MIN);
            for &(i, p) in px {
                let (u, v) = (chroma(p, UC), chroma(p, VC));
                (su, sv) = (su + u, sv + v);
                (umin, umax, vmin, vmax) = (umin.min(u), umax.max(u), vmin.min(v), vmax.max(v));
                self.y[i] = luma(p);
                self.y_free[i] = 3;
            }
            self.uv_state[c] = 2;
            let k = (n as i32) << 16;
            self.u[c] = (128 + (2 * su + k).div_euclid(2 * k)).clamp(0, 255) as u8;
            self.v[c] = (128 + (2 * sv + k).div_euclid(2 * k)).clamp(0, 255) as u8;
            // Plus proche voisin : la chroma des 4 pixels ne diffère que par l'arrondi du RGB.
            self.blocks_free += 1;
            if (umax - umin).max(vmax - vmin) > 6 << 16 {
                self.blocks_interpolated += 1;
            }
            return;
        }
        let expected =
            prior(cx, cy).map(|(u, v)| [u as f64 - 128.0, v as f64 - 128.0]).unwrap_or_else(|| {
                // Faute de mieux : chroma moyenne des 4 pixels, bornés compris.
                let k = (n as f64) * 65536.0;
                let sum = |c| px.iter().map(|&(_, p)| chroma(p, c)).sum::<i32>() as f64 / k;
                [sum(UC), sum(VC)]
            });
        // Aucun canal libre (blanc, noir) : rien à résoudre.
        let [a, b] = if px.iter().any(|(_, p)| p.iter().any(|&v| free(v))) {
            let mut key = [[0u8; 3]; 4];
            for (k, (_, p)) in px.iter().enumerate() {
                key[k] = *p;
            }
            match self.last {
                Some((k, e, x)) if n == 4 && k == key && e == expected => x,
                _ => {
                    let x = clamped_chroma(px, expected);
                    self.last = (n == 4).then_some((key, expected, x));
                    x
                }
            }
        } else {
            [expected[0].clamp(-128.0, 127.0), expected[1].clamp(-128.0, 127.0)]
        };
        self.u[c] = to_u8(a + 128.0);
        self.v[c] = to_u8(b + 128.0);
        self.uv_state[c] = 1;
        for &(i, p) in px {
            // Y = canal − sa part de chroma, moyenné sur les canaux libres.
            let (mut acc, mut m) = (0.0, 0u8);
            for j in (0..3).filter(|&j| free(p[j])) {
                acc += p[j] as f64 - CHROMA[j][0] * a - CHROMA[j][1] * b;
                m += 1;
            }
            self.y_free[i] = m;
            self.y[i] = if m == 0 || m == 3 { luma(p) } else { to_u8(acc / m as f64) };
        }
    }

    /// La chroma varie dans des blocs entièrement libres : interpolée par le navigateur.
    pub fn interpolated(&self) -> bool {
        self.blocks_interpolated >= 4 && self.blocks_interpolated * 100 > self.blocks_free
    }

    pub fn view(&self) -> Yuv420<'_> {
        Yuv420 {
            width: self.width,
            height: self.height,
            y: &self.y,
            u: &self.u,
            v: &self.v,
            y_stride: self.width,
            uv_stride: self.width.div_ceil(2),
        }
    }

    /// Valeur d'un échantillon et sa fiabilité (la chroma l'est toujours, au besoin par la
    /// chroma attendue).
    fn at(&self, s: Src) -> Option<(u8, bool)> {
        match s {
            Src::Y(x, y) => (x < self.width && y < self.height).then(|| {
                let i = (y * self.width + x) as usize;
                (self.y[i], self.y_free[i] > 0)
            }),
            Src::U(x, y) | Src::V(x, y) => {
                let ok = self.uv_state.get((y * self.width.div_ceil(2) + x) as usize).is_some_and(|&k| k > 0);
                self.view().at(s).map(|v| (v, ok))
            }
        }
    }

    /// Valeur d'un échantillon calculé sans aucun canal borné.
    fn exact(&self, s: Src) -> Option<u8> {
        let v = self.view().at(s)?;
        let exact = match s {
            Src::Y(x, y) => self.y_free[(y * self.width + x) as usize] == 3,
            Src::U(x, y) | Src::V(x, y) => self.uv_state[(y * self.width.div_ceil(2) + x) as usize] == 2,
        };
        exact.then_some(v)
    }
}

impl Planes444 {
    /// Chroma de la vue principale (Ũ, Ṽ) aux positions que portent les échantillons U et V du
    /// bloc (cx, cy) de la vue auxiliaire : c'est ce qu'on en attend faute de mieux.
    fn aux_prior(&self, cx: u32, cy: u32, v2: bool) -> Option<(u8, u8)> {
        let hw = self.hw();
        let main = |x: u32, y: u32, v: bool| -> Option<u8> {
            let i = (y / 2) as usize * hw + (x / 2) as usize;
            if v { self.mv.get(i).copied() } else { self.mu.get(i).copied() }
        };
        if !v2 {
            return Some((main(2 * cx + 1, 2 * cy, false)?, main(2 * cx + 1, 2 * cy, true)?));
        }
        let qw = self.width / 4;
        let (x, v) = if cx < qw { (cx, false) } else { (cx - qw, true) };
        Some((main(4 * x, 2 * cy + 1, v)?, main(4 * x + 2, 2 * cy + 1, v)?))
    }

    /// Zones de la vue auxiliaire qui portent la chroma des zones `rects` de l'image (débords
    /// découpés par `FromRgb::new`).
    fn aux_blocks(&self, rects: &[Rect], v2: bool) -> Vec<Rect> {
        let mut out = Vec::new();
        for r in rects {
            let Some(r) = r.clip(self.width, self.height) else { continue };
            if !v2 {
                // Lignes impaires rangées par bandes de 16 lignes, chroma des lignes paires en place.
                let (y0, y1) = (r.y / 16 * 16, (r.y + r.h).div_ceil(16) * 16);
                out.push(Rect { x: r.x & !1, y: y0, w: r.w + 2, h: y1 - y0 });
            } else {
                // Colonnes à demi-largeur : moitié gauche (U), moitié droite (V).
                let (x0, x1) = (r.x / 4 * 2, (r.x + r.w) / 2 + 2);
                let (y0, h) = (r.y & !1, r.h + 2);
                let right = (self.width / 4 * 2).min(self.width / 2);
                out.push(Rect { x: x0, y: y0, w: x1 - x0, h });
                out.push(Rect { x: right + x0, y: y0, w: x1 - x0 + 2, h });
            }
        }
        out
    }

    /// Vue auxiliaire rendue en RGB par le navigateur, retrouvée en s'aidant de la vue principale
    /// déjà appliquée.
    pub fn aux_from_rgba(&self, f: &crate::Rgba<'_>, rects: &[Rect], v2: bool) -> Result<FromRgb, Error> {
        FromRgb::new(f, &self.aux_blocks(rects, v2), |cx, cy| self.aux_prior(cx, cy, v2))
    }

    pub fn apply_aux_from(&mut self, aux: &FromRgb, rects: &[Rect], v2: bool) {
        self.aux_with(rects, v2, |s| aux.at(s));
    }

    /// Contrôle du modèle d'inversion sur les zones unies de la vue principale déjà appliquée : la
    /// vue auxiliaire doit y porter la même chroma. Un écart moyen systématique pour une couleur
    /// trahit une autre conversion du navigateur (BT.601, plage limitée…), avec laquelle la
    /// recomposition ferait pire que la vue principale seule. Le bruit du codage, lui, se moyenne.
    pub fn aux_consistent(&self, aux: &FromRgb, rects: &[Rect], v2: bool) -> bool {
        let (w, h, hw) = (self.width, self.height, self.hw());
        // Écarts signés cumulés par classe : couleur (Ũ, Ṽ par pas de 32) et plan source (la luma
        // et la chroma de la vue auxiliaire ne sont pas déformées de la même façon).
        let (mut sum, mut cnt) = ([0i64; 128], [0i64; 128]);
        for r in rects {
            let Some(r) = r.clip(w, h) else { continue };
            for cy in r.y.div_ceil(2)..((r.y + r.h) / 2).min(h / 2).saturating_sub(1) {
                for cx in r.x.div_ceil(2)..((r.x + r.w) / 2).min(w / 2).saturating_sub(1) {
                    let c = cy as usize * hw + cx as usize;
                    let (mu, mv) = (self.mu[c] as i32, self.mv[c] as i32);
                    // Zone unie : luma du bloc et chroma des blocs voisins proches (bruit de codage).
                    let flat =
                        |p: &[u8]| [c + 1, c + hw].iter().all(|&o| (p[o] as i32 - p[c] as i32).abs() <= 2);
                    let i = (2 * cy * w + 2 * cx) as usize;
                    let ys = [self.y[i], self.y[i + 1], self.y[i + w as usize], self.y[i + w as usize + 1]];
                    let (ymin, ymax) = (ys.iter().min().unwrap(), ys.iter().max().unwrap());
                    if ymax - ymin > 6 || !flat(&self.mu) || !flat(&self.mv) {
                        continue;
                    }
                    // Classes centrées sur le neutre (128) : le bruit n'y fait pas changer de classe, ce
                    // qui biaiserait l'écart mesuré par rapport à cette même valeur.
                    let class = |m: i32| ((m as usize + 16) >> 5).min(7);
                    let k = class(mu) * 8 + class(mv);
                    for (x, y) in [(2 * cx + 1, 2 * cy), (2 * cx, 2 * cy + 1), (2 * cx + 1, 2 * cy + 1)] {
                        let Some((su, sv)) = aux_src(x, y, w, v2) else { continue };
                        for (s, m) in [(su, mu), (sv, mv)] {
                            if let Some(v) = aux.exact(s) {
                                let k = k + if matches!(s, Src::Y(..)) { 64 } else { 0 };
                                sum[k] += (v as i32 - m) as i64;
                                cnt[k] += 1;
                            }
                        }
                    }
                }
            }
        }
        // Refus si l'écart moyen d'une classe dépasse 1,5 avec une marge pour le bruit de codage,
        // corrélé par macrobloc (24/√n : 4,5 à 64 échantillons, 2,25 à 1 024).
        sum.iter().zip(&cnt).all(|(&s, &n)| {
            n < 64 || (s.unsigned_abs() as f64 / n as f64) <= 1.5 + 24.0 / (n as u32).isqrt() as f64
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u8 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 56) as u8
        }
    }

    /// Emballe un 4:4:4 en vues principale et auxiliaire, comme le ferait l'encodeur.
    type Packed = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

    fn pack(w: u32, h: u32, u: &[u8], v: &[u8], v2: bool) -> Packed {
        let (hw, hh) = ((w / 2) as usize, (h / 2) as usize);
        let at = |p: &[u8], x: u32, y: u32| p[(y * w + x) as usize];
        let (mut mu, mut mv) = (vec![0u8; hw * hh], vec![0u8; hw * hh]);
        for y in 0..hh as u32 {
            for x in 0..hw as u32 {
                let avg = |p: &[u8]| {
                    ((at(p, 2 * x, 2 * y) as u32
                        + at(p, 2 * x + 1, 2 * y) as u32
                        + at(p, 2 * x, 2 * y + 1) as u32
                        + at(p, 2 * x + 1, 2 * y + 1) as u32
                        + 2)
                        / 4) as u8
                };
                mu[y as usize * hw + x as usize] = avg(u);
                mv[y as usize * hw + x as usize] = avg(v);
            }
        }
        let (mut ay, mut au, mut av) = (vec![0u8; (w * h) as usize], vec![0u8; hw * hh], vec![0u8; hw * hh]);
        if !v2 {
            for k in 0..h / 16 {
                for i in 0..8 {
                    for x in 0..w {
                        ay[((16 * k + i) * w + x) as usize] = at(u, x, 16 * k + 2 * i + 1);
                        ay[((16 * k + 8 + i) * w + x) as usize] = at(v, x, 16 * k + 2 * i + 1);
                    }
                }
            }
            for y in 0..hh as u32 {
                for x in 0..hw as u32 {
                    au[y as usize * hw + x as usize] = at(u, 2 * x + 1, 2 * y);
                    av[y as usize * hw + x as usize] = at(v, 2 * x + 1, 2 * y);
                }
            }
        } else {
            for y in 0..h {
                for x in 0..w / 2 {
                    ay[(y * w + x) as usize] = at(u, 2 * x + 1, y);
                    ay[(y * w + w / 2 + x) as usize] = at(v, 2 * x + 1, y);
                }
            }
            for y in 0..hh as u32 {
                for x in 0..w / 4 {
                    let row = y as usize * hw;
                    au[row + x as usize] = at(u, 4 * x, 2 * y + 1);
                    au[row + (w / 4 + x) as usize] = at(v, 4 * x, 2 * y + 1);
                    av[row + x as usize] = at(u, 4 * x + 2, 2 * y + 1);
                    av[row + (w / 4 + x) as usize] = at(v, 4 * x + 2, 2 * y + 1);
                }
            }
        }
        (mu, mv, ay, au, av)
    }

    fn roundtrip(v2: bool) {
        let (w, h) = (32u32, 32u32);
        let mut rng = Rng(v2 as u64 + 7);
        let y: Vec<u8> = (0..w * h).map(|_| rng.next()).collect();
        let u: Vec<u8> = (0..w * h).map(|_| rng.next()).collect();
        let v: Vec<u8> = (0..w * h).map(|_| rng.next()).collect();
        let (mu, mv, ay, au, av) = pack(w, h, &u, &v, v2);
        let main = Yuv420 { width: w, height: h, y: &y, u: &mu, v: &mv, y_stride: w, uv_stride: w / 2 };
        let aux = Yuv420 { width: w, height: h, y: &ay, u: &au, v: &av, y_stride: w, uv_stride: w / 2 };
        let full = [Rect { x: 0, y: 0, w, h }];
        let mut p = Planes444::new(w, h);
        p.apply_main(&main, &full).unwrap();
        p.apply_aux(&aux, &full, v2).unwrap();
        // Toutes les positions non paires-paires sont exactes ; les paires-paires à ±30 au pire
        // (filtre inverse et seuil de la spec), exactes quand l'écart dépasse le seuil.
        let mut exact_far = 0;
        for yy in 0..h {
            for xx in 0..w {
                let i = (yy * w + xx) as usize;
                if xx.is_multiple_of(2) && yy.is_multiple_of(2) {
                    let c = (yy / 2 * (w / 2) + xx / 2) as usize;
                    let rec = reverse(p.mu[c], &p.u, i, w as usize);
                    assert!((rec as i32 - u[i] as i32).abs() <= 33, "U({xx},{yy})"); // seuil 30 + arrondi de la moyenne
                    if (rec as i32 - mu[c] as i32).abs() > 30 {
                        assert!((rec as i32 - u[i] as i32).abs() <= 3);
                        exact_far += 1;
                    }
                } else {
                    assert_eq!((p.u[i], p.v[i]), (u[i], v[i]), "({xx},{yy}) v2={v2}");
                }
            }
        }
        assert!(exact_far > 0, "le filtre inverse doit servir sur des données aléatoires");
    }

    #[test]
    fn v1_roundtrip() {
        roundtrip(false);
    }

    #[test]
    fn v2_roundtrip() {
        roundtrip(true);
    }

    /// Navigateur qui ne rend que du RGB : image de bureau 4:4:4 → vues principale et auxiliaire →
    /// RGB façon navigateur → plans retrouvés → combinaison, comparée à l'original.
    mod rgb {
        extern crate std;
        use super::*;
        use std::{format, println, string::String};

        #[derive(Clone, Copy, PartialEq, Debug)]
        enum Up {
            Nearest,
            /// Échantillons de chroma centrés (filtrage linéaire d'une texture).
            Bilinear,
        }

        #[derive(Clone, Copy, PartialEq, Debug)]
        enum Matrix {
            Bt709Full,
            Bt601Full,
            Bt709Limited,
        }

        fn to_yuv(p: [u8; 3]) -> [u8; 3] {
            let (r, g, b) = (p[0] as f64, p[1] as f64, p[2] as f64);
            let y = 0.2126 * r + 0.7152 * g + 0.0722 * b;
            let c = |x: f64| x.round().clamp(0.0, 255.0) as u8;
            [c(y), c((b - y) / 1.8556 + 128.0), c((r - y) / 1.5748 + 128.0)]
        }

        /// Conversion YUV420 → RGBA du navigateur.
        fn browser(w: u32, h: u32, planes: [&[u8]; 3], up: Up, m: Matrix) -> Vec<u8> {
            let [y, u, v] = planes;
            let (hw, hh) = ((w / 2) as usize, (h / 2) as usize);
            let chroma = |p: &[u8], x: u32, yy: u32| -> f64 {
                match up {
                    Up::Nearest => p[(yy / 2) as usize * hw + (x / 2) as usize] as f64,
                    Up::Bilinear => {
                        let fx = ((x as f64 + 0.5) / 2.0 - 0.5).clamp(0.0, (hw - 1) as f64);
                        let fy = ((yy as f64 + 0.5) / 2.0 - 0.5).clamp(0.0, (hh - 1) as f64);
                        let (x0, y0) = (fx.floor() as usize, fy.floor() as usize);
                        let (x1, y1) = ((x0 + 1).min(hw - 1), (y0 + 1).min(hh - 1));
                        let (ax, ay) = (fx - x0 as f64, fy - y0 as f64);
                        let at = |cx: usize, cy: usize| p[cy * hw + cx] as f64;
                        (at(x0, y0) * (1.0 - ax) + at(x1, y0) * ax) * (1.0 - ay)
                            + (at(x0, y1) * (1.0 - ax) + at(x1, y1) * ax) * ay
                    }
                }
            };
            let (gain, off, rv, gu, gv, bu) = match m {
                Matrix::Bt709Full => (1.0, 0.0, 1.5748, 0.1873, 0.4681, 1.8556),
                Matrix::Bt601Full => (1.0, 0.0, 1.402, 0.344136, 0.714136, 1.772),
                Matrix::Bt709Limited => (255.0 / 219.0, 16.0, 1.7927, 0.2132, 0.5329, 2.1124),
            };
            let mut out = vec![255u8; (w * h * 4) as usize];
            for yy in 0..h {
                for x in 0..w {
                    let l = (y[(yy * w + x) as usize] as f64 - off) * gain;
                    let (cu, cv) = (chroma(u, x, yy) - 128.0, chroma(v, x, yy) - 128.0);
                    let c = |x: f64| x.round().clamp(0.0, 255.0) as u8;
                    let o = ((yy * w + x) * 4) as usize;
                    out[o] = c(l + rv * cv);
                    out[o + 1] = c(l - gu * cu - gv * cv);
                    out[o + 2] = c(l + bu * cu);
                }
            }
            out
        }

        type Part = (&'static str, Rect);

        /// Bureau : fond clair et texte noir, texte coloré (lien, erreur, blanc sur bleu d'accent,
        /// ocre sur fond sombre), aplats saturés avec icônes 3×3, dégradé.
        fn desktop(w: u32, h: u32) -> (Vec<[u8; 3]>, [Part; 4]) {
            let mut img = vec![[243u8, 243, 243]; (w * h) as usize];
            let mut rng = Rng(42);
            let put = |img: &mut Vec<[u8; 3]>, x: u32, y: u32, c: [u8; 3]| img[(y * w + x) as usize] = c;
            let mix = |a: [u8; 3], b: [u8; 3]| -> [u8; 3] {
                core::array::from_fn(|i| ((a[i] as u16 + b[i] as u16) / 2) as u8)
            };
            // Pseudo-glyphes 5×8 à traits d'un pixel, avec des pixels de lissage.
            let mut text = |img: &mut Vec<[u8; 3]>, r: Rect, fg: [u8; 3], bg: [u8; 3]| {
                for y in r.y..r.y + r.h {
                    for x in r.x..r.x + r.w {
                        put(img, x, y, bg);
                    }
                }
                let mut gy = r.y + 2;
                while gy + 9 <= r.y + r.h {
                    let mut gx = r.x + 1;
                    while gx + 6 <= r.x + r.w {
                        let bits = (rng.next() as u32) << 8 | rng.next() as u32;
                        for (k, col) in [0, 2, 4].into_iter().enumerate() {
                            if bits >> k & 1 == 1 {
                                (0..8).for_each(|dy| put(img, gx + col, gy + dy, fg));
                            }
                        }
                        for (k, row) in [0, 3, 7].into_iter().enumerate() {
                            if bits >> (3 + k) & 1 == 1 {
                                (0..5).for_each(|dx| put(img, gx + dx, gy + row, fg));
                            }
                        }
                        for dx in 0..6 {
                            if bits >> (6 + dx) & 1 == 1 {
                                put(img, gx + dx, gy + 8, mix(bg, fg));
                            }
                        }
                        gx += 7;
                    }
                    gy += 11;
                }
            };
            let black = Rect { x: 0, y: 0, w: w / 2, h: h / 2 };
            text(&mut img, black, [0, 0, 0], [243, 243, 243]);
            let colored = Rect { x: w / 2, y: 0, w: w / 2, h: h / 2 };
            let q = colored.w / 4;
            let pairs = [
                ([0, 102, 204], [255, 255, 255]),
                ([232, 17, 35], [255, 255, 255]),
                ([255, 255, 255], [0, 120, 215]),
                ([206, 145, 120], [30, 30, 30]),
            ];
            for (i, (fg, bg)) in pairs.into_iter().enumerate() {
                text(&mut img, Rect { x: colored.x + i as u32 * q, y: 0, w: q, h: colored.h }, fg, bg);
            }
            let flat = Rect { x: 0, y: h / 2, w: w / 2, h: h / 2 };
            let palette: [[u8; 3]; 8] = [
                [0, 120, 215],
                [232, 17, 35],
                [16, 124, 16],
                [255, 185, 0],
                [255, 0, 0],
                [0, 0, 255],
                [0, 255, 0],
                [136, 23, 152],
            ];
            for y in flat.y..flat.y + flat.h {
                for x in flat.x..flat.x + flat.w {
                    // Aplats aux bords non alignés sur 2, semés d'icônes 3×3.
                    let (i, j) = (((x - flat.x) * 4 + 1) / flat.w, ((y - flat.y) * 2 + 1) / flat.h);
                    let icon = x % 11 < 3 && y % 9 < 3;
                    let k = if icon { (x / 11 + y / 9) as usize } else { (j * 4 + i) as usize };
                    put(&mut img, x, y, palette[k % 8]);
                }
            }
            let grad = Rect { x: w / 2, y: h / 2, w: w / 2, h: h / 2 };
            for y in grad.y..grad.y + grad.h {
                for x in grad.x..grad.x + grad.w {
                    let (t, s) = ((x - grad.x) as f64 / grad.w as f64, (y - grad.y) as f64 / grad.h as f64);
                    put(&mut img, x, y, [(255.0 * t) as u8, (255.0 * s) as u8, (255.0 * (1.0 - t)) as u8]);
                }
            }
            (img, [("texte noir", black), ("texte coloré", colored), ("aplats", flat), ("dégradé", grad)])
        }

        /// Erreur max et PSNR (dB) sur une zone.
        fn score(orig: &[[u8; 3]], got: &[u8], w: u32, r: Rect) -> (i32, f64) {
            let (mut max, mut se, mut n) = (0, 0.0, 0.0);
            for y in r.y..r.y + r.h {
                for x in r.x..r.x + r.w {
                    let i = (y * w + x) as usize;
                    for c in 0..3 {
                        let d = got[i * 4 + c] as i32 - orig[i][c] as i32;
                        (max, se, n) = (max.max(d.abs()), se + (d * d) as f64, n + 1.0);
                    }
                }
            }
            (max, if se == 0.0 { 99.0 } else { 10.0 * (255.0f64 * 255.0 * n / se).log10() })
        }

        const W: u32 = 256;
        const H: u32 = 128;
        const FULL: Rect = Rect { x: 0, y: 0, w: W, h: H };

        /// Images RGB des deux vues telles que les rend le navigateur ; `noise` : bruit de codage
        /// (±noise) ajouté aux plans décodés.
        fn views(img: &[[u8; 3]], v2: bool, up: Up, m: Matrix, noise: u8) -> (Vec<u8>, Vec<u8>) {
            let yuv: Vec<[u8; 3]> = img.iter().map(|&p| to_yuv(p)).collect();
            let plane = |k: usize| -> Vec<u8> { yuv.iter().map(|p| p[k]).collect() };
            let (y, u, v) = (plane(0), plane(1), plane(2));
            let (mu, mv, ay, au, av) = pack(W, H, &u, &v, v2);
            let mut rng = Rng(9);
            let mut noisy = |p: &[u8]| -> Vec<u8> {
                let span = 2 * noise as i32 + 1;
                p.iter()
                    .map(|&x| (x as i32 + rng.next() as i32 % span - noise as i32).clamp(0, 255) as u8)
                    .collect()
            };
            let (y, mu, mv, ay, au, av) =
                (noisy(&y), noisy(&mu), noisy(&mv), noisy(&ay), noisy(&au), noisy(&av));
            (browser(W, H, [&y, &mu, &mv], up, m), browser(W, H, [&ay, &au, &av], up, m))
        }

        /// Chemin de `Gfx::submit_avc444_rgba` ; `None` : recomposition refusée.
        fn recompose(main: &[u8], aux: &[u8], v2: bool) -> Option<Vec<u8>> {
            let rgba = |data| crate::Rgba { width: W, height: H, data, stride: W * 4 };
            let m = FromRgb::new(&rgba(main), &[FULL], |_, _| None).unwrap();
            if m.interpolated() {
                return None;
            }
            let mut p = Planes444::new(W, H);
            p.apply_main(&m.view(), &[FULL]).unwrap();
            let a = p.aux_from_rgba(&rgba(aux), &[FULL], v2).unwrap();
            if a.interpolated() || !p.aux_consistent(&a, &[FULL], v2) {
                return None;
            }
            p.apply_aux_from(&a, &[FULL], v2);
            let mut out = vec![0u8; (W * H * 4) as usize];
            p.to_rgba_444(FULL, &mut out, W);
            Some(out)
        }

        fn line(img: &[[u8; 3]], parts: &[Part], got: &[u8]) -> (String, Vec<(i32, f64)>) {
            let scores: Vec<_> =
                parts.iter().map(|(_, r)| score(img, got, W, *r)).chain([score(img, got, W, FULL)]).collect();
            let names = parts.iter().map(|(n, _)| *n).chain(["total"]);
            let text = names
                .zip(&scores)
                .map(|(n, (m, p))| format!("{n} {m}/{p:.1}"))
                .collect::<Vec<_>>()
                .join(" | ");
            (text, scores)
        }

        #[test]
        fn recomposition_beats_main_view() {
            let (img, parts) = desktop(W, H);
            for v2 in [false, true] {
                for noise in [0, 2] {
                    let (main, aux) = views(&img, v2, Up::Nearest, Matrix::Bt709Full, noise);
                    let (ta, a) = line(&img, &parts, &main);
                    let got = recompose(&main, &aux, v2)
                        .expect("ppv, BT.709 pleine plage : recomposition attendue");
                    let (tb, b) = line(&img, &parts, &got);
                    println!(
                        "v2={v2} bruit ±{noise}\n  (a) principale seule : {ta}\n  (b) recomposée      : {tb}"
                    );
                    // Texte coloré et total : au moins 6 dB de mieux, erreur max plus faible.
                    for k in [1, 4] {
                        assert!(b[k].1 >= a[k].1 + 6.0, "{}: {:?} contre {:?}", k, b[k], a[k]);
                        assert!(b[k].0 < a[k].0, "{}: {:?} contre {:?}", k, b[k], a[k]);
                    }
                    // Nulle part pire.
                    for k in 0..4 {
                        assert!(b[k].1 >= a[k].1 - 0.5, "{}: {:?} contre {:?}", parts[k].0, b[k], a[k]);
                    }
                }
            }
        }

        /// Coût en 1920×1088 (`cargo test --release -p rdp-gfx bench_1080p -- --ignored --nocapture`) :
        /// image du test répétée en mosaïque (dense, pire cas) et bureau blanc à texte noir.
        #[test]
        #[ignore]
        fn bench_1080p() {
            use std::time::Instant;
            let (w, h) = (1920u32, 1088u32);
            let (img, _) = desktop(W, H);
            let mut white = img.clone();
            for p in &mut white {
                if p[0] != p[1] || p[1] != p[2] || *p == [243, 243, 243] {
                    *p = [255, 255, 255];
                }
            }
            for (name, img) in [("mosaïque du test", &img), ("bureau blanc, texte noir", &white)] {
                let (m, a) = views(img, true, Up::Nearest, Matrix::Bt709Full, 0);
                let tile = |src: &[u8]| -> Vec<u8> {
                    (0..w * h)
                        .flat_map(|i| src[(((i / w) % H * W + i % w % W) * 4) as usize..][..4].to_vec())
                        .collect()
                };
                let (m, a) = (tile(&m), tile(&a));
                let full = [Rect { x: 0, y: 0, w, h }];
                let rgba = |data| crate::Rgba { width: w, height: h, data, stride: w * 4 };
                let mut out = vec![0u8; (w * h * 4) as usize];
                let (mut inv, mut yuv) = (Vec::new(), Vec::new());
                for _ in 0..9 {
                    let mut p = Planes444::new(w, h);
                    let t0 = Instant::now();
                    let mf = FromRgb::new(&rgba(&m), &full, |_, _| None).unwrap();
                    p.apply_main(&mf.view(), &full).unwrap();
                    let af = p.aux_from_rgba(&rgba(&a), &full, true).unwrap();
                    // (La mosaïque casse la disposition v2 : le contrôle refuse, son coût compte.)
                    std::hint::black_box(p.aux_consistent(&af, &full, true));
                    p.apply_aux_from(&af, &full, true);
                    p.to_rgba_444(full[0], &mut out, w);
                    let t1 = Instant::now();
                    // Chemin YUV actuel sur les mêmes plans, pour comparaison.
                    let mut q = Planes444::new(w, h);
                    q.apply_main(&mf.view(), &full).unwrap();
                    q.apply_aux(&af.view(), &full, true).unwrap();
                    q.to_rgba_444(full[0], &mut out, w);
                    inv.push((t1 - t0).as_secs_f64() * 1e3);
                    yuv.push(t1.elapsed().as_secs_f64() * 1e3);
                }
                let med = |v: &mut Vec<f64>| {
                    v.sort_by(f64::total_cmp);
                    v[v.len() / 2]
                };
                println!(
                    "{name} : depuis le RGB {:.1} ms, depuis les plans YUV {:.1} ms",
                    med(&mut inv),
                    med(&mut yuv)
                );
            }
        }

        #[test]
        fn partial_update_reads_the_right_aux_area() {
            // Zone aux bords impairs : la vue auxiliaire n'est inversée qu'aux endroits qui portent
            // sa chroma ; le résultat doit être celui de l'image entière.
            let (img, _) = desktop(W, H);
            let zone = Rect { x: 37, y: 21, w: 150, h: 70 };
            for v2 in [false, true] {
                let (main, aux) = views(&img, v2, Up::Nearest, Matrix::Bt709Full, 0);
                let rgba = |data| crate::Rgba { width: W, height: H, data, stride: W * 4 };
                let m = FromRgb::new(&rgba(&main), &[FULL], |_, _| None).unwrap();
                let mut out = [vec![0u8; (W * H * 4) as usize], vec![0u8; (W * H * 4) as usize]];
                for (k, rects) in [[FULL], [zone]].iter().enumerate() {
                    let mut p = Planes444::new(W, H);
                    p.apply_main(&m.view(), &[FULL]).unwrap();
                    let a = p.aux_from_rgba(&rgba(&aux), rects, v2).unwrap();
                    p.apply_aux_from(&a, rects, v2);
                    // Sans le bord droit et bas : le filtre inverse y lit des voisins hors zone.
                    p.to_rgba_444(Rect { w: zone.w - 2, h: zone.h - 2, ..zone }, &mut out[k], W);
                }
                assert!(out[0] == out[1], "v2={v2}");
            }
        }

        #[test]
        fn recomposition_refused_when_not_invertible() {
            let (img, _) = desktop(W, H);
            for v2 in [false, true] {
                for noise in [0, 2] {
                    for (up, m) in [
                        (Up::Bilinear, Matrix::Bt709Full),
                        (Up::Nearest, Matrix::Bt601Full),
                        (Up::Nearest, Matrix::Bt709Limited),
                    ] {
                        let (main, aux) = views(&img, v2, up, m, noise);
                        assert!(recompose(&main, &aux, v2).is_none(), "{up:?} {m:?} v2={v2} bruit ±{noise}");
                    }
                }
            }
        }
    }
}
