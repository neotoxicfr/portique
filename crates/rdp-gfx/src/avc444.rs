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
        let (w, h) = (self.width, self.height);
        for r in rects {
            let Some(r) = r.clip(w, h) else { continue };
            for y in r.y..r.y + r.h {
                for x in r.x..r.x + r.w {
                    if let Some((u, v)) = aux_sample(f, x, y, w, v2) {
                        let i = (y * w + x) as usize;
                        if let Some(u) = u {
                            self.u[i] = u;
                        }
                        if let Some(v) = v {
                            self.v[i] = v;
                        }
                    }
                }
            }
        }
        Ok(())
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

/// Valeurs U/V du pixel (x, y) portées par la vue auxiliaire, s'il en porte.
fn aux_sample(f: &Yuv420<'_>, x: u32, y: u32, w: u32, v2: bool) -> Option<(Option<u8>, Option<u8>)> {
    let yat = |px: u32, py: u32| -> Option<u8> {
        (px < f.width && py < f.height).then(|| f.y[(py * f.y_stride + px) as usize])
    };
    let uat = |px: u32, py: u32| -> Option<u8> {
        (px < f.width.div_ceil(2) && py < f.height.div_ceil(2)).then(|| f.u[(py * f.uv_stride + px) as usize])
    };
    let vat = |px: u32, py: u32| -> Option<u8> {
        (px < f.width.div_ceil(2) && py < f.height.div_ceil(2)).then(|| f.v[(py * f.uv_stride + px) as usize])
    };
    if !v2 {
        if !y.is_multiple_of(2) {
            // B4/B5 : lignes impaires, entrelacées par blocs de 16 lignes dans la luma auxiliaire.
            let k = y / 16;
            let i = (y % 16) / 2;
            return Some((yat(x, 16 * k + i), yat(x, 16 * k + 8 + i)));
        }
        if !x.is_multiple_of(2) {
            // B6/B7 : lignes paires, colonnes impaires.
            return Some((uat(x / 2, y / 2), vat(x / 2, y / 2)));
        }
        return None;
    }
    let (hw, qw) = (w / 2, w / 4);
    if !x.is_multiple_of(2) {
        // B4/B5 : colonnes impaires, toutes les lignes ; U à gauche, V à droite.
        return Some((yat(x / 2, y), yat(hw + x / 2, y)));
    }
    if !y.is_multiple_of(2) {
        // B6..B9 : lignes impaires, colonnes paires (4x dans U aux, 4x+2 dans V aux).
        let (cx, cy) = (x / 4, y / 2);
        return Some(if x.is_multiple_of(4) {
            (uat(cx, cy), uat(qw + cx, cy))
        } else {
            (vat(cx, cy), vat(qw + cx, cy))
        });
    }
    None
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
}
