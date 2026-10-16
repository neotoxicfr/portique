//! Conversion YUV420p → RGBA, BT.709 pleine plage (MS-RDPEGFX 3.3.8.3.1).

use crate::{Error, Rect};

/// Image YUV420p décodée (plans 8 bits ; chroma à demi-résolution).
pub struct Yuv420<'a> {
    pub width: u32,
    pub height: u32,
    pub y: &'a [u8],
    pub u: &'a [u8],
    pub v: &'a [u8],
    pub y_stride: u32,
    pub uv_stride: u32,
}

// Coefficients BT.709 pleine plage en virgule fixe (×2^16).
const RV: i32 = 103_206; // 1.5748
const GU: i32 = 12_276; // 0.1873
const GV: i32 = 30_679; // 0.4681
const BU: i32 = 121_609; // 1.8556

#[inline]
fn clamp(v: i32) -> u8 {
    v.clamp(0, 255) as u8
}

/// Un pixel YUV pleine plage BT.709 → RGBA opaque.
#[inline]
pub(crate) fn to_rgb(y: u8, u: u8, v: u8) -> [u8; 4] {
    let yv = (y as i32) << 16;
    let (u, v) = (u as i32 - 128, v as i32 - 128);
    [
        clamp((yv + RV * v + 0x8000) >> 16),
        clamp((yv - GU * u - GV * v + 0x8000) >> 16),
        clamp((yv + BU * u + 0x8000) >> 16),
        0xFF,
    ]
}

impl Yuv420<'_> {
    /// Vérifie que les plans couvrent bien les dimensions annoncées.
    pub(crate) fn check(&self) -> Result<(), Error> {
        if self.width == 0 || self.height == 0 {
            return Err(Error::Invalid("image H.264 vide"));
        }
        let need_y = ((self.height - 1) * self.y_stride + self.width) as usize;
        let need_uv = ((self.height.div_ceil(2) - 1) * self.uv_stride + self.width.div_ceil(2)) as usize;
        if self.y_stride < self.width
            || self.uv_stride < self.width.div_ceil(2)
            || self.y.len() < need_y
            || self.u.len() < need_uv
            || self.v.len() < need_uv
        {
            return Err(Error::Truncated("plans YUV"));
        }
        Ok(())
    }

    /// Convertit la zone `r` (coordonnées image = coordonnées surface) dans `dst` (RGBA).
    pub fn to_rgba(&self, r: Rect, dst: &mut [u8], dst_width: u32) -> Result<(), Error> {
        if r.x + r.w > self.width || r.y + r.h > self.height {
            return Err(Error::Invalid("zone H.264 hors de l'image décodée"));
        }
        self.check()?;
        for row in r.y..r.y + r.h {
            let yrow = &self.y[(row * self.y_stride) as usize..];
            let crow = ((row / 2) * self.uv_stride) as usize;
            let out = &mut dst
                [((row * dst_width + r.x) * 4) as usize..((row * dst_width + r.x + r.w) * 4) as usize];
            for (i, px) in out.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                let col = r.x + i as u32;
                let yv = (yrow[col as usize] as i32) << 16;
                let u = self.u[crow + (col / 2) as usize] as i32 - 128;
                let v = self.v[crow + (col / 2) as usize] as i32 - 128;
                px[0] = clamp((yv + RV * v + 0x8000) >> 16);
                px[1] = clamp((yv - GU * u - GV * v + 0x8000) >> 16);
                px[2] = clamp((yv + BU * u + 0x8000) >> 16);
                px[3] = 0xFF;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primaries() {
        // Blanc, noir, rouge pur (Y, U, V calculés en BT.709 pleine plage).
        let cases =
            [((255, 128, 128), [255, 255, 255]), ((0, 128, 128), [0, 0, 0]), ((54, 99, 255), [254, 0, 0])];
        for ((y, u, v), rgb) in cases {
            let (yp, up, vp) = ([y; 4], [u; 1], [v; 1]);
            let f = Yuv420 { width: 2, height: 2, y: &yp, u: &up, v: &vp, y_stride: 2, uv_stride: 1 };
            let mut dst = [0u8; 16];
            f.to_rgba(Rect { x: 0, y: 0, w: 2, h: 2 }, &mut dst, 2).unwrap();
            for c in 0..3 {
                assert!((dst[c] as i32 - rgb[c]).abs() <= 2, "{:?} → {:?}", (y, u, v), &dst[..4]);
            }
        }
    }
}
