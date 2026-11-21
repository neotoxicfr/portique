//! Fast-path (MS-RDPBCGR 2.2.8.1.2 entrées, 2.2.9.1.2 sorties) et curseurs (2.2.9.1.1.4).

use alloc::vec::Vec;

use crate::{Error, cursor::Reader};

/// Une trame fast-path commence par un octet dont les 2 bits faibles valent 0 (TPKT = 3).
pub fn is_fastpath(frame: &[u8]) -> bool {
    frame.first().is_some_and(|b| b & 0x03 == 0)
}

pub mod update_code {
    pub const ORDERS: u8 = 0x0;
    pub const BITMAP: u8 = 0x1;
    pub const PALETTE: u8 = 0x2;
    pub const SYNCHRONIZE: u8 = 0x3;
    pub const SURFCMDS: u8 = 0x4;
    pub const PTR_NULL: u8 = 0x5;
    pub const PTR_DEFAULT: u8 = 0x6;
    pub const PTR_POSITION: u8 = 0x8;
    pub const COLOR: u8 = 0x9;
    pub const CACHED: u8 = 0xA;
    pub const POINTER: u8 = 0xB;
    pub const LARGE_POINTER: u8 = 0xC;
}

/// Réassemble les mises à jour fast-path fragmentées (FIRST/NEXT/LAST).
#[derive(Default)]
pub struct Reassembler {
    pending: Option<(u8, Vec<u8>)>,
}

/// Une mise à jour complète : (code, données).
pub type Update = (u8, Vec<u8>);

impl Reassembler {
    pub fn feed(&mut self, frame: &[u8]) -> Result<Vec<Update>, Error> {
        let mut r = Reader::new(frame);
        let header = r.u8("fast-path")?;
        if header & 0xC0 != 0 {
            return Err(Error::Invalid("fast-path chiffré : sécurité RDP standard non supportée"));
        }
        let l1 = r.u8("fast-path")?;
        if l1 & 0x80 != 0 {
            r.skip(1, "fast-path")?;
        }
        let mut out = Vec::new();
        while r.remaining() > 0 {
            let h = r.u8("mise à jour")?;
            let code = h & 0x0F;
            let frag = (h >> 4) & 0x03;
            if h >> 6 & 0x02 != 0 {
                return Err(Error::Invalid("mise à jour compressée non négociée"));
            }
            let size = r.u16_le("mise à jour")? as usize;
            let data = r.bytes(size, "mise à jour")?;
            match frag {
                0 => out.push((code, data.to_vec())),
                // Un FIRST avant le LAST du précédent perdrait la mise à jour en cours.
                2 if self.pending.is_some() => {
                    return Err(Error::Invalid("fragment fast-path FIRST en double"));
                }
                2 => self.pending = Some((code, data.to_vec())),
                3 | 1 => {
                    let (c, buf) =
                        self.pending.as_mut().ok_or(Error::Invalid("fragment fast-path orphelin"))?;
                    if *c != code {
                        return Err(Error::Invalid("fragments fast-path mélangés"));
                    }
                    if buf.len() + data.len() > crate::slowpath::MAX_REQUEST_SIZE as usize {
                        return Err(Error::Invalid("mise à jour fast-path trop grande"));
                    }
                    buf.extend_from_slice(data);
                    if frag == 1 {
                        let (c, buf) = self.pending.take().unwrap();
                        out.push((c, buf));
                    }
                }
                _ => unreachable!(),
            }
        }
        Ok(out)
    }
}

/// Curseur décodé : pixels RGBA (stride = largeur × 4), point chaud.
#[derive(Debug, Clone, PartialEq)]
pub struct Pointer {
    pub width: u16,
    pub height: u16,
    pub hot_x: u16,
    pub hot_y: u16,
    pub rgba: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PointerUpdate {
    Hidden,
    Default,
    Position {
        x: u16,
        y: u16,
    },
    /// Nouveau curseur, à mémoriser dans l'emplacement `cache_index`. Vide (0×0) si sa forme n'est pas
    /// décodable : l'appelant montre alors le curseur par défaut, et le garde pour cet emplacement.
    New {
        cache_index: u16,
        pointer: Pointer,
    },
    Cached {
        cache_index: u16,
    },
}

fn row_stride(width: usize, bpp: usize) -> usize {
    // Les lignes des masques sont alignées sur 2 octets.
    (width * bpp).div_ceil(8).div_ceil(2) * 2
}

/// Décode les masques XOR/AND (lignes de bas en haut) en RGBA.
fn decode_masks(width: usize, height: usize, bpp: usize, xor: &[u8], and: &[u8]) -> Result<Vec<u8>, Error> {
    let xs = row_stride(width, bpp);
    let as_ = row_stride(width, 1);
    if xor.len() < xs * height || (!and.is_empty() && and.len() < as_ * height) {
        return Err(Error::Truncated("masque de curseur"));
    }
    let mut rgba = alloc::vec![0u8; width * height * 4];
    let mut any_alpha = false;
    for y in 0..height {
        let src_row = height - 1 - y;
        let xr = &xor[src_row * xs..];
        for x in 0..width {
            let and_bit = if and.is_empty() { 0 } else { (and[src_row * as_ + x / 8] >> (7 - x % 8)) & 1 };
            let (r, g, b, a) = match bpp {
                32 => {
                    let p = &xr[x * 4..x * 4 + 4];
                    any_alpha |= p[3] != 0;
                    (p[2], p[1], p[0], p[3])
                }
                24 => {
                    let p = &xr[x * 3..x * 3 + 3];
                    (p[2], p[1], p[0], 0xFF)
                }
                16 => {
                    let v = u16::from_le_bytes([xr[x * 2], xr[x * 2 + 1]]);
                    let (r5, g6, b5) = ((v >> 11) & 0x1F, (v >> 5) & 0x3F, v & 0x1F);
                    (
                        ((r5 << 3) | (r5 >> 2)) as u8,
                        ((g6 << 2) | (g6 >> 4)) as u8,
                        ((b5 << 3) | (b5 >> 2)) as u8,
                        0xFF,
                    )
                }
                1 => {
                    let bit = (xr[x / 8] >> (7 - x % 8)) & 1;
                    let v = if bit == 1 { 0xFF } else { 0 };
                    (v, v, v, 0xFF)
                }
                _ => return Err(Error::Invalid("profondeur de curseur non gérée")),
            };
            // AND = 1 : pixel transparent (XOR noir) ou inversé (approximé en noir opaque).
            let a = if bpp == 32 {
                a
            } else if and_bit == 1 {
                if r | g | b == 0 { 0 } else { 0xFF }
            } else {
                a
            };
            let (r, g, b) = if bpp != 32 && and_bit == 1 && a == 0xFF { (0, 0, 0) } else { (r, g, b) };
            let o = (y * width + x) * 4;
            rgba[o..o + 4].copy_from_slice(&[r, g, b, a]);
        }
    }
    // 32 bpp sans aucun alpha : le masque AND fait foi.
    if bpp == 32 && !any_alpha {
        for y in 0..height {
            let src_row = height - 1 - y;
            for x in 0..width {
                let and_bit =
                    if and.is_empty() { 0 } else { (and[src_row * as_ + x / 8] >> (7 - x % 8)) & 1 };
                rgba[(y * width + x) * 4 + 3] = if and_bit == 1 { 0 } else { 0xFF };
            }
        }
    }
    Ok(rgba)
}

fn color_pointer(r: &mut Reader, bpp: usize, large: bool) -> Result<Option<PointerUpdate>, Error> {
    let cache_index = r.u16_le("curseur")?;
    let hot_x = r.u16_le("curseur")?;
    let hot_y = r.u16_le("curseur")?;
    let width = r.u16_le("curseur")?;
    let height = r.u16_le("curseur")?;
    if width > 384 || height > 384 {
        return Err(Error::Invalid("curseur trop grand"));
    }
    let (and_len, xor_len) = if large {
        (r.u32_le("curseur")? as usize, r.u32_le("curseur")? as usize)
    } else {
        (r.u16_le("curseur")? as usize, r.u16_le("curseur")? as usize)
    };
    let xor = r.bytes(xor_len, "masque XOR")?;
    let and = r.bytes(and_len, "masque AND")?;
    if matches!(bpp, 4 | 8) {
        // Indices dans la palette de la session (2.2.9.1.1.4.4), que Portique ne suit pas. L'emplacement
        // reçoit quand même un curseur, vide : un CACHED ultérieur ne doit pas ressortir l'image d'avant.
        let pointer = Pointer { width: 0, height: 0, hot_x, hot_y, rgba: Vec::new() };
        return Ok(Some(PointerUpdate::New { cache_index, pointer }));
    }
    let rgba = decode_masks(width as usize, height as usize, bpp, xor, and)?;
    Ok(Some(PointerUpdate::New { cache_index, pointer: Pointer { width, height, hot_x, hot_y, rgba } }))
}

/// Décode une mise à jour de curseur fast-path ; `None` si `code` n'en est pas une.
pub fn pointer_update(code: u8, data: &[u8]) -> Result<Option<PointerUpdate>, Error> {
    let mut r = Reader::new(data);
    Ok(Some(match code {
        update_code::PTR_NULL => PointerUpdate::Hidden,
        update_code::PTR_DEFAULT => PointerUpdate::Default,
        update_code::PTR_POSITION => {
            PointerUpdate::Position { x: r.u16_le("position")?, y: r.u16_le("position")? }
        }
        update_code::CACHED => PointerUpdate::Cached { cache_index: r.u16_le("curseur en cache")? },
        update_code::COLOR => return color_pointer(&mut r, 24, false),
        update_code::POINTER | update_code::LARGE_POINTER => {
            let bpp = r.u16_le("curseur")? as usize;
            return color_pointer(&mut r, bpp, code == update_code::LARGE_POINTER);
        }
        _ => return Ok(None),
    }))
}

// --- Entrées client (2.2.8.1.2.2) ---

pub mod kbd {
    pub const RELEASE: u8 = 0x01;
    pub const EXTENDED: u8 = 0x02;
    pub const EXTENDED1: u8 = 0x04;
}

pub mod ptr {
    pub const HWHEEL: u16 = 0x0400;
    pub const WHEEL: u16 = 0x0200;
    pub const WHEEL_NEGATIVE: u16 = 0x0100;
    pub const MOVE: u16 = 0x0800;
    pub const DOWN: u16 = 0x8000;
    pub const BUTTON1: u16 = 0x1000;
    pub const BUTTON2: u16 = 0x2000;
    pub const BUTTON3: u16 = 0x4000;
    /// Boutons X1/X2 (souris étendue, PTRXFLAGS).
    pub const X_DOWN: u16 = 0x8000;
    pub const X_BUTTON1: u16 = 0x0001;
    pub const X_BUTTON2: u16 = 0x0002;
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Input {
    /// Code de balayage (scancode) ; `flags` = combinaison de `kbd::*`.
    Scancode {
        code: u8,
        flags: u8,
    },
    Unicode {
        code: u16,
        release: bool,
    },
    Mouse {
        flags: u16,
        x: u16,
        y: u16,
    },
    MouseX {
        flags: u16,
        x: u16,
        y: u16,
    },
    /// État des verrous (bits : 1 Arrêt défil, 2 Verr num, 4 Verr maj, 8 Kana).
    Sync {
        toggles: u8,
    },
}

impl Input {
    /// Molette : `delta` en crans de 120 (positif = vers le haut / la droite).
    pub fn wheel(delta: i16, horizontal: bool, x: u16, y: u16) -> Self {
        let v = delta.clamp(-255, 255);
        let mut flags = if horizontal { ptr::HWHEEL } else { ptr::WHEEL };
        if v < 0 {
            flags |= ptr::WHEEL_NEGATIVE | ((v as u16) & 0xFF);
        } else {
            flags |= v as u16;
        }
        Input::Mouse { flags, x, y }
    }
}

/// Encode une trame d'entrées fast-path (au plus 255 événements) ; rien pour un lot vide
/// (numEvents à 0 dans l'en-tête annoncerait un compteur à suivre, 2.2.8.1.2).
pub fn input_frame(events: &[Input]) -> Vec<u8> {
    if events.is_empty() {
        return Vec::new();
    }
    let mut body = Vec::with_capacity(events.len() * 7 + 1);
    let n = events.len().min(255);
    if n >= 16 {
        body.push(n as u8);
    }
    for e in &events[..n] {
        match *e {
            Input::Scancode { code, flags } => body.extend_from_slice(&[flags & 0x07, code]),
            Input::Unicode { code, release } => {
                body.push((4 << 5) | release as u8);
                body.extend_from_slice(&code.to_le_bytes());
            }
            Input::Mouse { flags, x, y } | Input::MouseX { flags, x, y } => {
                body.push(if matches!(e, Input::Mouse { .. }) { 1 << 5 } else { 2 << 5 });
                body.extend_from_slice(&flags.to_le_bytes());
                body.extend_from_slice(&x.to_le_bytes());
                body.extend_from_slice(&y.to_le_bytes());
            }
            Input::Sync { toggles } => body.push((3 << 5) | (toggles & 0x0F)),
        }
    }
    let header = if n < 16 { (n as u8) << 2 } else { 0 };
    let total = 1 + body.len() + if body.len() + 2 > 0x7F { 2 } else { 1 };
    let mut out = Vec::with_capacity(total);
    out.push(header);
    if total > 0x7F {
        out.extend_from_slice(&(0x8000u16 | total as u16).to_be_bytes());
    } else {
        out.push(total as u8);
    }
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_encoding() {
        let f = input_frame(&[Input::Scancode { code: 0x1E, flags: 0 }]);
        assert_eq!(f, [0x04, 0x04, 0x00, 0x1E]);
        assert_eq!(crate::x224::frame_len(&f), Some(f.len()));
        let many: Vec<Input> = (0..20).map(|_| Input::Mouse { flags: ptr::MOVE, x: 10, y: 20 }).collect();
        let f = input_frame(&many);
        assert_eq!(f[0], 0);
        assert_eq!(crate::x224::frame_len(&f), Some(f.len()));
        assert_eq!(f[3], 20, "numEvents dans le corps au-delà de 15");
        assert!(input_frame(&[]).is_empty());
    }

    #[test]
    fn wheel_flags() {
        assert_eq!(Input::wheel(120, false, 0, 0), Input::Mouse { flags: 0x0278, x: 0, y: 0 });
        assert_eq!(Input::wheel(-120, false, 0, 0), Input::Mouse { flags: 0x0388, x: 0, y: 0 });
    }

    #[test]
    fn reassembly() {
        let mut r = Reassembler::default();
        let frame = |frag: u8, data: &[u8]| {
            let mut f = alloc::vec![0x00, 0x00, 0x10 | (frag << 4) | update_code::BITMAP];
            f[2] = (frag << 4) | update_code::BITMAP;
            f.extend_from_slice(&(data.len() as u16).to_le_bytes());
            f.extend_from_slice(data);
            f[1] = f.len() as u8;
            f
        };
        assert!(r.feed(&frame(2, &[1, 2])).unwrap().is_empty());
        assert!(r.feed(&frame(3, &[3])).unwrap().is_empty());
        assert_eq!(r.feed(&frame(1, &[4])).unwrap(), [(update_code::BITMAP, alloc::vec![1, 2, 3, 4])]);
        assert!(r.feed(&frame(1, &[5])).is_err());
        // FIRST puis FIRST : la première mise à jour serait perdue sans le dire.
        assert!(r.feed(&frame(2, &[1])).unwrap().is_empty());
        assert!(r.feed(&frame(2, &[2])).is_err());
    }

    #[test]
    fn palette_pointer_empties_its_slot_but_is_checked() {
        // Curseur 2×2 à 8 bpp en emplacement 3 : XOR 2 lignes de 2 octets, AND 2 lignes de 2 octets. Palette
        // non suivie, mais l'emplacement est remplacé (vide) : un CACHED(3) ne ressort pas l'image d'avant.
        let mut p = 8u16.to_le_bytes().to_vec();
        p.extend_from_slice(&[3, 0, 0, 0, 0, 0, 2, 0, 2, 0]);
        p.extend_from_slice(&4u16.to_le_bytes());
        p.extend_from_slice(&4u16.to_le_bytes());
        p.extend_from_slice(&[0; 8]);
        let empty = Pointer { width: 0, height: 0, hot_x: 0, hot_y: 0, rgba: Vec::new() };
        assert_eq!(
            pointer_update(update_code::POINTER, &p),
            Ok(Some(PointerUpdate::New { cache_index: 3, pointer: empty }))
        );
        assert_eq!(
            pointer_update(update_code::POINTER, &p[..p.len() - 1]),
            Err(Error::Truncated("masque AND"))
        );
    }

    #[test]
    fn monochrome_pointer() {
        // Curseur 2×2, 1 bpp : ligne du bas blanche opaque, ligne du haut transparente (AND = 1).
        let mut d = Vec::new();
        d.extend_from_slice(&[0, 0, 1, 0, 1, 0, 2, 0, 2, 0]); // index, hotspot, 2×2
        d.extend_from_slice(&4u16.to_le_bytes()); // lengthAndMask
        d.extend_from_slice(&4u16.to_le_bytes()); // lengthXorMask
        d.extend_from_slice(&[0xC0, 0x00, 0x00, 0x00]); // XOR : rangée du bas = 11
        d.extend_from_slice(&[0x00, 0x00, 0xC0, 0x00]); // AND : rangée du haut = 11
        let mut p = 1u16.to_le_bytes().to_vec();
        p.extend_from_slice(&d);
        match pointer_update(update_code::POINTER, &p).unwrap().unwrap() {
            PointerUpdate::New { pointer, .. } => {
                assert_eq!(&pointer.rgba[..4], &[0, 0, 0, 0], "haut transparent");
                assert_eq!(&pointer.rgba[8..12], &[255, 255, 255, 255], "bas blanc");
                assert_eq!((pointer.hot_x, pointer.hot_y), (1, 1));
            }
            other => panic!("{other:?}"),
        }
    }
}
