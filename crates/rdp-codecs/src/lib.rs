//! Décodeurs d'image et de compression utilisés par le pipeline graphique (EGFX).
//!
//! Les décodeurs d'image écrivent des pixels RGBA 8 bits par canal, ligne après ligne,
//! `stride = largeur * 4` (l'ordre attendu par `ImageData` côté navigateur) ; Planar et NSCodec
//! passent par des plans temporaires. ZGFX ajoute les octets décompressés à un `Vec`. Aucune I/O.

#![no_std]
extern crate alloc;

pub mod clearcodec;
pub mod nscodec;
pub mod planar;
pub mod progressive;
pub mod rfx;
pub mod zgfx;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Truncated(&'static str),
    Invalid(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Truncated(w) => write!(f, "{w} tronqué"),
            Error::Invalid(w) => f.write_str(w),
        }
    }
}

impl core::error::Error for Error {}
