//! Encodage et décodage des PDU RDP (MS-RDPBCGR), sans I/O : chaque fonction prend ou rend
//! des octets, le transport est l'affaire de l'appelant.

#![no_std]
extern crate alloc;

pub mod cursor;
pub mod gcc;
pub mod mcs;
pub mod x224;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Truncated(&'static str),
    Invalid(&'static str),
    /// RDP_NEG_FAILURE : code de refus (voir `x224::negotiation_failure_text`).
    NegotiationFailure(u32),
    /// Connect Response MCS avec un résultat non nul.
    McsRefused(u8),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Truncated(what) => write!(f, "{what} tronqué"),
            Error::Invalid(what) => f.write_str(what),
            Error::NegotiationFailure(code) => {
                write!(f, "négociation refusée : {} (0x{code:x})", x224::negotiation_failure_text(*code))
            }
            Error::McsRefused(code) => write!(f, "connexion MCS refusée (résultat {code})"),
        }
    }
}

impl core::error::Error for Error {}
