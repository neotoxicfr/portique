//! Authentification NLA pour la pile RDP de portique : NTLMv2 et CredSSP, sans I/O.
//!
//! Référence : MS-NLMP et MS-CSSP. Toute la cryptographie vient de RustCrypto.

#![no_std]
extern crate alloc;

use alloc::vec::Vec;

pub mod credssp;
pub mod der;
pub mod ntlm;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Truncated(&'static str),
    Invalid(&'static str),
    /// Code NTSTATUS renvoyé par le serveur (ex. 0xC000006D = identifiants refusés).
    Server(u32),
    /// Authentification réussie mais l'utilisateur n'a pas le droit d'ouvrir de session RDP.
    AccessDenied,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Truncated(what) => write!(f, "{what} tronqué"),
            Error::Invalid(what) => f.write_str(what),
            Error::Server(code) => match ntstatus_text(*code) {
                Some(t) => write!(f, "{t} (0x{code:08X})"),
                None => write!(f, "refus du serveur, code 0x{code:08X}"),
            },
            Error::AccessDenied => f.write_str("accès RDP refusé à ce compte"),
        }
    }
}

impl core::error::Error for Error {}

/// Codes NTSTATUS les plus fréquents lors d'une connexion NLA.
pub fn ntstatus_text(code: u32) -> Option<&'static str> {
    Some(match code {
        0xC000_006D => "identifiant ou mot de passe incorrect",
        0xC000_006E => "restriction de compte",
        0xC000_0064 => "compte inconnu",
        0xC000_006A => "mot de passe incorrect",
        0xC000_0071 => "mot de passe expiré",
        0xC000_0072 => "compte désactivé",
        0xC000_0193 => "compte expiré",
        0xC000_0224 => "le mot de passe doit être changé",
        0xC000_0234 => "compte verrouillé",
        0xC000_015B => "type d'ouverture de session refusé",
        _ => return None,
    })
}

pub(crate) fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}
