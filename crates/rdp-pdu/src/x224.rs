//! TPKT (RFC 1006) et X.224 (ISO 8073 classe 0) tels qu'utilisés par RDP
//! (MS-RDPBCGR 2.2.1.1, 2.2.1.2).

use alloc::{string::String, vec::Vec};

use crate::{Error, cursor::Reader};

pub const TPKT_HEADER: usize = 4;
/// En-tête X.224 Data : LI=2, code DT, EOT.
pub const X224_DATA_HEADER: [u8; 3] = [0x02, 0xF0, 0x80];

/// Longueur de la prochaine trame dans le flux (TPKT ou fast-path), si l'en-tête est là.
pub fn frame_len(buf: &[u8]) -> Option<usize> {
    let first = *buf.first()?;
    if first == 0x03 {
        let b = buf.get(2..4)?;
        return Some(u16::from_be_bytes([b[0], b[1]]) as usize);
    }
    // Fast-path (2.2.9.1.2) : longueur sur 1 ou 2 octets, bit 0x80 = forme longue.
    let l1 = *buf.get(1)?;
    if l1 & 0x80 == 0 {
        Some(l1 as usize)
    } else {
        Some((((l1 & 0x7F) as usize) << 8) | *buf.get(2)? as usize)
    }
}

pub fn tpkt(payload: &[u8]) -> Vec<u8> {
    let len = (TPKT_HEADER + payload.len()) as u16;
    let mut out = Vec::with_capacity(len as usize);
    out.extend_from_slice(&[0x03, 0x00]);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Trame TPKT + X.224 Data autour d'une PDU MCS.
pub fn data(mcs: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(3 + mcs.len());
    p.extend_from_slice(&X224_DATA_HEADER);
    p.extend_from_slice(mcs);
    tpkt(&p)
}

/// Contenu d'une trame TPKT + X.224 Data.
pub fn read_data(frame: &[u8]) -> Result<&[u8], Error> {
    let mut r = Reader::new(frame);
    if r.u8("TPKT")? != 0x03 {
        return Err(Error::Invalid("trame TPKT attendue"));
    }
    r.skip(3, "TPKT")?;
    if r.bytes(3, "X.224")? != X224_DATA_HEADER {
        return Err(Error::Invalid("X.224 Data attendu"));
    }
    Ok(r.rest())
}

pub mod protocol {
    pub const RDP: u32 = 0x0;
    pub const SSL: u32 = 0x1;
    pub const HYBRID: u32 = 0x2;
    pub const RDSTLS: u32 = 0x4;
    pub const HYBRID_EX: u32 = 0x8;
}

pub fn protocol_name(p: u32) -> &'static str {
    match p {
        protocol::RDP => "RDP standard (sans TLS)",
        protocol::SSL => "TLS",
        protocol::HYBRID => "CredSSP (NLA)",
        protocol::RDSTLS => "RDSTLS",
        protocol::HYBRID_EX => "CredSSP étendu (NLA + Early User Authorization)",
        _ => "inconnu",
    }
}

/// Connection Request (2.2.1.1) avec RDP_NEG_REQ.
pub fn connection_request(cookie_user: Option<&str>, requested: u32) -> Vec<u8> {
    let mut body = Vec::new();
    if let Some(user) = cookie_user {
        // Le cookie mstshash est tronqué à 9 caractères par mstsc ; on garde l'ASCII.
        let user: String = user.chars().filter(char::is_ascii_graphic).take(9).collect();
        body.extend_from_slice(b"Cookie: mstshash=");
        body.extend_from_slice(user.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&8u16.to_le_bytes());
    body.extend_from_slice(&requested.to_le_bytes());

    let mut x224 = Vec::with_capacity(7 + body.len());
    x224.push((6 + body.len()) as u8);
    x224.extend_from_slice(&[0xE0, 0, 0, 0, 0, 0]);
    x224.extend_from_slice(&body);
    tpkt(&x224)
}

pub mod neg_flags {
    pub const EXTENDED_CLIENT_DATA_SUPPORTED: u8 = 0x01;
    pub const DYNVC_GFX_PROTOCOL_SUPPORTED: u8 = 0x02;
    pub const RESTRICTED_ADMIN_MODE_SUPPORTED: u8 = 0x08;
    pub const REDIRECTED_AUTHENTICATION_MODE_SUPPORTED: u8 = 0x10;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionConfirm {
    pub selected_protocol: u32,
    pub flags: u8,
}

/// Connection Confirm (2.2.1.2) : protocole retenu, ou refus explicite.
pub fn connection_confirm(frame: &[u8]) -> Result<ConnectionConfirm, Error> {
    let mut r = Reader::new(frame);
    if r.u8("TPKT")? != 0x03 {
        return Err(Error::Invalid("trame TPKT attendue"));
    }
    r.skip(3, "TPKT")?;
    let _li = r.u8("X.224")?;
    if r.u8("X.224")? & 0xF0 != 0xD0 {
        return Err(Error::Invalid("X.224 Connection Confirm attendu"));
    }
    r.skip(5, "X.224")?;
    if r.remaining() < 8 {
        // Pas de RDP_NEG_RSP : vieux serveur, sécurité RDP standard.
        return Ok(ConnectionConfirm { selected_protocol: protocol::RDP, flags: 0 });
    }
    let kind = r.u8("RDP_NEG")?;
    let flags = r.u8("RDP_NEG")?;
    r.skip(2, "RDP_NEG")?;
    let value = r.u32_le("RDP_NEG")?;
    match kind {
        0x02 => Ok(ConnectionConfirm { selected_protocol: value, flags }),
        0x03 => Err(Error::NegotiationFailure(value)),
        _ => Err(Error::Invalid("RDP_NEG inconnu")),
    }
}

pub fn negotiation_failure_text(code: u32) -> &'static str {
    match code {
        0x1 => "le serveur exige TLS",
        0x2 => "le serveur n'accepte pas TLS (certificat absent ?)",
        0x3 => "le serveur n'a pas de certificat utilisable",
        0x4 => "chiffrement RDP standard refusé",
        0x5 => "le serveur exige NLA (CredSSP)",
        0x6 => "le serveur exige TLS avec certificat",
        _ => "refus de négociation inconnu",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_bytes() {
        // MS-RDPBCGR 4.1.1 : même structure, cookie « eltons ».
        let req = connection_request(Some("eltons"), protocol::RDP);
        let expected = [
            0x03, 0x00, 0x00, 0x2c, 0x27, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43, 0x6f, 0x6f, 0x6b, 0x69,
            0x65, 0x3a, 0x20, 0x6d, 0x73, 0x74, 0x73, 0x68, 0x61, 0x73, 0x68, 0x3d, 0x65, 0x6c, 0x74, 0x6f,
            0x6e, 0x73, 0x0d, 0x0a, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(req, expected);
        assert_eq!(frame_len(&req), Some(req.len()));
    }

    #[test]
    fn confirm_parsing() {
        // 4.1.2 : réponse sélectionnant RDP standard.
        let rsp = [
            0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00,
            0x00, 0x00, 0x00,
        ];
        assert_eq!(connection_confirm(&rsp).unwrap(), ConnectionConfirm { selected_protocol: 0, flags: 0 });
        let mut hybrid = rsp;
        hybrid[12] = 0x1f;
        hybrid[15] = protocol::HYBRID as u8;
        let c = connection_confirm(&hybrid).unwrap();
        assert_eq!((c.selected_protocol, c.flags), (protocol::HYBRID, 0x1f));
        let mut fail = rsp;
        fail[11] = 0x03;
        fail[15] = 0x05;
        assert_eq!(connection_confirm(&fail), Err(Error::NegotiationFailure(5)));
    }

    #[test]
    fn fastpath_length() {
        assert_eq!(frame_len(&[0x00, 0x10]), Some(0x10));
        assert_eq!(frame_len(&[0x00, 0x81, 0x2c]), Some(0x12c));
        assert_eq!(frame_len(&[0x00]), None);
    }
}
