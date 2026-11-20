//! PDU « slow-path » de la séquence de connexion et de la session (MS-RDPBCGR 2.2.1.11 à
//! 2.2.1.22, 2.2.3, 2.2.5) : Client Info, licence, Demand/Confirm Active, finalisation,
//! PDU de données du serveur.

use alloc::{string::String, vec::Vec};

use crate::{Error, cursor::Reader};

pub const SEC_INFO_PKT: u16 = 0x0040;
pub const SEC_LICENSE_PKT: u16 = 0x0080;

fn utf16z(s: &str) -> Vec<u8> {
    let mut v: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
    v.extend_from_slice(&[0, 0]);
    v
}

pub mod info_flags {
    pub const MOUSE: u32 = 0x0000_0001;
    pub const DISABLECTRLALTDEL: u32 = 0x0000_0002;
    pub const UNICODE: u32 = 0x0000_0010;
    pub const MAXIMIZESHELL: u32 = 0x0000_0020;
    pub const LOGONNOTIFY: u32 = 0x0000_0040;
    pub const ENABLEWINDOWSKEY: u32 = 0x0000_0100;
    pub const LOGONERRORS: u32 = 0x0001_0000;
    pub const NOAUDIOPLAYBACK: u32 = 0x0008_0000;
    pub const VIDEO_DISABLE: u32 = 0x0040_0000;
}

pub mod perf {
    pub const ENABLE_FONT_SMOOTHING: u32 = 0x0000_0080;
    pub const ENABLE_DESKTOP_COMPOSITION: u32 = 0x0000_0100;
}

/// Client Info PDU (2.2.1.11), sécurité de base comprise. Le mot de passe reste vide : avec NLA,
/// le serveur a déjà les identifiants (CredSSP).
pub fn client_info(domain: &str, username: &str, flags: u32, performance_flags: u32) -> Vec<u8> {
    let (dom, user, empty) = (utf16z(domain), utf16z(username), utf16z(""));
    let mut p = Vec::with_capacity(512);
    p.extend_from_slice(&SEC_INFO_PKT.to_le_bytes());
    p.extend_from_slice(&0u16.to_le_bytes());
    p.extend_from_slice(&0u32.to_le_bytes()); // CodePage
    p.extend_from_slice(&flags.to_le_bytes());
    for s in [&dom, &user, &empty, &empty, &empty] {
        p.extend_from_slice(&((s.len() - 2) as u16).to_le_bytes());
    }
    for s in [&dom, &user, &empty, &empty, &empty] {
        p.extend_from_slice(s);
    }
    // Infos étendues (2.2.1.11.1.1.1).
    let addr = utf16z("0.0.0.0");
    let dir = utf16z("C:\\Windows\\System32\\mstscax.dll");
    p.extend_from_slice(&2u16.to_le_bytes()); // AF_INET
    p.extend_from_slice(&(addr.len() as u16).to_le_bytes());
    p.extend_from_slice(&addr);
    p.extend_from_slice(&(dir.len() as u16).to_le_bytes());
    p.extend_from_slice(&dir);
    p.extend_from_slice(&[0; 172]); // clientTimeZone : UTC (redirection de fuseau désactivée)
    p.extend_from_slice(&0u32.to_le_bytes()); // clientSessionId
    p.extend_from_slice(&performance_flags.to_le_bytes());
    p.extend_from_slice(&0u16.to_le_bytes()); // cbAutoReconnectCookie
    p
}

/// Message de licence (2.2.1.12) : `Ok(true)` si le serveur valide le client sans échange.
pub fn license_is_valid_client(payload: &[u8]) -> Result<bool, Error> {
    let mut r = Reader::new(payload);
    let flags = r.u16_le("en-tête de sécurité")?;
    if flags & SEC_LICENSE_PKT == 0 {
        return Err(Error::Invalid("PDU de licence attendue"));
    }
    r.skip(2, "en-tête de sécurité")?;
    let msg_type = r.u8("licence")?;
    r.skip(3, "licence")?;
    if msg_type != 0xFF {
        // Demande de licence réelle (serveur RDS avec CAL) : hors périmètre.
        return Ok(false);
    }
    let error_code = r.u32_le("licence")?;
    let state = r.u32_le("licence")?;
    Ok(error_code == 0x0000_0007 && state == 0x0000_0002) // STATUS_VALID_CLIENT, ST_NO_TRANSITION
}

pub mod pdu_type {
    pub const DEMAND_ACTIVE: u16 = 0x1;
    pub const CONFIRM_ACTIVE: u16 = 0x3;
    pub const DEACTIVATE_ALL: u16 = 0x6;
    pub const DATA: u16 = 0x7;
    pub const SERVER_REDIRECT: u16 = 0xA;
}

pub mod data_type {
    pub const UPDATE: u8 = 0x02;
    pub const CONTROL: u8 = 0x14;
    pub const POINTER: u8 = 0x1B;
    pub const INPUT: u8 = 0x1C;
    pub const SYNCHRONIZE: u8 = 0x1F;
    pub const REFRESH_RECT: u8 = 0x21;
    pub const SUPPRESS_OUTPUT: u8 = 0x23;
    pub const SHUTDOWN_REQUEST: u8 = 0x24;
    pub const SHUTDOWN_DENIED: u8 = 0x25;
    pub const SAVE_SESSION_INFO: u8 = 0x26;
    pub const FONT_LIST: u8 = 0x27;
    pub const FONT_MAP: u8 = 0x28;
    pub const SET_KEYBOARD_INDICATORS: u8 = 0x29;
    pub const SET_ERROR_INFO: u8 = 0x2F;
    pub const MONITOR_LAYOUT: u8 = 0x37;
}

/// En-tête Share Control (2.2.8.1.1.1.1).
#[derive(Debug, PartialEq)]
pub struct ShareControl<'a> {
    pub pdu_type: u16,
    pub source: u16,
    pub body: &'a [u8],
}

pub fn read_share_control(payload: &[u8]) -> Result<ShareControl<'_>, Error> {
    let mut r = Reader::new(payload);
    let total = r.u16_le("Share Control")? as usize;
    // 0x8000 : PDU « flow control » sans en-tête complet, à ignorer.
    if total == 0x8000 {
        return Ok(ShareControl { pdu_type: 0, source: 0, body: &[] });
    }
    let pdu_type = r.u16_le("Share Control")? & 0x0F;
    let source = if r.remaining() >= 2 { r.u16_le("Share Control")? } else { 0 };
    let body_len = total.checked_sub(6).ok_or(Error::Invalid("Share Control trop court"))?;
    Ok(ShareControl { pdu_type, source, body: r.bytes(body_len.min(r.remaining()), "Share Control")? })
}

fn share_control(pdu_type: u16, source: u16, body: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(6 + body.len());
    p.extend_from_slice(&((6 + body.len()) as u16).to_le_bytes());
    p.extend_from_slice(&(pdu_type | 0x10).to_le_bytes());
    p.extend_from_slice(&source.to_le_bytes());
    p.extend_from_slice(body);
    p
}

/// PDU de données client (Share Control + Share Data).
pub fn data_pdu(share_id: u32, source: u16, pdu_type2: u8, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(12 + data.len());
    b.extend_from_slice(&share_id.to_le_bytes());
    b.push(0);
    b.push(1); // STREAM_LOW
    b.extend_from_slice(&((data.len() + 4) as u16).to_le_bytes());
    b.push(pdu_type2);
    b.push(0);
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(data);
    share_control(pdu_type::DATA, source, &b)
}

/// Corps d'une PDU de données serveur : (pduType2, données). Compression refusée par le client.
pub fn read_data_pdu(body: &[u8]) -> Result<(u8, &[u8]), Error> {
    let mut r = Reader::new(body);
    r.skip(4 + 1 + 1 + 2, "Share Data")?;
    let pdu_type2 = r.u8("Share Data")?;
    let compressed = r.u8("Share Data")?;
    r.skip(2, "Share Data")?;
    if compressed & 0x20 != 0 {
        return Err(Error::Invalid("PDU compressée alors que la compression n'est pas négociée"));
    }
    Ok((pdu_type2, r.rest()))
}

#[derive(Debug, Clone, PartialEq)]
pub struct DemandActive {
    pub share_id: u32,
    /// Capacités serveur brutes : (type, données).
    pub capabilities: Vec<(u16, Vec<u8>)>,
}

impl DemandActive {
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(body);
        let share_id = r.u32_le("Demand Active")?;
        let len_source = r.u16_le("Demand Active")? as usize;
        r.skip(2, "Demand Active")?;
        r.skip(len_source, "Demand Active")?;
        let count = r.u16_le("Demand Active")?;
        r.skip(2, "Demand Active")?;
        let mut capabilities = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let kind = r.u16_le("capacité")?;
            let len = r.u16_le("capacité")? as usize;
            let data = r.bytes(len.checked_sub(4).ok_or(Error::Invalid("capacité"))?, "capacité")?;
            capabilities.push((kind, data.to_vec()));
        }
        Ok(Self { share_id, capabilities })
    }

    /// Taille de bureau imposée par le serveur (capacité Bitmap).
    pub fn desktop_size(&self) -> Option<(u16, u16)> {
        let (_, d) = self.capabilities.iter().find(|(k, _)| *k == cap::BITMAP)?;
        let w = u16::from_le_bytes([*d.get(8)?, *d.get(9)?]);
        let h = u16::from_le_bytes([*d.get(10)?, *d.get(11)?]);
        Some((w, h))
    }
}

pub mod cap {
    pub const GENERAL: u16 = 1;
    pub const BITMAP: u16 = 2;
    pub const ORDER: u16 = 3;
    pub const CONTROL: u16 = 5;
    pub const ACTIVATION: u16 = 7;
    pub const POINTER: u16 = 8;
    pub const SHARE: u16 = 9;
    pub const COLOR_CACHE: u16 = 10;
    pub const SOUND: u16 = 12;
    pub const INPUT: u16 = 13;
    pub const FONT: u16 = 14;
    pub const BRUSH: u16 = 15;
    pub const GLYPH_CACHE: u16 = 16;
    pub const OFFSCREEN_CACHE: u16 = 17;
    pub const VIRTUAL_CHANNEL: u16 = 20;
    pub const MULTIFRAGMENT_UPDATE: u16 = 26;
    pub const LARGE_POINTER: u16 = 27;
}

pub mod input_flags {
    pub const SCANCODES: u16 = 0x0001;
    pub const MOUSEX: u16 = 0x0004;
    pub const UNICODE: u16 = 0x0010;
    pub const FASTPATH_INPUT2: u16 = 0x0020;
    pub const MOUSE_HWHEEL: u16 = 0x0100;
}

/// Taille maximale d'une mise à jour réassemblée annoncée au serveur.
pub const MAX_REQUEST_SIZE: u32 = 8 * 1024 * 1024;

pub struct ClientCaps {
    pub width: u16,
    pub height: u16,
    pub keyboard_layout: u32,
}

fn cap_set(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&((body.len() + 4) as u16).to_le_bytes());
    out.extend_from_slice(body);
}

fn le16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn le32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}

/// Confirm Active PDU (2.2.1.13.2). Aucun ordre de dessin ni cache bitmap : l'affichage passe
/// par EGFX, les mises à jour bitmap restent possibles en secours.
pub fn confirm_active(share_id: u32, user: u16, c: &ClientCaps) -> (Vec<u8>, u16) {
    let mut caps = Vec::with_capacity(512);
    let mut n = 0u16;
    let mut add = |kind: u16, body: Vec<u8>| {
        cap_set(&mut caps, kind, &body);
        n += 1;
    };

    let mut g = Vec::new();
    le16(&mut g, 1); // osMajorType : Windows
    le16(&mut g, 3); // osMinorType : NT
    le16(&mut g, 0x0200); // protocolVersion
    le16(&mut g, 0);
    le16(&mut g, 0); // generalCompressionTypes
    // FASTPATH_OUTPUT_SUPPORTED | LONG_CREDENTIALS | AUTORECONNECT | ENC_SALTED_CHECKSUM | NO_BITMAP_COMPRESSION_HDR
    le16(&mut g, 0x0001 | 0x0004 | 0x0008 | 0x0010 | 0x0400);
    le16(&mut g, 0); // updateCapabilityFlag
    le16(&mut g, 0); // remoteUnshareFlag
    le16(&mut g, 0); // generalCompressionLevel
    g.push(1); // refreshRectSupport
    g.push(1); // suppressOutputSupport
    add(cap::GENERAL, g);

    let mut b = Vec::new();
    le16(&mut b, 32);
    le16(&mut b, 1);
    le16(&mut b, 1);
    le16(&mut b, 1);
    le16(&mut b, c.width);
    le16(&mut b, c.height);
    le16(&mut b, 0);
    le16(&mut b, 1); // desktopResizeFlag
    le16(&mut b, 1); // bitmapCompressionFlag
    b.push(0); // highColorFlags
    b.push(0x08 | 0x02); // drawingFlags : skip alpha, fidélité dynamique
    le16(&mut b, 1); // multipleRectangleSupport
    le16(&mut b, 0);
    add(cap::BITMAP, b);

    let mut o = Vec::new();
    o.extend_from_slice(&[0; 16]); // terminalDescriptor
    le32(&mut o, 0);
    le16(&mut o, 1);
    le16(&mut o, 20);
    le16(&mut o, 0);
    le16(&mut o, 1); // maximumOrderLevel
    le16(&mut o, 0); // numberFonts
    le16(&mut o, 0x0002 | 0x0008); // NEGOTIATEORDERSUPPORT | ZEROBOUNDSDELTASSUPPORT
    o.extend_from_slice(&[0; 32]); // orderSupport : aucun ordre
    le16(&mut o, 0);
    le16(&mut o, 0);
    le32(&mut o, 0);
    le32(&mut o, 0);
    le16(&mut o, 0);
    le16(&mut o, 0);
    le16(&mut o, 0);
    le16(&mut o, 0);
    add(cap::ORDER, o);

    let mut p = Vec::new();
    le16(&mut p, 1); // colorPointerFlag
    le16(&mut p, 25);
    le16(&mut p, 25);
    add(cap::POINTER, p);

    let mut i = Vec::new();
    le16(
        &mut i,
        input_flags::SCANCODES
            | input_flags::MOUSEX
            | input_flags::UNICODE
            | input_flags::FASTPATH_INPUT2
            | input_flags::MOUSE_HWHEEL,
    );
    le16(&mut i, 0);
    le32(&mut i, c.keyboard_layout);
    le32(&mut i, 4);
    le32(&mut i, 0);
    le32(&mut i, 12);
    i.extend_from_slice(&[0; 64]);
    add(cap::INPUT, i);

    add(cap::BRUSH, alloc::vec![0, 0, 0, 0]);
    let mut gl = Vec::new();
    for _ in 0..10 {
        le16(&mut gl, 0);
        le16(&mut gl, 0);
    }
    le32(&mut gl, 0);
    le16(&mut gl, 0); // GLYPH_SUPPORT_NONE
    le16(&mut gl, 0);
    add(cap::GLYPH_CACHE, gl);
    add(cap::OFFSCREEN_CACHE, alloc::vec![0; 8]);
    let mut vc = Vec::new();
    le32(&mut vc, 0);
    le32(&mut vc, 1600);
    add(cap::VIRTUAL_CHANNEL, vc);
    add(cap::SOUND, alloc::vec![0, 0, 0, 0]);
    add(cap::MULTIFRAGMENT_UPDATE, MAX_REQUEST_SIZE.to_le_bytes().to_vec());
    add(cap::LARGE_POINTER, alloc::vec![0x03, 0x00]); // 96×96 et 384×384
    add(cap::CONTROL, alloc::vec![0, 0, 0, 0, 2, 0, 2, 0]);
    add(cap::ACTIVATION, alloc::vec![0; 8]);
    add(cap::SHARE, alloc::vec![0; 4]);
    add(cap::FONT, alloc::vec![1, 0, 0, 0]);
    add(cap::COLOR_CACHE, alloc::vec![6, 0, 0, 0]);

    let source = b"MSTSC\0";
    let mut body = Vec::with_capacity(caps.len() + 16);
    le32(&mut body, share_id);
    le16(&mut body, 0x03EA); // originatorId
    le16(&mut body, source.len() as u16);
    le16(&mut body, (caps.len() + 4) as u16);
    body.extend_from_slice(source);
    le16(&mut body, n);
    le16(&mut body, 0);
    body.extend_from_slice(&caps);
    (share_control(pdu_type::CONFIRM_ACTIVE, user, &body), n)
}

/// Les quatre PDU de finalisation client (2.2.1.14 à 2.2.1.18).
pub fn finalization(share_id: u32, user: u16) -> [Vec<u8>; 4] {
    let sync = [1u8, 0, 0xEA, 0x03]; // SYNCMSGTYPE_SYNC, targetUser = 1002
    let cooperate = [4u8, 0, 0, 0, 0, 0, 0, 0];
    let request = [1u8, 0, 0, 0, 0, 0, 0, 0];
    let fonts = [0u8, 0, 0, 0, 3, 0, 50, 0];
    [
        data_pdu(share_id, user, data_type::SYNCHRONIZE, &sync),
        data_pdu(share_id, user, data_type::CONTROL, &cooperate),
        data_pdu(share_id, user, data_type::CONTROL, &request),
        data_pdu(share_id, user, data_type::FONT_LIST, &fonts),
    ]
}

/// Refresh Rect (2.2.11.2) : redemande tout l'écran (après une reconnexion du rendu).
pub fn refresh_rect(share_id: u32, user: u16, width: u16, height: u16) -> Vec<u8> {
    let mut d = alloc::vec![1, 0, 0, 0];
    for v in [0u16, 0, width.saturating_sub(1), height.saturating_sub(1)] {
        le16(&mut d, v);
    }
    data_pdu(share_id, user, data_type::REFRESH_RECT, &d)
}

/// Shutdown Request (2.2.2.2) : déconnexion propre demandée par le client.
pub fn shutdown_request(share_id: u32, user: u16) -> Vec<u8> {
    data_pdu(share_id, user, data_type::SHUTDOWN_REQUEST, &[])
}

/// Texte d'un code Set Error Info (2.2.5.1.1) ; `None` pour 0 (pas d'erreur).
pub fn error_info_text(code: u32) -> Option<String> {
    let t = match code {
        0x0000_0000 => return None,
        0x0000_0001 => "session fermée par un administrateur",
        0x0000_0002 => "session déconnectée par un administrateur",
        0x0000_0003 => "session fermée après inactivité",
        0x0000_0004 => "durée maximale de session atteinte",
        0x0000_0005 => "un autre utilisateur a pris la session",
        0x0000_0006 => "mémoire insuffisante sur le serveur",
        0x0000_0007 => "accès refusé par le serveur",
        0x0000_0009 => "accès refusé (droits)",
        0x0000_000B => "session déconnectée par l'utilisateur sur le serveur",
        0x0000_000C => "session fermée par l'utilisateur sur le serveur",
        0x0000_0011 => "le délai de connexion a expiré",
        0x0000_0100..=0x0000_010F => "erreur de licence",
        _ => return Some(alloc::format!("erreur serveur 0x{code:08X}")),
    };
    Some(String::from(t))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synchronize_matches_spec() {
        // MS-RDPBCGR 4.1.14 : Client Synchronize PDU (sans en-têtes MCS/X.224).
        let pdu = data_pdu(0x0001_03ea, 0x03ef, data_type::SYNCHRONIZE, &[1, 0, 0xea, 0x03]);
        assert_eq!(
            pdu,
            [
                0x16, 0x00, 0x17, 0x00, 0xef, 0x03, 0xea, 0x03, 0x01, 0x00, 0x00, 0x01, 0x08, 0x00, 0x1f,
                0x00, 0x00, 0x00, 0x01, 0x00, 0xea, 0x03
            ]
        );
        let sc = read_share_control(&pdu).unwrap();
        assert_eq!((sc.pdu_type, sc.source), (pdu_type::DATA, 0x03ef));
        assert_eq!(read_data_pdu(sc.body).unwrap(), (data_type::SYNCHRONIZE, &[1u8, 0, 0xea, 0x03][..]));
    }

    #[test]
    fn license_valid_client() {
        // 4.1.12 : Server License Error PDU - Valid Client.
        let pdu = [
            0x80, 0x00, 0x00, 0x00, 0xff, 0x03, 0x10, 0x00, 0x07, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x04, 0x00, 0x00, 0x00,
        ];
        assert!(license_is_valid_client(&pdu).unwrap());
    }

    #[test]
    fn confirm_active_roundtrip() {
        let caps = ClientCaps { width: 1920, height: 1080, keyboard_layout: 0x040C };
        let (pdu, n) = confirm_active(0x0001_03ea, 1007, &caps);
        let sc = read_share_control(&pdu).unwrap();
        assert_eq!(sc.pdu_type, pdu_type::CONFIRM_ACTIVE);
        // Même structure que Demand Active, à l'originatorId près : réutilise l'analyseur.
        let mut demand_like = sc.body[..4].to_vec();
        demand_like.extend_from_slice(&6u16.to_le_bytes());
        demand_like.extend_from_slice(&sc.body[8..]);
        let parsed = DemandActive::parse(&demand_like).unwrap();
        assert_eq!(parsed.capabilities.len(), n as usize);
        assert_eq!(parsed.desktop_size(), Some((1920, 1080)));
    }

    #[test]
    fn client_info_lengths() {
        let p = client_info("", "alice", info_flags::UNICODE, 0);
        assert_eq!(u16::from_le_bytes([p[0], p[1]]), SEC_INFO_PKT);
        assert_eq!(u16::from_le_bytes([p[14], p[15]]), 10, "cbUserName (UTF-16) sans le zéro final");
    }
}
