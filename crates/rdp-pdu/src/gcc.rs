//! Blocs de données GCC échangés pendant la connexion (MS-RDPBCGR 2.2.1.3, 2.2.1.4).

use alloc::{string::String, vec::Vec};

use crate::{Error, cursor::Reader};

pub mod early_caps {
    pub const SUPPORT_ERRINFO_PDU: u16 = 0x0001;
    pub const WANT_32BPP_SESSION: u16 = 0x0002;
    pub const SUPPORT_STATUSINFO_PDU: u16 = 0x0004;
    pub const STRONG_ASYMMETRIC_KEYS: u16 = 0x0008;
    pub const VALID_CONNECTION_TYPE: u16 = 0x0020;
    pub const SUPPORT_MONITOR_LAYOUT_PDU: u16 = 0x0040;
    pub const SUPPORT_NETCHAR_AUTODETECT: u16 = 0x0080;
    pub const SUPPORT_DYNVC_GFX_PROTOCOL: u16 = 0x0100;
    pub const SUPPORT_DYNAMIC_TIME_ZONE: u16 = 0x0200;
    pub const SUPPORT_HEARTBEAT_PDU: u16 = 0x0400;
    pub const SUPPORT_SKIP_CHANNELJOIN: u16 = 0x0800;
}

pub mod channel_opts {
    pub const INITIALIZED: u32 = 0x8000_0000;
    pub const ENCRYPT_RDP: u32 = 0x4000_0000;
    pub const COMPRESS_RDP: u32 = 0x0080_0000;
    pub const SHOW_PROTOCOL: u32 = 0x0020_0000;
}

/// RDP 10.7 : niveau qui débloque l'EGFX moderne côté Windows.
pub const RDP_VERSION_10_7: u32 = 0x0008_000C;

#[derive(Debug, Clone)]
pub struct ClientCore {
    pub version: u32,
    pub width: u16,
    pub height: u16,
    pub keyboard_layout: u32,
    pub client_build: u32,
    pub client_name: String,
    pub early_capability_flags: u16,
    pub selected_protocol: u32,
}

#[derive(Debug, Clone)]
pub struct Channel {
    pub name: &'static str,
    pub options: u32,
}

#[derive(Debug, Clone)]
pub struct ClientData {
    pub core: ClientCore,
    pub channels: Vec<Channel>,
}

fn header(out: &mut Vec<u8>, kind: u16, body_len: usize) {
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&((body_len + 4) as u16).to_le_bytes());
}

/// Chaîne UTF-16LE dans un champ fixe, terminateur compris ; tronquée caractère par caractère
/// pour ne jamais couper une paire de substitution.
fn fixed_utf16(s: &str, bytes: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(bytes);
    for c in s.chars() {
        let mut units = [0u16; 2];
        let units = c.encode_utf16(&mut units);
        if v.len() + units.len() * 2 > bytes - 2 {
            break;
        }
        v.extend(units.iter().flat_map(|u| u.to_le_bytes()));
    }
    v.resize(bytes, 0);
    v
}

impl ClientData {
    pub fn encode(&self) -> Vec<u8> {
        let c = &self.core;
        let mut core = Vec::with_capacity(216);
        core.extend_from_slice(&c.version.to_le_bytes());
        core.extend_from_slice(&c.width.to_le_bytes());
        core.extend_from_slice(&c.height.to_le_bytes());
        core.extend_from_slice(&0xCA01u16.to_le_bytes()); // colorDepth : RNS_UD_COLOR_8BPP (ignoré)
        core.extend_from_slice(&0xAA03u16.to_le_bytes()); // SASSequence
        core.extend_from_slice(&c.keyboard_layout.to_le_bytes());
        core.extend_from_slice(&c.client_build.to_le_bytes());
        core.extend_from_slice(&fixed_utf16(&c.client_name, 32));
        core.extend_from_slice(&4u32.to_le_bytes()); // keyboardType : IBM 101/102 touches
        core.extend_from_slice(&0u32.to_le_bytes()); // keyboardSubType
        core.extend_from_slice(&12u32.to_le_bytes()); // keyboardFunctionKey
        core.extend_from_slice(&[0; 64]); // imeFileName
        core.extend_from_slice(&0xCA01u16.to_le_bytes()); // postBeta2ColorDepth
        core.extend_from_slice(&1u16.to_le_bytes()); // clientProductId
        core.extend_from_slice(&0u32.to_le_bytes()); // serialNumber
        // highColorDepth : 32 n'y existe pas ; 24 en repli, le 32 bpp se demande par
        // RNS_UD_CS_WANT_32BPP_SESSION dans earlyCapabilityFlags (2.2.1.3.2).
        core.extend_from_slice(&24u16.to_le_bytes());
        core.extend_from_slice(&0x000Fu16.to_le_bytes()); // supportedColorDepths : 24/16/15/32
        core.extend_from_slice(&c.early_capability_flags.to_le_bytes());
        core.extend_from_slice(&[0; 64]); // clientDigProductId
        core.push(6); // connectionType : LAN (pas de détection réseau à mener)
        core.push(0); // pad1octet
        core.extend_from_slice(&c.selected_protocol.to_le_bytes());

        let mut out = Vec::with_capacity(core.len() + 64);
        header(&mut out, 0xC001, core.len());
        out.extend_from_slice(&core);

        // CS_SECURITY : aucun chiffrement RDP standard, TLS s'en charge.
        header(&mut out, 0xC002, 8);
        out.extend_from_slice(&[0; 8]);

        // 31 canaux statiques au plus (2.2.1.3.4) ; la liste vient du code, pas du réseau.
        assert!(self.channels.len() <= 31, "plus de 31 canaux statiques");
        let mut net = Vec::new();
        net.extend_from_slice(&(self.channels.len() as u32).to_le_bytes());
        for ch in &self.channels {
            let mut name = [0u8; 8];
            name[..ch.name.len().min(7)].copy_from_slice(&ch.name.as_bytes()[..ch.name.len().min(7)]);
            net.extend_from_slice(&name);
            net.extend_from_slice(&ch.options.to_le_bytes());
        }
        header(&mut out, 0xC003, net.len());
        out.extend_from_slice(&net);

        // CS_CLUSTER : redirection de session supportée, version 4.
        header(&mut out, 0xC004, 8);
        out.extend_from_slice(&0x0000_000Du32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ServerData {
    pub version: u32,
    pub client_requested_protocols: Option<u32>,
    pub early_capability_flags: Option<u32>,
    pub encryption_method: u32,
    pub encryption_level: u32,
    pub io_channel: u16,
    pub channel_ids: Vec<u16>,
    pub message_channel: Option<u16>,
    pub multitransport_flags: Option<u32>,
}

pub mod server_early_caps {
    pub const EDGE_ACTIONS_SUPPORTED_V1: u32 = 0x0000_0001;
    pub const DYNAMIC_DST_SUPPORTED: u32 = 0x0000_0002;
    pub const EDGE_ACTIONS_SUPPORTED_V2: u32 = 0x0000_0004;
    pub const SKIP_CHANNELJOIN_SUPPORTED: u32 = 0x0000_0008;
}

impl ServerData {
    pub fn parse(mut buf: &[u8]) -> Result<Self, Error> {
        let mut d = ServerData::default();
        // SC_CORE, SC_SECURITY et SC_NET sont obligatoires (2.2.1.4) : leur absence ne se
        // déduit pas de valeurs nulles.
        let (mut core, mut security, mut net) = (false, false, false);
        while buf.len() >= 4 {
            let kind = u16::from_le_bytes([buf[0], buf[1]]);
            let len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
            if len < 4 || len > buf.len() {
                return Err(Error::Truncated("bloc de données serveur"));
            }
            let mut r = Reader::new(&buf[4..len]);
            match kind {
                0x0C01 => {
                    core = true;
                    d.version = r.u32_le("SC_CORE")?;
                    if r.remaining() >= 4 {
                        d.client_requested_protocols = Some(r.u32_le("SC_CORE")?);
                    }
                    if r.remaining() >= 4 {
                        d.early_capability_flags = Some(r.u32_le("SC_CORE")?);
                    }
                }
                0x0C02 => {
                    security = true;
                    d.encryption_method = r.u32_le("SC_SECURITY")?;
                    d.encryption_level = r.u32_le("SC_SECURITY")?;
                }
                0x0C03 => {
                    net = true;
                    d.io_channel = r.u16_le("SC_NET")?;
                    let n = r.u16_le("SC_NET")?;
                    for _ in 0..n {
                        d.channel_ids.push(r.u16_le("SC_NET")?);
                    }
                }
                0x0C04 => d.message_channel = Some(r.u16_le("SC_MCS_MSGCHANNEL")?),
                0x0C08 => d.multitransport_flags = Some(r.u32_le("SC_MULTITRANSPORT")?),
                _ => {}
            }
            buf = &buf[len..];
        }
        match (core, security, net) {
            (false, _, _) => Err(Error::Invalid("bloc SC_CORE absent")),
            (_, false, _) => Err(Error::Invalid("bloc SC_SECURITY absent")),
            (_, _, false) => Err(Error::Invalid("bloc SC_NET absent")),
            _ => Ok(d),
        }
    }
}

/// Version RDP lisible (ex. 0x0008000C → « 10.7 »).
pub fn version_name(v: u32) -> &'static str {
    match v {
        0x0008_0001 => "4.0",
        0x0008_0004 => "5.0-8.1",
        0x0008_0005 => "10.0",
        0x0008_0006 => "10.1",
        0x0008_0007 => "10.2",
        0x0008_0008 => "10.3",
        0x0008_0009 => "10.4",
        0x0008_000A => "10.5",
        0x0008_000B => "10.6",
        0x0008_000C => "10.7",
        0x0008_000D => "10.8",
        0x0008_000E => "10.9",
        0x0008_000F => "10.10",
        0x0008_0010 => "10.11",
        0x0008_0011 => "10.12",
        _ => "inconnue",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_data_spec_example() {
        // MS-RDPBCGR 4.1.4 : blocs serveur (SC_CORE, SC_NET, SC_SECURITY sans chiffrement).
        let blocks = [
            0x01, 0x0c, 0x0c, 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, //
            0x03, 0x0c, 0x10, 0x00, 0xeb, 0x03, 0x03, 0x00, 0xec, 0x03, 0xed, 0x03, 0xee, 0x03, 0x00, 0x00,
            0x02, 0x0c, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let d = ServerData::parse(&blocks).unwrap();
        assert_eq!(d.version, 0x0008_0004);
        assert_eq!(d.client_requested_protocols, Some(0));
        assert_eq!(d.io_channel, 1003);
        assert_eq!(d.channel_ids, [1004, 1005, 1006]);
        // Chaque bloc obligatoire retiré à son tour : SC_CORE (0..12), SC_NET (12..28), SC_SECURITY.
        for (range, block) in [(0..12, "SC_CORE"), (12..28, "SC_NET"), (28..40, "SC_SECURITY")] {
            let mut b = blocks.to_vec();
            b.drain(range);
            assert!(matches!(ServerData::parse(&b), Err(Error::Invalid(m)) if m.contains(block)), "{block}");
        }
    }

    #[test]
    fn client_name_keeps_surrogate_pairs_whole() {
        let v = fixed_utf16("abcdefghijklmn😀", 32);
        assert_eq!(v.len(), 32);
        let units: Vec<u16> = v.chunks(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
        assert_eq!(String::from_utf16(&units).unwrap().trim_end_matches('\0'), "abcdefghijklmn");
        let v = fixed_utf16("abcdefghijklm😀z", 32);
        let units: Vec<u16> = v.chunks(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
        assert_eq!(String::from_utf16(&units).unwrap().trim_end_matches('\0'), "abcdefghijklm😀");
    }

    #[test]
    fn client_core_length() {
        let data = ClientData {
            core: ClientCore {
                version: RDP_VERSION_10_7,
                width: 1920,
                height: 1080,
                keyboard_layout: 0x040C,
                client_build: 1,
                client_name: "portique".into(),
                early_capability_flags: early_caps::SUPPORT_ERRINFO_PDU | early_caps::WANT_32BPP_SESSION,
                selected_protocol: 2,
            },
            channels: alloc::vec![Channel { name: "cliprdr", options: channel_opts::INITIALIZED }],
        };
        let enc = data.encode();
        // CS_CORE complet jusqu'à serverSelectedProtocol : 216 octets avec l'en-tête.
        assert_eq!(u16::from_le_bytes([enc[2], enc[3]]), 216);
        assert_eq!(&enc[216..218], &0xC002u16.to_le_bytes());
        // highColorDepth = 24 (HIGH_COLOR_24BPP), le 32 bpp passe par earlyCapabilityFlags.
        assert_eq!(u16::from_le_bytes([enc[140], enc[141]]), 24);
        assert_ne!(u16::from_le_bytes([enc[144], enc[145]]) & early_caps::WANT_32BPP_SESSION, 0);
    }
}
