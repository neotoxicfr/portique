//! Canaux virtuels statiques (MS-RDPBCGR 2.2.6) et canaux dynamiques (MS-RDPEDYC).

use alloc::{string::String, vec::Vec};

use crate::{Error, cursor::Reader};

pub const CHANNEL_FLAG_FIRST: u32 = 0x01;
pub const CHANNEL_FLAG_LAST: u32 = 0x02;
pub const CHANNEL_FLAG_SHOW_PROTOCOL: u32 = 0x10;
/// Taille des morceaux annoncée dans la capacité Virtual Channel.
pub const CHUNK_SIZE: usize = 1600;

/// Découpe un message de canal statique en morceaux (CHANNEL_PDU_HEADER + données).
pub fn chunks(data: &[u8], show_protocol: bool) -> Vec<Vec<u8>> {
    let total = data.len() as u32;
    let mut out = Vec::new();
    let pieces: Vec<&[u8]> =
        if data.is_empty() { alloc::vec![&[][..]] } else { data.chunks(CHUNK_SIZE).collect() };
    let last = pieces.len() - 1;
    for (i, piece) in pieces.into_iter().enumerate() {
        let mut flags = if show_protocol { CHANNEL_FLAG_SHOW_PROTOCOL } else { 0 };
        if i == 0 {
            flags |= CHANNEL_FLAG_FIRST;
        }
        if i == last {
            flags |= CHANNEL_FLAG_LAST;
        }
        let mut c = Vec::with_capacity(8 + piece.len());
        c.extend_from_slice(&total.to_le_bytes());
        c.extend_from_slice(&flags.to_le_bytes());
        c.extend_from_slice(piece);
        out.push(c);
    }
    out
}

/// Réassemble les morceaux d'un canal statique.
#[derive(Default)]
pub struct ChannelReassembler {
    buf: Vec<u8>,
    expected: usize,
}

/// Plafond d'un message de canal statique (le presse-papier peut porter une image).
const MAX_CHANNEL_MESSAGE: usize = 64 * 1024 * 1024;

impl ChannelReassembler {
    pub fn feed(&mut self, pdu: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let mut r = Reader::new(pdu);
        let total = r.u32_le("CHANNEL_PDU_HEADER")? as usize;
        let flags = r.u32_le("CHANNEL_PDU_HEADER")?;
        if flags & 0x0020_0000 != 0 {
            return Err(Error::Invalid("canal compressé non négocié"));
        }
        if total > MAX_CHANNEL_MESSAGE {
            return Err(Error::Invalid("message de canal trop grand"));
        }
        if flags & CHANNEL_FLAG_FIRST != 0 {
            self.buf.clear();
            self.expected = total;
        }
        self.buf.extend_from_slice(r.rest());
        if self.buf.len() > self.expected {
            return Err(Error::Invalid("message de canal plus long qu'annoncé"));
        }
        if flags & CHANNEL_FLAG_LAST != 0 {
            return Ok(Some(core::mem::take(&mut self.buf)));
        }
        Ok(None)
    }
}

// --- drdynvc (MS-RDPEDYC 2.2) ---

pub mod dvc_cmd {
    pub const CREATE: u8 = 0x01;
    pub const DATA_FIRST: u8 = 0x02;
    pub const DATA: u8 = 0x03;
    pub const CLOSE: u8 = 0x04;
    pub const CAPABILITY: u8 = 0x05;
    pub const DATA_FIRST_COMPRESSED: u8 = 0x06;
    pub const DATA_COMPRESSED: u8 = 0x07;
    pub const SOFT_SYNC_REQUEST: u8 = 0x08;
}

/// Version de drdynvc annoncée : la 2 (priorités) sans compression des données.
pub const DVC_VERSION: u16 = 2;

#[derive(Debug, PartialEq)]
pub enum DvcPdu<'a> {
    Capabilities { version: u16 },
    Create { channel_id: u32, name: String },
    DataFirst { channel_id: u32, total: u32, data: &'a [u8] },
    Data { channel_id: u32, data: &'a [u8] },
    Close { channel_id: u32 },
    Other(u8),
}

fn read_var(r: &mut Reader, size: u8, what: &'static str) -> Result<u32, Error> {
    Ok(match size {
        0 => r.u8(what)? as u32,
        1 => r.u16_le(what)? as u32,
        _ => r.u32_le(what)?,
    })
}

pub fn read_dvc(msg: &[u8]) -> Result<DvcPdu<'_>, Error> {
    let mut r = Reader::new(msg);
    let h = r.u8("en-tête DVC")?;
    let (cb_id, sp, cmd) = (h & 0x03, (h >> 2) & 0x03, h >> 4);
    Ok(match cmd {
        dvc_cmd::CAPABILITY => {
            r.skip(1, "capacités DVC")?;
            DvcPdu::Capabilities { version: r.u16_le("capacités DVC")? }
        }
        dvc_cmd::CREATE => {
            let channel_id = read_var(&mut r, cb_id, "création DVC")?;
            let raw = r.rest();
            let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
            let name = String::from_utf8_lossy(&raw[..end]).into_owned();
            DvcPdu::Create { channel_id, name }
        }
        dvc_cmd::DATA_FIRST => {
            let channel_id = read_var(&mut r, cb_id, "données DVC")?;
            let total = read_var(&mut r, sp, "données DVC")?;
            DvcPdu::DataFirst { channel_id, total, data: r.rest() }
        }
        dvc_cmd::DATA => {
            let channel_id = read_var(&mut r, cb_id, "données DVC")?;
            DvcPdu::Data { channel_id, data: r.rest() }
        }
        dvc_cmd::CLOSE => DvcPdu::Close { channel_id: read_var(&mut r, cb_id, "fermeture DVC")? },
        other => DvcPdu::Other(other),
    })
}

fn var_size(v: u32) -> (u8, usize) {
    if v <= 0xFF {
        (0, 1)
    } else if v <= 0xFFFF {
        (1, 2)
    } else {
        (2, 4)
    }
}

fn push_var(out: &mut Vec<u8>, v: u32, size: usize) {
    out.extend_from_slice(&v.to_le_bytes()[..size]);
}

pub fn dvc_capabilities_response() -> Vec<u8> {
    let mut v = alloc::vec![dvc_cmd::CAPABILITY << 4, 0];
    v.extend_from_slice(&DVC_VERSION.to_le_bytes());
    v
}

/// Create Response : `status` 0 = accepté, négatif (NTSTATUS) = refusé.
pub fn dvc_create_response(channel_id: u32, status: i32) -> Vec<u8> {
    let (cb, n) = var_size(channel_id);
    let mut v = alloc::vec![(dvc_cmd::CREATE << 4) | cb];
    push_var(&mut v, channel_id, n);
    v.extend_from_slice(&status.to_le_bytes());
    v
}

pub fn dvc_close(channel_id: u32) -> Vec<u8> {
    let (cb, n) = var_size(channel_id);
    let mut v = alloc::vec![(dvc_cmd::CLOSE << 4) | cb];
    push_var(&mut v, channel_id, n);
    v
}

/// Découpe un message DVC client en PDU Data First / Data tenant dans un morceau de canal statique.
pub fn dvc_data(channel_id: u32, data: &[u8]) -> Vec<Vec<u8>> {
    let (cb, n) = var_size(channel_id);
    let single_room = CHUNK_SIZE - 1 - n;
    if data.len() <= single_room {
        let mut v = Vec::with_capacity(1 + n + data.len());
        v.push((dvc_cmd::DATA << 4) | cb);
        push_var(&mut v, channel_id, n);
        v.extend_from_slice(data);
        return alloc::vec![v];
    }
    let (sp, ln) = var_size(data.len() as u32);
    let first_room = CHUNK_SIZE - 1 - n - ln;
    let mut out = Vec::new();
    let mut first = Vec::with_capacity(CHUNK_SIZE);
    first.push((dvc_cmd::DATA_FIRST << 4) | (sp << 2) | cb);
    push_var(&mut first, channel_id, n);
    push_var(&mut first, data.len() as u32, ln);
    first.extend_from_slice(&data[..first_room]);
    out.push(first);
    for piece in data[first_room..].chunks(single_room) {
        let mut v = Vec::with_capacity(1 + n + piece.len());
        v.push((dvc_cmd::DATA << 4) | cb);
        push_var(&mut v, channel_id, n);
        v.extend_from_slice(piece);
        out.push(v);
    }
    out
}

/// Réassemble les messages DVC d'un canal (Data First suivi de Data).
#[derive(Default)]
pub struct DvcReassembler {
    buf: Vec<u8>,
    expected: usize,
}

impl DvcReassembler {
    pub fn first(&mut self, total: u32, data: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        if total as usize > MAX_CHANNEL_MESSAGE {
            return Err(Error::Invalid("message DVC trop grand"));
        }
        self.buf.clear();
        self.expected = total as usize;
        self.data(data)
    }

    pub fn data(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        if self.expected == 0 {
            return Ok(Some(data.to_vec()));
        }
        self.buf.extend_from_slice(data);
        if self.buf.len() > self.expected {
            return Err(Error::Invalid("message DVC plus long qu'annoncé"));
        }
        if self.buf.len() == self.expected {
            self.expected = 0;
            return Ok(Some(core::mem::take(&mut self.buf)));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_chunks_roundtrip() {
        let data: Vec<u8> = (0..4000u32).map(|i| i as u8).collect();
        let parts = chunks(&data, true);
        assert_eq!(parts.len(), 3);
        let mut r = ChannelReassembler::default();
        assert_eq!(r.feed(&parts[0]).unwrap(), None);
        assert_eq!(r.feed(&parts[1]).unwrap(), None);
        assert_eq!(r.feed(&parts[2]).unwrap(), Some(data));
    }

    #[test]
    fn dvc_create_and_data() {
        // MS-RDPEDYC 4.1.2 : Create Request du canal 3 « testdvc ».
        let create = [0x10, 0x03, b't', b'e', b's', b't', b'd', b'v', b'c', 0x00];
        assert_eq!(read_dvc(&create).unwrap(), DvcPdu::Create { channel_id: 3, name: "testdvc".into() });
        assert_eq!(dvc_create_response(3, 0), [0x10, 0x03, 0, 0, 0, 0]);

        let big: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let pdus = dvc_data(3, &big);
        assert!(pdus.iter().all(|p| p.len() <= CHUNK_SIZE));
        let mut r = DvcReassembler::default();
        let mut got = None;
        for p in &pdus {
            got = match read_dvc(p).unwrap() {
                DvcPdu::DataFirst { total, data, .. } => r.first(total, data).unwrap(),
                DvcPdu::Data { data, .. } => r.data(data).unwrap(),
                other => panic!("{other:?}"),
            };
        }
        assert_eq!(got, Some(big));
    }
}
