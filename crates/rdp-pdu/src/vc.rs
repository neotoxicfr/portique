//! Canaux virtuels statiques (MS-RDPBCGR 2.2.6) et canaux dynamiques (MS-RDPEDYC).

use alloc::{string::String, vec::Vec};

use crate::{Error, cursor::Reader};

pub const CHANNEL_FLAG_FIRST: u32 = 0x01;
pub const CHANNEL_FLAG_LAST: u32 = 0x02;
pub const CHANNEL_FLAG_SHOW_PROTOCOL: u32 = 0x10;
pub const CHANNEL_FLAG_SUSPEND: u32 = 0x20;
pub const CHANNEL_FLAG_RESUME: u32 = 0x40;
/// Taille des morceaux annoncée dans la capacité Virtual Channel.
pub const CHUNK_SIZE: usize = 1600;

/// Découpe un message de canal statique en morceaux (CHANNEL_PDU_HEADER + données).
pub fn chunks(data: &[u8], show_protocol: bool) -> Vec<Vec<u8>> {
    let total = data.len() as u32;
    let mut out = Vec::new();
    let pieces: Vec<&[u8]> =
        if data.is_empty() { alloc::vec![&[][..]] } else { data.chunks(CHUNK_SIZE).collect() };
    let last = pieces.len() - 1;
    // Un message découpé porte SHOW_PROTOCOL sur chaque morceau (MS-RDPBCGR 3.1.5.2.1).
    let show_protocol = show_protocol || last > 0;
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
    /// Longueur annoncée du message en cours ; `None` hors réassemblage.
    expected: Option<usize>,
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
        // SUSPEND / RESUME (serveur → client) : notification de contrôle, pas un fragment de
        // données ; le message en cours de réassemblage n'est pas touché.
        if flags & (CHANNEL_FLAG_SUSPEND | CHANNEL_FLAG_RESUME) != 0
            && flags & (CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST) == 0
        {
            return Ok(None);
        }
        if flags & CHANNEL_FLAG_FIRST != 0 {
            self.buf.clear();
            self.expected = Some(total);
        }
        let expected = self.expected.ok_or(Error::Invalid("morceau de canal sans FIRST"))?;
        let piece = r.rest();
        if self.buf.len() + piece.len() > expected {
            self.expected = None;
            return Err(Error::Invalid("message de canal plus long qu'annoncé"));
        }
        self.buf.extend_from_slice(piece);
        if flags & CHANNEL_FLAG_LAST != 0 {
            self.expected = None;
            if self.buf.len() != expected {
                return Err(Error::Invalid("message de canal plus court qu'annoncé"));
            }
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
        2 => r.u32_le(what)?,
        // 3 : valeur invalide pour cbId comme pour Len (MS-RDPEDYC 2.2, 2.2.3.1).
        _ => return Err(Error::Invalid("largeur de champ DVC réservée")),
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
        // Longueur nulle : `data` prendrait ce fragment pour un message Data autonome.
        if total == 0 && !data.is_empty() {
            return Err(Error::Invalid("message DVC plus long qu'annoncé"));
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
        // Découpé : SHOW_PROTOCOL sur chaque morceau, même si l'appelant ne le demande pas.
        let flags = |p: &[u8]| u32::from_le_bytes(p[4..8].try_into().unwrap());
        assert!(chunks(&[0; 1601], false).iter().all(|p| flags(p) & CHANNEL_FLAG_SHOW_PROTOCOL != 0));
        assert_eq!(flags(&chunks(&[0; 1600], false)[0]), CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST);
    }

    #[test]
    fn static_reassembly_requires_exact_message() {
        let header = |total: u32, flags: u32, data: &[u8]| {
            let mut v = total.to_le_bytes().to_vec();
            v.extend(flags.to_le_bytes());
            v.extend_from_slice(data);
            v
        };
        let mut r = ChannelReassembler::default();
        // LAST avant la longueur annoncée.
        assert_eq!(r.feed(&header(4, CHANNEL_FLAG_FIRST, &[1])).unwrap(), None);
        assert!(r.feed(&header(4, CHANNEL_FLAG_LAST, &[2])).is_err());
        // LAST isolé après un message complet : rien à livrer.
        let whole = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST;
        assert_eq!(r.feed(&header(2, whole, &[1, 2])).unwrap(), Some(alloc::vec![1, 2]));
        assert!(r.feed(&header(2, CHANNEL_FLAG_LAST, &[3, 4])).is_err());
        // Message vide en un morceau.
        assert_eq!(r.feed(&header(0, whole, &[])).unwrap(), Some(Vec::new()));
        // Fragment orphelin (ni FIRST ni réassemblage en cours) : toujours refusé.
        assert!(r.feed(&header(2, 0, &[1, 2])).is_err());
    }

    #[test]
    fn suspend_and_resume_are_notifications() {
        let header = |total: u32, flags: u32, data: &[u8]| {
            let mut v = total.to_le_bytes().to_vec();
            v.extend(flags.to_le_bytes());
            v.extend_from_slice(data);
            v
        };
        let mut r = ChannelReassembler::default();
        // Sans message en cours.
        assert_eq!(r.feed(&header(0, CHANNEL_FLAG_SUSPEND, &[])).unwrap(), None);
        assert_eq!(r.feed(&header(0, CHANNEL_FLAG_RESUME, &[])).unwrap(), None);
        // Pendant un message : le réassemblage continue comme si de rien n'était.
        assert_eq!(r.feed(&header(4, CHANNEL_FLAG_FIRST, &[1, 2])).unwrap(), None);
        assert_eq!(r.feed(&header(0, CHANNEL_FLAG_SUSPEND, &[])).unwrap(), None);
        assert_eq!(r.feed(&header(0, CHANNEL_FLAG_RESUME, &[])).unwrap(), None);
        assert_eq!(r.feed(&header(4, CHANNEL_FLAG_LAST, &[3, 4])).unwrap(), Some(alloc::vec![1, 2, 3, 4]));
    }

    #[test]
    fn dvc_reserved_width_and_empty_first() {
        // cbId = 3 sur un Create Request.
        assert!(read_dvc(&[0x13, 0, 0, 0, 3, b'x', 0]).is_err());
        let mut r = DvcReassembler::default();
        assert!(r.first(0, &[1, 2]).is_err());
        assert_eq!(r.data(&[1, 2]).unwrap(), Some(alloc::vec![1, 2]), "Data autonome inchangé");
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
