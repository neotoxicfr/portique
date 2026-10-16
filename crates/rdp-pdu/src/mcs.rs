//! MCS Connect Initial / Connect Response (T.125, BER) et l'enveloppe GCC Conference
//! Create (T.124, PER) qui transporte les blocs de données (MS-RDPBCGR 2.2.1.3, 2.2.1.4).

use alloc::vec::Vec;

use crate::{Error, cursor::Reader, gcc};

fn ber_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
}

fn ber(out: &mut Vec<u8>, tag: &[u8], content: &[u8]) {
    out.extend_from_slice(tag);
    ber_len(out, content.len());
    out.extend_from_slice(content);
}

fn ber_int(out: &mut Vec<u8>, v: u32) {
    let bytes = v.to_be_bytes();
    let start = bytes.iter().take_while(|b| **b == 0).count().min(3);
    let mut content = Vec::with_capacity(5);
    // Entier signé : un bit de poids fort à 1 exige un zéro devant.
    if bytes[start] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(&bytes[start..]);
    ber(out, &[0x02], &content);
}

fn domain_params(p: [u32; 8]) -> Vec<u8> {
    let mut seq = Vec::new();
    for v in p {
        ber_int(&mut seq, v);
    }
    let mut out = Vec::new();
    ber(&mut out, &[0x30], &seq);
    out
}

/// Longueur PER (X.691 10.9) sur 1 ou 2 octets.
fn per_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        out.extend_from_slice(&(0x8000u16 | len as u16).to_be_bytes());
    }
}

fn read_per_len(r: &mut Reader) -> Result<usize, Error> {
    let b = r.u8("longueur PER")?;
    if b & 0x80 == 0 {
        Ok(b as usize)
    } else {
        Ok((((b & 0x7F) as usize) << 8) | r.u8("longueur PER")? as usize)
    }
}

/// Identifiant d'objet T.124 (0.0.20.124.0.1) précédé du choix « object ».
const T124_KEY: [u8; 7] = [0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01];

/// GCC Conference Create Request contenant les blocs client.
fn gcc_create_request(client_data: &[u8]) -> Vec<u8> {
    let mut ccr = Vec::new();
    // ConferenceCreateRequest : nom « 1 », pas de mot de passe, un jeu de données
    // utilisateur à clé H.221 non standard « Duca » (client vers serveur).
    ccr.extend_from_slice(&[0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x00]);
    ccr.extend_from_slice(b"Duca");
    per_len(&mut ccr, client_data.len());
    ccr.extend_from_slice(client_data);

    let mut out = T124_KEY.to_vec();
    per_len(&mut out, ccr.len());
    out.extend_from_slice(&ccr);
    out
}

/// MCS Connect Initial (2.2.1.3) prêt à envoyer (TPKT + X.224 compris).
pub fn connect_initial(client: &gcc::ClientData) -> Vec<u8> {
    let user_data = gcc_create_request(&client.encode());
    let mut body = Vec::new();
    ber(&mut body, &[0x04], &[0x01]); // callingDomainSelector
    ber(&mut body, &[0x04], &[0x01]); // calledDomainSelector
    ber(&mut body, &[0x01], &[0xFF]); // upwardFlag
    body.extend(domain_params([34, 2, 0, 1, 0, 1, 65535, 2])); // targetParameters
    body.extend(domain_params([1, 1, 1, 1, 0, 1, 1056, 2])); // minimumParameters
    body.extend(domain_params([65535, 64535, 65535, 1, 0, 1, 65535, 2])); // maximumParameters
    ber(&mut body, &[0x04], &user_data);
    let mut pdu = Vec::new();
    ber(&mut pdu, &[0x7F, 0x65], &body);
    crate::x224::data(&pdu)
}

fn read_ber_len(r: &mut Reader) -> Result<usize, Error> {
    let b = r.u8("longueur BER")?;
    if b < 0x80 {
        return Ok(b as usize);
    }
    let n = (b & 0x7F) as usize;
    if n == 0 || n > 2 {
        return Err(Error::Invalid("longueur BER"));
    }
    let mut len = 0usize;
    for _ in 0..n {
        len = (len << 8) | r.u8("longueur BER")? as usize;
    }
    Ok(len)
}

fn read_ber<'a>(r: &mut Reader<'a>, tag: u8, what: &'static str) -> Result<&'a [u8], Error> {
    if r.u8(what)? != tag {
        return Err(Error::Invalid(what));
    }
    let len = read_ber_len(r)?;
    r.bytes(len, what)
}

/// MCS Connect Response (2.2.1.4) : vérifie le résultat et renvoie les blocs serveur.
pub fn connect_response(frame: &[u8]) -> Result<gcc::ServerData, Error> {
    let mcs = crate::x224::read_data(frame)?;
    let mut r = Reader::new(mcs);
    if r.bytes(2, "MCS Connect Response")? != [0x7F, 0x66] {
        return Err(Error::Invalid("MCS Connect Response attendu"));
    }
    let len = read_ber_len(&mut r)?;
    let mut r = Reader::new(r.bytes(len, "MCS Connect Response")?);
    let result = read_ber(&mut r, 0x0A, "résultat MCS")?;
    if result != [0] {
        return Err(Error::McsRefused(*result.first().unwrap_or(&0xFF)));
    }
    read_ber(&mut r, 0x02, "calledConnectId")?;
    read_ber(&mut r, 0x30, "domainParameters")?;
    let user_data = read_ber(&mut r, 0x04, "userData")?;

    let mut g = Reader::new(user_data);
    if g.bytes(7, "clé T.124")? != T124_KEY {
        return Err(Error::Invalid("clé T.124 attendue"));
    }
    read_per_len(&mut g)?;
    // ConferenceCreateResponse : choix, nodeID, tag (entier PER), résultat, nombre de jeux,
    // choix « non standard », clé H.221 « McDn » (serveur vers client).
    g.skip(1 + 2, "GCC")?;
    let tag_len = g.u8("GCC")? as usize;
    g.skip(tag_len + 1 + 1 + 1, "GCC")?;
    let key_len = g.u8("GCC")? as usize + 4;
    if g.bytes(key_len, "GCC")? != b"McDn" {
        return Err(Error::Invalid("clé H.221 McDn attendue"));
    }
    let n = read_per_len(&mut g)?;
    gcc::ServerData::parse(g.bytes(n, "données serveur")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ber_integers() {
        let mut v = Vec::new();
        ber_int(&mut v, 34);
        ber_int(&mut v, 65535);
        ber_int(&mut v, 0);
        assert_eq!(v, [0x02, 0x01, 0x22, 0x02, 0x03, 0x00, 0xFF, 0xFF, 0x02, 0x01, 0x00]);
    }

    /// Connect Response construite selon la structure de MS-RDPBCGR 4.1.4.
    fn response(result: u8, blocks: &[u8]) -> Vec<u8> {
        let mut gcc = T124_KEY.to_vec();
        let mut ccr = alloc::vec![0x14, 0x76, 0x0a, 0x01, 0x01, 0x00, 0x01, 0xc0, 0x00];
        ccr.extend_from_slice(b"McDn");
        per_len(&mut ccr, blocks.len());
        ccr.extend_from_slice(blocks);
        per_len(&mut gcc, ccr.len());
        gcc.extend_from_slice(&ccr);
        let mut body = Vec::new();
        ber(&mut body, &[0x0A], &[result]);
        ber_int(&mut body, 0);
        body.extend(domain_params([34, 3, 0, 1, 0, 1, 65528, 2]));
        ber(&mut body, &[0x04], &gcc);
        let mut pdu = Vec::new();
        ber(&mut pdu, &[0x7F, 0x66], &body);
        crate::x224::data(&pdu)
    }

    #[test]
    fn connect_response_parsing() {
        let blocks = [
            0x01, 0x0c, 0x0c, 0x00, 0x0c, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x00, //
            0x03, 0x0c, 0x0c, 0x00, 0xeb, 0x03, 0x02, 0x00, 0xec, 0x03, 0xed, 0x03,
        ];
        let d = connect_response(&response(0, &blocks)).unwrap();
        assert_eq!(d.version, 0x0008_000C);
        assert_eq!(d.client_requested_protocols, Some(0x0b));
        assert_eq!((d.io_channel, d.channel_ids.as_slice()), (1003, &[1004, 1005][..]));
        assert_eq!(connect_response(&response(2, &blocks)), Err(Error::McsRefused(2)));
        let big = [0x80u8; 300];
        assert!(connect_response(&response(0, &big)).is_err(), "blocs corrompus refusés");
    }

    #[test]
    fn ber_int_high_bit() {
        let mut v = Vec::new();
        ber_int(&mut v, 0x8000_0000);
        assert_eq!(v, [0x02, 0x05, 0x00, 0x80, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn connect_initial_wraps_client_data() {
        let client = gcc::ClientData {
            core: gcc::ClientCore {
                version: gcc::RDP_VERSION_10_7,
                width: 1280,
                height: 720,
                keyboard_layout: 0x040C,
                client_build: 1,
                client_name: "yawrdp".into(),
                early_capability_flags: 0,
                selected_protocol: 2,
            },
            channels: Vec::new(),
        };
        let f = connect_initial(&client);
        assert_eq!(crate::x224::frame_len(&f), Some(f.len()));
        let mcs = crate::x224::read_data(&f).unwrap();
        assert_eq!(&mcs[..2], &[0x7F, 0x65]);
        let pos = mcs.windows(4).position(|w| w == b"Duca").expect("clé Duca");
        assert_eq!(&mcs[pos + 6..pos + 8], &0xC001u16.to_le_bytes());
    }
}
