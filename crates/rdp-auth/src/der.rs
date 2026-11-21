//! Le strict nécessaire de DER pour les messages CredSSP (TSRequest, TSCredentials).

use alloc::vec::Vec;

use crate::Error;

pub const SEQUENCE: u8 = 0x30;
pub const INTEGER: u8 = 0x02;
pub const OCTET_STRING: u8 = 0x04;

/// Balise contextuelle construite `[n]`.
pub const fn ctx(n: u8) -> u8 {
    0xA0 | n
}

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = (len as u32).to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (4 - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// INTEGER en complément à deux, forme minimale.
pub fn integer(v: i64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        let (b, next) = (bytes[start], bytes[start + 1]);
        if (b == 0x00 && next & 0x80 == 0) || (b == 0xFF && next & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    tlv(INTEGER, &bytes[start..])
}

pub fn octet_string(v: &[u8]) -> Vec<u8> {
    tlv(OCTET_STRING, v)
}

pub fn explicit(n: u8, inner: &[u8]) -> Vec<u8> {
    tlv(ctx(n), inner)
}

/// Longueur totale du TLV en tête de `buf`, si l'en-tête est complet.
pub fn total_len(buf: &[u8]) -> Option<usize> {
    let first = *buf.get(1)?;
    if first < 0x80 {
        return Some(2 + first as usize);
    }
    let n = (first & 0x7F) as usize;
    if n == 0 || n > 4 {
        return Some(usize::MAX);
    }
    let len = buf.get(2..2 + n)?.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize);
    // Sur 32 bits, l'en-tête ajouté à une longueur de 4 octets peut déborder : on sature à
    // `usize::MAX`, la valeur « invalide » déjà refusée par `read` et `read_frame`.
    Some((2 + n).saturating_add(len))
}

/// Lit un TLV : (balise, contenu, reste).
pub fn read(buf: &[u8]) -> Result<(u8, &[u8], &[u8]), Error> {
    let total = total_len(buf).ok_or(Error::Truncated("DER"))?;
    if total == usize::MAX || buf.len() < total {
        return Err(Error::Truncated("DER"));
    }
    let header = if buf[1] < 0x80 { 2 } else { 2 + (buf[1] & 0x7F) as usize };
    Ok((buf[0], &buf[header..total], &buf[total..]))
}

pub fn expect(buf: &[u8], tag: u8) -> Result<(&[u8], &[u8]), Error> {
    let (t, content, rest) = read(buf)?;
    if t != tag {
        return Err(Error::Invalid("balise DER inattendue"));
    }
    Ok((content, rest))
}

pub fn read_integer(content: &[u8]) -> Result<i64, Error> {
    if content.is_empty() || content.len() > 8 {
        return Err(Error::Invalid("INTEGER DER"));
    }
    let neg = content[0] & 0x80 != 0;
    let mut v: i64 = if neg { -1 } else { 0 };
    for b in content {
        v = (v << 8) | *b as i64;
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers() {
        assert_eq!(integer(6), [0x02, 0x01, 0x06]);
        assert_eq!(integer(128), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(integer(-1), [0x02, 0x01, 0xFF]);
        let ntstatus = 0xC000_006Du32 as i32 as i64;
        let enc = integer(ntstatus);
        assert_eq!(enc, [0x02, 0x04, 0xC0, 0x00, 0x00, 0x6D]);
        assert_eq!(read_integer(&enc[2..]).unwrap() as u32, 0xC000_006D);
    }

    #[test]
    fn long_length() {
        let content = [7u8; 300];
        let enc = octet_string(&content);
        assert_eq!(&enc[..4], &[0x04, 0x82, 0x01, 0x2C]);
        assert_eq!(total_len(&enc), Some(enc.len()));
        let (tag, c, rest) = read(&enc).unwrap();
        assert_eq!((tag, c.len(), rest.len()), (OCTET_STRING, 300, 0));
    }
}
