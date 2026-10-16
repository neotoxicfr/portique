//! RDP 8.0 Bulk Compression (« ZGFX ») et son enveloppe RDP_SEGMENTED_DATA (MS-RDPEGFX 2.2.5,
//! 3.1.9.1). Décompression seulement.
//!
//! L'historique (2 500 000 octets) persiste d'un appel à l'autre : une instance par canal. Après
//! une erreur, l'historique n'est plus fiable et le canal doit être abandonné.

use alloc::vec;
use alloc::vec::Vec;

use crate::Error;

const HISTORY: usize = 2_500_000;
const SINGLE: u8 = 0xE0;
const MULTIPART: u8 = 0xE1;
const PACKET_COMPRESSED: u8 = 0x20;
const TYPE_MASK: u8 = 0x0F;
const TYPE_RDP8: u8 = 0x04;
/// Sortie maximale d'un segment compressé (3.1.9.1.2.3).
const SEGMENT_MAX: usize = 65_535;
/// Sortie maximale d'un bloc entier (protection mémoire).
const TOTAL_MAX: usize = 64 << 20;

#[derive(Clone, Copy)]
enum Kind {
    Literal(u8),
    /// Distance = `base` + `bits` bits de valeur.
    Match {
        bits: u8,
        base: u32,
    },
}

struct Token {
    len: u8,
    code: u8,
    kind: Kind,
}

const fn lit(len: u8, code: u8, value: u8) -> Token {
    Token { len, code, kind: Kind::Literal(value) }
}

const fn dist(len: u8, code: u8, bits: u8, base: u32) -> Token {
    Token { len, code, kind: Kind::Match { bits, base } }
}

/// Jetons commençant par un bit 1 (3.1.9.1.2.3) ; le préfixe « 0 » (littéral sur 8 bits) est
/// traité à part. Code préfixe : aucun jeton n'est le début d'un autre.
const TOKENS: [Token; 36] = [
    dist(5, 0b10001, 5, 0),
    dist(5, 0b10010, 7, 32),
    dist(5, 0b10011, 9, 160),
    dist(5, 0b10100, 10, 672),
    dist(5, 0b10101, 12, 1696),
    dist(6, 0b101100, 14, 5792),
    dist(6, 0b101101, 15, 22176),
    dist(7, 0b1011100, 18, 54944),
    dist(7, 0b1011101, 20, 317088),
    dist(8, 0b10111100, 20, 1365664),
    dist(8, 0b10111101, 21, 2414240),
    lit(5, 0b11000, 0x00),
    lit(5, 0b11001, 0x01),
    lit(6, 0b110100, 0x02),
    lit(6, 0b110101, 0x03),
    lit(6, 0b110110, 0xFF),
    lit(7, 0b1101110, 0x04),
    lit(7, 0b1101111, 0x05),
    lit(7, 0b1110000, 0x06),
    lit(7, 0b1110001, 0x07),
    lit(7, 0b1110010, 0x08),
    lit(7, 0b1110011, 0x09),
    lit(7, 0b1110100, 0x0A),
    lit(7, 0b1110101, 0x0B),
    lit(7, 0b1110110, 0x3A),
    lit(7, 0b1110111, 0x3B),
    lit(7, 0b1111000, 0x3C),
    lit(7, 0b1111001, 0x3D),
    lit(7, 0b1111010, 0x3E),
    lit(7, 0b1111011, 0x3F),
    lit(7, 0b1111100, 0x40),
    lit(7, 0b1111101, 0x80),
    lit(8, 0b11111100, 0x0C),
    lit(8, 0b11111101, 0x38),
    lit(8, 0b11111110, 0x39),
    lit(8, 0b11111111, 0x66),
];

/// Les 8 prochains bits (le premier valant 1, indexés sans lui) → indice dans `TOKENS` + 1,
/// 0 pour une séquence réservée.
const LOOKUP: [u8; 128] = {
    let mut table = [0u8; 128];
    let mut v = 0;
    while v < 128 {
        let byte = (v | 0x80) as u8;
        let mut i = 0;
        while i < TOKENS.len() {
            if byte >> (8 - TOKENS[i].len) == TOKENS[i].code {
                table[v] = i as u8 + 1;
            }
            i += 1;
        }
        v += 1;
    }
    table
};

/// Lecture bit à bit, bit de poids fort d'abord.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    end: usize,
}

impl Bits<'_> {
    fn left(&self) -> usize {
        self.end - self.pos
    }

    /// `n` bits (1 à 25) à la position courante, complétés par des zéros au-delà des données.
    fn peek(&self, n: u32) -> u32 {
        let i = self.pos / 8;
        let mut w = 0u32;
        for k in 0..4 {
            w = (w << 8) | u32::from(self.data.get(i + k).copied().unwrap_or(0));
        }
        (w << (self.pos % 8)) >> (32 - n)
    }

    fn read(&mut self, n: u32, what: &'static str) -> Result<u32, Error> {
        if n as usize > self.left() {
            return Err(Error::Truncated(what));
        }
        let v = self.peek(n);
        self.pos += n as usize;
        Ok(v)
    }

    /// Longueur d'une correspondance : « 0 » = 3, sinon k bits 1, un 0, puis k+1 bits de valeur.
    fn length(&mut self) -> Result<usize, Error> {
        let mut ones = 0;
        while self.read(1, "longueur ZGFX")? == 1 {
            ones += 1;
            if ones > 14 {
                return Err(Error::Invalid("ZGFX : préfixe de longueur réservé"));
            }
        }
        if ones == 0 {
            return Ok(3);
        }
        Ok((1usize << (ones + 1)) + self.read(ones + 1, "longueur ZGFX")? as usize)
    }
}

/// Décompresseur RDP 8.0 Bulk avec son historique circulaire.
pub struct Zgfx {
    history: Vec<u8>,
    /// Position du prochain octet écrit.
    cursor: usize,
    /// Octets valides dans l'historique (plafonné à sa taille).
    filled: usize,
}

impl core::fmt::Debug for Zgfx {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Zgfx").field("cursor", &self.cursor).field("filled", &self.filled).finish()
    }
}

impl Default for Zgfx {
    fn default() -> Self {
        Self::new()
    }
}

impl Zgfx {
    pub fn new() -> Self {
        Self { history: vec![0; HISTORY], cursor: 0, filled: 0 }
    }

    /// Décompresse un bloc RDP_SEGMENTED_DATA (descripteur 0xE0 = segment unique, 0xE1 = multipart)
    /// et AJOUTE le résultat à `out`. L'historique persiste entre appels (une instance par canal).
    /// En cas d'erreur, `out` est remis à sa longueur d'entrée.
    pub fn decompress(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        let start = out.len();
        let result = self.deblock(input, out);
        if result.is_err() {
            out.truncate(start);
        }
        result
    }

    fn deblock(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        let (&descriptor, rest) = input.split_first().ok_or(Error::Truncated("RDP_SEGMENTED_DATA"))?;
        match descriptor {
            SINGLE => self.segment(rest, out, TOTAL_MAX),
            MULTIPART => {
                let [c0, c1, s0, s1, s2, s3, ..] = *rest else {
                    return Err(Error::Truncated("RDP_SEGMENTED_DATA"));
                };
                let count = u16::from_le_bytes([c0, c1]);
                let total = u32::from_le_bytes([s0, s1, s2, s3]) as usize;
                if total > TOTAL_MAX {
                    return Err(Error::Invalid("RDP_SEGMENTED_DATA : taille décompressée excessive"));
                }
                let mut rest = &rest[6..];
                let start = out.len();
                for _ in 0..count {
                    let [z0, z1, z2, z3, ..] = *rest else {
                        return Err(Error::Truncated("RDP_DATA_SEGMENT"));
                    };
                    let size = u32::from_le_bytes([z0, z1, z2, z3]) as usize;
                    rest = &rest[4..];
                    if size > rest.len() {
                        return Err(Error::Truncated("RDP_DATA_SEGMENT"));
                    }
                    let (segment, tail) = rest.split_at(size);
                    let done = out.len() - start;
                    self.segment(segment, out, total - done)?;
                    rest = tail;
                }
                if !rest.is_empty() {
                    return Err(Error::Invalid("RDP_SEGMENTED_DATA : octets en trop"));
                }
                if out.len() - start != total {
                    return Err(Error::Invalid("RDP_SEGMENTED_DATA : taille décompressée incohérente"));
                }
                Ok(())
            }
            _ => Err(Error::Invalid("RDP_SEGMENTED_DATA : descripteur inconnu")),
        }
    }

    /// Un RDP8_BULK_ENCODED_DATA ; `limit` = octets de sortie encore permis.
    fn segment(&mut self, segment: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<(), Error> {
        let (&header, data) = segment.split_first().ok_or(Error::Truncated("RDP8_BULK_ENCODED_DATA"))?;
        if header & TYPE_MASK != TYPE_RDP8 {
            return Err(Error::Invalid("RDP8_BULK_ENCODED_DATA : type de compression inconnu"));
        }
        if header & PACKET_COMPRESSED != 0 {
            return self.decode(data, out, limit.min(SEGMENT_MAX));
        }
        if data.len() > limit {
            return Err(Error::Invalid("segment ZGFX : sortie excessive"));
        }
        out.extend_from_slice(data);
        self.remember(data);
        Ok(())
    }

    /// Flux de bits Huffman (3.1.9.1.2.3) ; le dernier octet donne le nombre de bits inutilisés.
    fn decode(&mut self, data: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<(), Error> {
        let (&unused, data) = data.split_last().ok_or(Error::Truncated("segment ZGFX"))?;
        let end = (data.len() * 8)
            .checked_sub(usize::from(unused & 0x07))
            .ok_or(Error::Invalid("segment ZGFX : bits inutilisés incohérents"))?;
        let mut bits = Bits { data, pos: 0, end };
        let base = out.len();
        while bits.left() > 0 {
            let kind = if bits.peek(1) == 0 {
                Kind::Literal(bits.read(9, "littéral ZGFX")? as u8)
            } else {
                let index = LOOKUP[(bits.peek(8) & 0x7F) as usize];
                let token = TOKENS
                    .get(usize::from(index).wrapping_sub(1))
                    .ok_or(Error::Invalid("ZGFX : jeton réservé"))?;
                bits.read(u32::from(token.len), "jeton ZGFX")?;
                token.kind
            };
            match kind {
                Kind::Literal(byte) => {
                    if out.len() - base >= limit {
                        return Err(Error::Invalid("segment ZGFX : sortie excessive"));
                    }
                    out.push(byte);
                    self.remember(&[byte]);
                }
                Kind::Match { bits: n, base: d } => {
                    let distance = d as usize + bits.read(u32::from(n), "distance ZGFX")? as usize;
                    if distance == 0 {
                        // Séquence non codée : 15 bits de longueur, puis des octets entiers.
                        let count = bits.read(15, "séquence ZGFX")? as usize;
                        let from = bits.pos.div_ceil(8);
                        let to = from + count;
                        if to * 8 > bits.end {
                            return Err(Error::Truncated("séquence ZGFX"));
                        }
                        if out.len() - base + count > limit {
                            return Err(Error::Invalid("segment ZGFX : sortie excessive"));
                        }
                        out.extend_from_slice(&data[from..to]);
                        self.remember(&data[from..to]);
                        bits.pos = to * 8;
                    } else {
                        let length = bits.length()?;
                        if distance > self.filled {
                            return Err(Error::Invalid("ZGFX : distance hors de l'historique"));
                        }
                        if out.len() - base + length > limit {
                            return Err(Error::Invalid("segment ZGFX : sortie excessive"));
                        }
                        self.copy(distance, length, out);
                    }
                }
            }
        }
        Ok(())
    }

    /// Recopie `length` octets situés `distance` octets en arrière ; un recouvrement réplique
    /// les octets (distance < longueur), d'où la copie octet par octet.
    fn copy(&mut self, distance: usize, length: usize, out: &mut Vec<u8>) {
        let mut src = (self.cursor + HISTORY - distance) % HISTORY;
        out.reserve(length);
        for _ in 0..length {
            let byte = self.history[src];
            src = if src + 1 == HISTORY { 0 } else { src + 1 };
            out.push(byte);
            self.history[self.cursor] = byte;
            self.cursor = if self.cursor + 1 == HISTORY { 0 } else { self.cursor + 1 };
        }
        self.filled = (self.filled + length).min(HISTORY);
    }

    fn remember(&mut self, bytes: &[u8]) {
        // Seuls les derniers HISTORY octets restent accessibles.
        let bytes = &bytes[bytes.len().saturating_sub(HISTORY)..];
        let first = (HISTORY - self.cursor).min(bytes.len());
        self.history[self.cursor..self.cursor + first].copy_from_slice(&bytes[..first]);
        self.history[..bytes.len() - first].copy_from_slice(&bytes[first..]);
        self.cursor = (self.cursor + bytes.len()) % HISTORY;
        self.filled = self.filled.saturating_add(bytes.len()).min(HISTORY);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FOX: &[u8] = b"The quick brown fox jumps over the lazy dog";

    fn run(z: &mut Zgfx, input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        z.decompress(input, &mut out).map(|()| out)
    }

    /// Encodeur de test minimal : littéraux sur 9 bits, correspondances, séquences non codées.
    #[derive(Default)]
    struct Writer {
        bytes: Vec<u8>,
        nbits: usize,
    }

    impl Writer {
        fn push(&mut self, value: u32, n: u32) {
            for i in (0..n).rev() {
                if self.nbits.is_multiple_of(8) {
                    self.bytes.push(0);
                }
                if (value >> i) & 1 == 1 {
                    *self.bytes.last_mut().unwrap() |= 0x80 >> (self.nbits % 8);
                }
                self.nbits += 1;
            }
        }

        fn literal(&mut self, b: u8) -> &mut Self {
            self.push(u32::from(b), 9);
            self
        }

        fn matching(&mut self, distance: u32, length: usize) -> &mut Self {
            let t = TOKENS
                .iter()
                .find(|t| matches!(t.kind, Kind::Match { bits, base } if distance >= base && distance - base < 1 << bits))
                .unwrap();
            let Kind::Match { bits, base } = t.kind else { unreachable!() };
            self.push(u32::from(t.code), u32::from(t.len));
            self.push(distance - base, u32::from(bits));
            if length == 3 {
                self.push(0, 1);
            } else {
                let ones = length.ilog2() - 1;
                self.push((1 << ones) - 1, ones);
                self.push(0, 1);
                self.push((length - (1 << (ones + 1))) as u32, ones + 1);
            }
            self
        }

        fn raw(&mut self, data: &[u8]) -> &mut Self {
            self.push(0b10001, 5);
            self.push(0, 5);
            self.push(data.len() as u32, 15);
            self.nbits = self.bytes.len() * 8;
            self.bytes.extend_from_slice(data);
            self.nbits += data.len() * 8;
            self
        }

        /// Segment unique compressé : E0 24 <bits> <bits inutilisés>.
        fn single(&self) -> Vec<u8> {
            let mut v = vec![SINGLE, 0x24];
            v.extend_from_slice(&self.bytes);
            v.push((self.bytes.len() * 8 - self.nbits) as u8);
            v
        }
    }

    /// MS-RDPEGFX 4.2.1.1.1 : multipart, deux segments bruts puis un segment compressé.
    #[test]
    fn spec_example_1_multipart() {
        let input = [
            0xE1, 0x03, 0x00, 0x2B, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x04, 0x54, 0x68, 0x65, 0x20,
            0x71, 0x75, 0x69, 0x63, 0x6B, 0x20, 0x62, 0x72, 0x6F, 0x77, 0x6E, 0x20, 0x0E, 0x00, 0x00, 0x00,
            0x04, 0x66, 0x6F, 0x78, 0x20, 0x6A, 0x75, 0x6D, 0x70, 0x73, 0x20, 0x6F, 0x76, 0x65, 0x10, 0x00,
            0x00, 0x00, 0x24, 0x39, 0x08, 0x0E, 0x91, 0xF8, 0xD8, 0x61, 0x3D, 0x1E, 0x44, 0x06, 0x43, 0x79,
            0x9C, 0x02,
        ];
        assert_eq!(run(&mut Zgfx::new(), &input).unwrap(), FOX);
    }

    /// 4.2.1.1.2 : segment unique non compressé.
    #[test]
    fn spec_example_2_uncompressed() {
        let mut input = vec![0xE0, 0x04];
        input.extend_from_slice(FOX);
        let mut z = Zgfx::new();
        assert_eq!(run(&mut z, &input).unwrap(), FOX);
        // Le segment brut alimente l'historique.
        let mut w = Writer::default();
        w.matching(FOX.len() as u32, 3);
        assert_eq!(run(&mut z, &w.single()).unwrap(), b"The");
    }

    /// 4.2.1.1.3 : littéraux courts et correspondance de distance 1.
    #[test]
    fn spec_example_3_short_literals() {
        let input = [0xE0, 0x24, 0xCE, 0x9B, 0x19, 0x62, 0x18, 0x00];
        assert_eq!(run(&mut Zgfx::new(), &input).unwrap(), [0x01, 0x02, 0xFF, 0x65, 0x65, 0x65, 0x65, 0x65]);
    }

    /// 4.2.1.1.4 : séquence non codée de 1 000 octets (en-tête de la spec, octets libres).
    #[test]
    fn spec_example_4_unencoded_run() {
        let payload: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
        let mut input = vec![0xE0, 0x24, 0x88, 0x01, 0xF4, 0x00];
        input.extend_from_slice(&payload);
        input.push(0x00);
        assert_eq!(run(&mut Zgfx::new(), &input).unwrap(), payload);
        let mut w = Writer::default();
        w.raw(&payload);
        assert_eq!(w.single(), input);
    }

    /// 4.2.1.1.5 : correspondance qui se recouvre (« ABC » × 20) ; l'encodeur de test produit
    /// exactement les octets de la spec.
    #[test]
    fn spec_example_5_overlap() {
        let input = [0xE0, 0x24, 0x20, 0x90, 0x88, 0x71, 0x1F, 0xB2, 0x01];
        assert_eq!(run(&mut Zgfx::new(), &input).unwrap(), b"ABC".repeat(20));
        let mut w = Writer::default();
        w.literal(b'A').literal(b'B').literal(b'C').matching(3, 57);
        assert_eq!(w.single(), input);
    }

    /// 3.1.9.1.2.5 : « 0 0100 1001 10001 00001 110 001 » = dix octets 0x49.
    #[test]
    fn spec_bitstream_example() {
        let mut w = Writer::default();
        w.literal(0x49).matching(1, 9);
        assert_eq!(run(&mut Zgfx::new(), &w.single()).unwrap(), [0x49; 10]);
    }

    /// Littéraux, correspondance et copie non compressée dans le même segment, puis une
    /// correspondance qui pointe dans le bloc précédent (historique persistant).
    #[test]
    fn roundtrip_mixed_and_history() {
        let mut w = Writer::default();
        w.literal(b'a').literal(b'b').matching(2, 6).raw(b"xyz").literal(b'!').matching(4, 3);
        let mut z = Zgfx::new();
        assert_eq!(run(&mut z, &w.single()).unwrap(), b"ababababxyz!xyz");
        let mut w = Writer::default();
        w.matching(15, 4);
        assert_eq!(run(&mut z, &w.single()).unwrap(), b"abab");
    }

    /// Correspondance à cheval sur la fin du tampon circulaire, et distance maximale.
    #[test]
    fn history_wraps() {
        let mut z = Zgfx::new();
        let mut big = vec![0xE0, 0x04];
        big.resize(2 + HISTORY - 2, 0x11);
        run(&mut z, &big).unwrap();
        run(&mut z, &[0xE0, 0x04, b'W', b'X', b'Y', b'Z']).unwrap();
        assert_eq!(z.cursor, 2);
        let mut w = Writer::default();
        w.matching(4, 4).matching(HISTORY as u32, 3);
        // Distance HISTORY : l'octet écrit 2 500 000 octets plus tôt, soit un 0x11.
        assert_eq!(run(&mut z, &w.single()).unwrap(), b"WXYZ\x11\x11\x11");
    }

    #[test]
    fn distance_beyond_history() {
        let mut w = Writer::default();
        w.literal(1).matching(2, 3);
        let mut out = vec![9];
        assert_eq!(
            Zgfx::new().decompress(&w.single(), &mut out),
            Err(Error::Invalid("ZGFX : distance hors de l'historique"))
        );
        assert_eq!(out, [9]);
    }

    #[test]
    fn segment_output_capped() {
        let mut w = Writer::default();
        w.literal(0).matching(1, 40000).matching(1, 40000);
        assert!(matches!(run(&mut Zgfx::new(), &w.single()), Err(Error::Invalid(_))));
    }

    #[test]
    fn malformed_inputs() {
        let z = &mut Zgfx::new();
        let bad = |z: &mut Zgfx, input: &[u8]| run(z, input).unwrap_err();
        assert!(matches!(bad(z, &[]), Error::Truncated(_)));
        assert!(matches!(bad(z, &[0xE2, 0x04]), Error::Invalid(_)));
        // Type de compression autre que RDP8.
        assert!(matches!(bad(z, &[0xE0, 0x23, 0x00]), Error::Invalid(_)));
        // Plus de bits inutilisés que de bits.
        assert!(matches!(bad(z, &[0xE0, 0x24, 0x07]), Error::Invalid(_)));
        // Jeton réservé 10000.
        assert!(matches!(bad(z, &[0xE0, 0x24, 0x80, 0x03]), Error::Invalid(_)));
        // Préfixe de longueur réservé (15 bits à 1).
        let mut w = Writer::default();
        w.literal(1).push(0b10001_00001, 10);
        w.push(0x7FFF, 15);
        assert!(matches!(bad(z, &w.single()), Error::Invalid(_)));
        // Littéral coupé par la fin du flux.
        assert!(matches!(bad(z, &[0xE0, 0x24, 0x00, 0x00]), Error::Truncated(_)));
        // Séquence non codée plus longue que les données.
        assert!(matches!(bad(z, &[0xE0, 0x24, 0x88, 0x01, 0xF4, 0x00, 1, 2, 0x00]), Error::Truncated(_)));
        // Multipart : segment annoncé plus long que les données, total incohérent, total excessif.
        assert!(matches!(bad(z, &[0xE1, 1, 0, 1, 0, 0, 0, 9, 0, 0, 0, 0x04]), Error::Truncated(_)));
        assert!(matches!(bad(z, &[0xE1, 1, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0x04, 1]), Error::Invalid(_)));
        assert!(matches!(bad(z, &[0xE1, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0x04, 1]), Error::Invalid(_)));
        assert!(matches!(bad(z, &[0xE1, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0x04]), Error::Invalid(_)));
        // Octets après le dernier segment.
        assert!(matches!(bad(z, &[0xE1, 0, 0, 0, 0, 0, 0, 0xAA]), Error::Invalid(_)));
        assert_eq!(run(z, &[0xE1, 0, 0, 0, 0, 0, 0]).unwrap(), b"");
    }
}
