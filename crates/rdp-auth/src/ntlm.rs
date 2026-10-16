//! Client NTLMv2 (MS-NLMP) avec sécurité de session étendue, MIC et scellement.
//!
//! Sans I/O ni horloge ni hasard : l'appelant fournit le défi client, la clé de session
//! aléatoire et l'heure (FILETIME), ce qui rend chaque étape testable contre les vecteurs
//! de la spec (section 4.2.4).

use alloc::{string::String, vec::Vec};

use hmac::{Hmac, KeyInit, Mac};
use md4::Md4;
use md5::{Digest, Md5};
use rc4::{Rc4, StreamCipher};

use crate::{Error, utf16le};

type HmacMd5 = Hmac<Md5>;

const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

pub mod flags {
    pub const UNICODE: u32 = 0x0000_0001;
    pub const REQUEST_TARGET: u32 = 0x0000_0004;
    pub const SIGN: u32 = 0x0000_0010;
    pub const SEAL: u32 = 0x0000_0020;
    pub const NTLM: u32 = 0x0000_0200;
    pub const ALWAYS_SIGN: u32 = 0x0000_8000;
    pub const EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
    pub const TARGET_INFO: u32 = 0x0080_0000;
    pub const VERSION: u32 = 0x0200_0000;
    pub const N128: u32 = 0x2000_0000;
    pub const KEY_EXCH: u32 = 0x4000_0000;
    pub const N56: u32 = 0x8000_0000;
}

/// Drapeaux annoncés : NTLMv2 avec scellement 128 bits et échange de clé (comme mstsc).
pub const CLIENT_FLAGS: u32 = flags::N56
    | flags::KEY_EXCH
    | flags::N128
    | flags::VERSION
    | flags::EXTENDED_SESSIONSECURITY
    | flags::ALWAYS_SIGN
    | flags::NTLM
    | flags::SEAL
    | flags::SIGN
    | flags::REQUEST_TARGET
    | flags::UNICODE;

/// Windows 10, build 19041, révision NTLM 15.
const VERSION: [u8; 8] = [10, 0, 0x61, 0x4a, 0, 0, 0, 0x0f];

mod av {
    pub const EOL: u16 = 0;
    pub const FLAGS: u16 = 6;
    pub const TIMESTAMP: u16 = 7;
    pub const TARGET_NAME: u16 = 9;
    pub const CHANNEL_BINDINGS: u16 = 10;
    /// MsvAvFlags : le message AUTHENTICATE porte un MIC.
    pub const FLAG_MIC_PRESENT: u32 = 0x2;
}

#[derive(Clone)]
pub struct Credentials {
    pub username: String,
    pub domain: String,
    pub password: String,
}

impl core::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Le mot de passe ne doit jamais finir dans un journal.
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

/// Entrées non déterministes, fournies par l'appelant.
pub struct Randomness {
    pub client_challenge: [u8; 8],
    pub exported_session_key: [u8; 16],
    /// Heure courante en FILETIME (centaines de ns depuis 1601), si le serveur n'en donne pas.
    pub now_filetime: u64,
}

fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut m = <HmacMd5 as KeyInit>::new_from_slice(key).expect("HMAC accepte toute taille de clé");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

fn rc4_128(key: &[u8; 16]) -> Rc4 {
    Rc4::new_from_slice(key).expect("clé RC4 de 16 octets")
}

fn md5(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = Md5::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// NTOWFv2 (MS-NLMP 3.3.2).
pub fn ntowf_v2(c: &Credentials) -> [u8; 16] {
    let nt_hash: [u8; 16] = Md4::digest(utf16le(&c.password)).into();
    let mut user_dom = utf16le(&c.username.to_uppercase());
    user_dom.extend_from_slice(&utf16le(&c.domain));
    hmac_md5(&nt_hash, &[&user_dom])
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn u16(&self, at: usize) -> Result<u16, Error> {
        self.0.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).ok_or(Error::Truncated("NTLM"))
    }
    fn u32(&self, at: usize) -> Result<u32, Error> {
        self.0
            .get(at..at + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or(Error::Truncated("NTLM"))
    }
    /// Champ « len, maxlen, offset » pointant dans la charge utile.
    fn field(&self, at: usize) -> Result<&'a [u8], Error> {
        let len = self.u16(at)? as usize;
        let off = self.u32(at + 4)? as usize;
        self.0.get(off..off + len).ok_or(Error::Truncated("champ NTLM"))
    }
}

#[derive(Debug, Clone)]
pub struct Challenge {
    pub flags: u32,
    pub server_challenge: [u8; 8],
    pub target_info: Vec<u8>,
}

impl Challenge {
    pub fn parse(msg: &[u8]) -> Result<Self, Error> {
        let r = Reader(msg);
        if msg.get(..8) != Some(SIGNATURE) || r.u32(8)? != 2 {
            return Err(Error::Invalid("message CHALLENGE NTLM attendu"));
        }
        let flags = r.u32(20)?;
        let server_challenge = msg.get(24..32).ok_or(Error::Truncated("NTLM"))?.try_into().unwrap();
        let target_info = if flags & flags::TARGET_INFO != 0 { r.field(40)?.to_vec() } else { Vec::new() };
        Ok(Self { flags, server_challenge, target_info })
    }

    fn av_pairs(&self) -> Result<Vec<(u16, &[u8])>, Error> {
        av_pairs(&self.target_info)
    }
}

fn av_pairs(mut b: &[u8]) -> Result<Vec<(u16, &[u8])>, Error> {
    let mut out = Vec::new();
    loop {
        if b.len() < 4 {
            return Err(Error::Truncated("AV_PAIR"));
        }
        let id = u16::from_le_bytes([b[0], b[1]]);
        let len = u16::from_le_bytes([b[2], b[3]]) as usize;
        if id == av::EOL {
            return Ok(out);
        }
        let val = b.get(4..4 + len).ok_or(Error::Truncated("AV_PAIR"))?;
        out.push((id, val));
        b = &b[4 + len..];
    }
}

fn push_av(out: &mut Vec<u8>, id: u16, val: &[u8]) {
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&(val.len() as u16).to_le_bytes());
    out.extend_from_slice(val);
}

/// Construit `temp` (MS-NLMP 3.3.2) : en-tête, horodatage, défi client, AV pairs, 4 zéros.
pub fn ntlmv2_temp(timestamp: u64, client_challenge: &[u8; 8], target_info: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(28 + target_info.len() + 4);
    t.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0]);
    t.extend_from_slice(&timestamp.to_le_bytes());
    t.extend_from_slice(client_challenge);
    t.extend_from_slice(&[0; 4]);
    t.extend_from_slice(target_info);
    t.extend_from_slice(&[0; 4]);
    t
}

/// Clés de session dérivées (sécurité de session étendue, 128 bits).
pub struct SessionKeys {
    pub client_signing: [u8; 16],
    pub client_sealing: [u8; 16],
    pub server_signing: [u8; 16],
    pub server_sealing: [u8; 16],
}

impl SessionKeys {
    pub fn derive(exported: &[u8; 16]) -> Self {
        let k = |magic: &[u8]| md5(&[exported, magic]);
        Self {
            client_signing: k(b"session key to client-to-server signing key magic constant\0"),
            client_sealing: k(b"session key to client-to-server sealing key magic constant\0"),
            server_signing: k(b"session key to server-to-client signing key magic constant\0"),
            server_sealing: k(b"session key to server-to-client sealing key magic constant\0"),
        }
    }
}

/// Un sens de communication scellé : le flux RC4 continue d'un message à l'autre.
pub struct SealingHandle {
    rc4: Rc4,
    signing_key: [u8; 16],
    seq: u32,
}

impl SealingHandle {
    pub fn new(sealing_key: &[u8; 16], signing_key: &[u8; 16]) -> Self {
        Self { rc4: rc4_128(sealing_key), signing_key: *signing_key, seq: 0 }
    }

    /// SEAL (MS-NLMP 3.4.3) : renvoie (signature 16 octets, message chiffré).
    pub fn seal(&mut self, msg: &[u8]) -> ([u8; 16], Vec<u8>) {
        let mut data = msg.to_vec();
        self.rc4.apply_keystream(&mut data);
        let sig = self.signature(msg);
        (sig, data)
    }

    /// Inverse de `seal` pour les messages du serveur ; vérifie la signature.
    pub fn unseal(&mut self, sig: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut plain = data.to_vec();
        self.rc4.apply_keystream(&mut plain);
        let expected = self.signature(&plain);
        if sig.len() != 16 || !ct_eq(sig, &expected) {
            return Err(Error::Invalid("signature NTLM invalide"));
        }
        Ok(plain)
    }

    fn signature(&mut self, plain: &[u8]) -> [u8; 16] {
        let seq = self.seq.to_le_bytes();
        let mac = hmac_md5(&self.signing_key, &[&seq, plain]);
        let mut checksum: [u8; 8] = mac[..8].try_into().unwrap();
        self.rc4.apply_keystream(&mut checksum);
        self.seq = self.seq.wrapping_add(1);
        let mut sig = [0u8; 16];
        sig[..4].copy_from_slice(&1u32.to_le_bytes());
        sig[4..12].copy_from_slice(&checksum);
        sig[12..].copy_from_slice(&seq);
        sig
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Client NTLM : NEGOTIATE → (CHALLENGE) → AUTHENTICATE, puis scellement.
pub struct NtlmClient {
    creds: Credentials,
    rand: Randomness,
    /// SPN « TERMSRV/hôte » ajouté aux AV pairs (MsvAvTargetName).
    spn: String,
    negotiate: Vec<u8>,
}

pub struct Established {
    pub client: SealingHandle,
    pub server: SealingHandle,
}

impl NtlmClient {
    pub fn new(creds: Credentials, rand: Randomness, spn: String) -> Self {
        Self { creds, rand, spn, negotiate: Vec::new() }
    }

    pub fn negotiate(&mut self) -> Vec<u8> {
        let mut m = Vec::with_capacity(40);
        m.extend_from_slice(SIGNATURE);
        m.extend_from_slice(&1u32.to_le_bytes());
        m.extend_from_slice(&CLIENT_FLAGS.to_le_bytes());
        // Domaine et poste vides : champs à zéro, décalage = fin de l'en-tête.
        for _ in 0..2 {
            m.extend_from_slice(&[0, 0, 0, 0]);
            m.extend_from_slice(&40u32.to_le_bytes());
        }
        m.extend_from_slice(&VERSION);
        self.negotiate = m.clone();
        m
    }

    /// Répond au CHALLENGE ; renvoie le message AUTHENTICATE et les poignées de scellement.
    pub fn authenticate(self, challenge_msg: &[u8]) -> Result<(Vec<u8>, Established), Error> {
        let ch = Challenge::parse(challenge_msg)?;
        if ch.flags & flags::EXTENDED_SESSIONSECURITY == 0 || ch.flags & flags::KEY_EXCH == 0 {
            return Err(Error::Invalid("le serveur refuse NTLMv2 avec échange de clé"));
        }
        let pairs = ch.av_pairs()?;
        let server_ts = pairs
            .iter()
            .find(|(id, v)| *id == av::TIMESTAMP && v.len() == 8)
            .map(|(_, v)| u64::from_le_bytes((*v).try_into().unwrap()));

        // AV pairs renvoyées : celles du serveur + MIC présent + liaison de canal vide + SPN.
        let mut ti = Vec::with_capacity(ch.target_info.len() + 64);
        for (id, v) in &pairs {
            if *id != av::FLAGS {
                push_av(&mut ti, *id, v);
            }
        }
        let server_flags = pairs
            .iter()
            .find(|(id, v)| *id == av::FLAGS && v.len() == 4)
            .map(|(_, v)| u32::from_le_bytes((*v).try_into().unwrap()))
            .unwrap_or(0);
        push_av(&mut ti, av::FLAGS, &(server_flags | av::FLAG_MIC_PRESENT).to_le_bytes());
        push_av(&mut ti, av::CHANNEL_BINDINGS, &[0; 16]);
        push_av(&mut ti, av::TARGET_NAME, &utf16le(&self.spn));
        push_av(&mut ti, av::EOL, &[]);

        let key_nt = ntowf_v2(&self.creds);
        let ts = server_ts.unwrap_or(self.rand.now_filetime);
        let temp = ntlmv2_temp(ts, &self.rand.client_challenge, &ti);
        let proof = hmac_md5(&key_nt, &[&ch.server_challenge, &temp]);
        let mut nt_response = proof.to_vec();
        nt_response.extend_from_slice(&temp);
        // Avec horodatage serveur, la réponse LM est remplacée par 24 zéros (3.1.5.1.2).
        let lm_response = [0u8; 24];

        let session_base_key = hmac_md5(&key_nt, &[&proof]);
        let mut encrypted_key = self.rand.exported_session_key;
        rc4_128(&session_base_key).apply_keystream(&mut encrypted_key);

        let domain = utf16le(&self.creds.domain);
        let user = utf16le(&self.creds.username);
        let workstation: Vec<u8> = Vec::new();

        const HEADER: usize = 88;
        let mut payload = Vec::new();
        let mut field = |data: &[u8], header: &mut Vec<u8>| {
            let off = HEADER + payload.len();
            header.extend_from_slice(&(data.len() as u16).to_le_bytes());
            header.extend_from_slice(&(data.len() as u16).to_le_bytes());
            header.extend_from_slice(&(off as u32).to_le_bytes());
            payload.extend_from_slice(data);
        };
        let mut m = Vec::with_capacity(HEADER + 512);
        m.extend_from_slice(SIGNATURE);
        m.extend_from_slice(&3u32.to_le_bytes());
        field(&lm_response, &mut m);
        field(&nt_response, &mut m);
        field(&domain, &mut m);
        field(&user, &mut m);
        field(&workstation, &mut m);
        field(&encrypted_key, &mut m);
        m.extend_from_slice(&(CLIENT_FLAGS & ch.flags | flags::KEY_EXCH).to_le_bytes());
        m.extend_from_slice(&VERSION);
        let mic_at = m.len();
        m.extend_from_slice(&[0; 16]);
        debug_assert_eq!(m.len(), HEADER);
        m.extend_from_slice(&payload);

        let exported = self.rand.exported_session_key;
        let mic = hmac_md5(&exported, &[&self.negotiate, challenge_msg, &m]);
        m[mic_at..mic_at + 16].copy_from_slice(&mic);

        let keys = SessionKeys::derive(&exported);
        Ok((
            m,
            Established {
                client: SealingHandle::new(&keys.client_sealing, &keys.client_signing),
                server: SealingHandle::new(&keys.server_sealing, &keys.server_signing),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn spec_creds() -> Credentials {
        Credentials { username: "User".into(), domain: "Domain".into(), password: "Password".into() }
    }

    // MS-NLMP 4.2.4 : entrées communes (4.2.1) et AV pairs du CHALLENGE (4.2.4.3).
    const SPEC_TARGET_INFO: &str =
        "02000c0044006f006d00610069006e00 01000c00530065007200760065007200 00000000";

    #[test]
    fn ntowf_v2_spec() {
        assert_eq!(ntowf_v2(&spec_creds()).to_vec(), h("0c868a403bfd7a93a3001ef22ef02e3f"));
    }

    #[test]
    fn proof_and_session_key_spec() {
        let temp = ntlmv2_temp(0, &[0xaa; 8], &h(SPEC_TARGET_INFO));
        assert_eq!(
            temp,
            h("0101000000000000 0000000000000000 aaaaaaaaaaaaaaaa 00000000 {SPEC} 00000000"
                .replace("{SPEC}", SPEC_TARGET_INFO)
                .as_str())
        );
        let key = ntowf_v2(&spec_creds());
        let proof = hmac_md5(&key, &[&h("0123456789abcdef"), &temp]);
        assert_eq!(proof.to_vec(), h("68cd0ab851e51c96aabc927bebef6a1c"));
        let base = hmac_md5(&key, &[&proof]);
        assert_eq!(base.to_vec(), h("8de40ccadbc14a82f15cb0ad0de95ca3"));
    }

    #[test]
    fn seal_spec() {
        let keys = SessionKeys::derive(&[0x55; 16]);
        assert_eq!(keys.client_sealing.to_vec(), h("59f600973cc4960a25480a7c196e4c58"));
        assert_eq!(keys.client_signing.to_vec(), h("4788dc861b4782f35d43fd98fe1a2d39"));
        let mut handle = SealingHandle::new(&keys.client_sealing, &keys.client_signing);
        let (sig, data) = handle.seal(&utf16le("Plaintext"));
        assert_eq!(data, h("54e50165bf1936dc996020c1811b0f06fb5f"));
        assert_eq!(sig.to_vec(), h("010000007fb38ec5c55d497600000000"));
    }

    #[test]
    fn seal_unseal_roundtrip_and_tamper() {
        let keys = SessionKeys::derive(&[7; 16]);
        let mut tx = SealingHandle::new(&keys.client_sealing, &keys.client_signing);
        let mut rx = SealingHandle::new(&keys.client_sealing, &keys.client_signing);
        for msg in [&b"premier"[..], b"second message"] {
            let (sig, data) = tx.seal(msg);
            assert_eq!(rx.unseal(&sig, &data).unwrap(), msg);
        }
        let (sig, mut data) = tx.seal(b"troisieme");
        data[0] ^= 1;
        assert!(rx.unseal(&sig, &data).is_err());
    }

    #[test]
    fn authenticate_message_layout() {
        let challenge = h(
            "4e544c4d53535000020000000c000c003800000033828ae20123456789abcdef00000000000000002400240044000000060070170000000f53006500720076006500720002000c0044006f006d00610069006e0001000c0053006500720076006500720000000000",
        );
        let mut c = NtlmClient::new(
            spec_creds(),
            Randomness { client_challenge: [0xaa; 8], exported_session_key: [0x55; 16], now_filetime: 0 },
            "TERMSRV/server".into(),
        );
        let neg = c.negotiate();
        assert_eq!(&neg[..8], SIGNATURE);
        assert_eq!(u32::from_le_bytes(neg[12..16].try_into().unwrap()), CLIENT_FLAGS);
        let (auth, _) = c.authenticate(&challenge).unwrap();
        let r = Reader(&auth);
        assert_eq!(r.u32(8).unwrap(), 3);
        assert_eq!(r.field(36).unwrap(), utf16le("User"));
        assert_eq!(r.field(28).unwrap(), utf16le("Domain"));
        // Clé chiffrée = RC4(SessionBaseKey, 0x55…) ; la base dépend des AV pairs ajoutées.
        let nt = r.field(20).unwrap();
        let pairs = av_pairs(&nt[16 + 28..]).unwrap();
        assert!(pairs.iter().any(|(id, v)| *id == av::FLAGS && *v == av::FLAG_MIC_PRESENT.to_le_bytes()));
        assert!(pairs.iter().any(|(id, v)| *id == av::TARGET_NAME && *v == utf16le("TERMSRV/server")));
        assert_ne!(&auth[72..88], &[0u8; 16], "MIC rempli");
    }
}
