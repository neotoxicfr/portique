//! Client CredSSP (MS-CSSP) au-dessus de NTLM, versions 2 à 6.
//!
//! Déroulé : NEGOTIATE → CHALLENGE → AUTHENTICATE + preuve de clé publique → preuve du
//! serveur → identifiants chiffrés. La preuve lie l'authentification à la clé publique du
//! certificat TLS : un intermédiaire qui présenterait un autre certificat est détecté.

use alloc::{string::String, vec::Vec};

use sha2::{Digest, Sha256};

use crate::{
    Error, der,
    ntlm::{Credentials, Established, NtlmClient, Randomness},
    utf16le,
};

/// Version annoncée (Windows 10 et suivants parlent la 6).
pub const VERSION: i64 = 6;

const CLIENT_SERVER_MAGIC: &[u8] = b"CredSSP Client-To-Server Binding Hash\0";
const SERVER_CLIENT_MAGIC: &[u8] = b"CredSSP Server-To-Client Binding Hash\0";

#[derive(Debug, Default, PartialEq)]
pub struct TsRequest {
    pub version: i64,
    pub nego_token: Option<Vec<u8>>,
    pub auth_info: Option<Vec<u8>>,
    pub pub_key_auth: Option<Vec<u8>>,
    pub error_code: Option<u32>,
    pub client_nonce: Option<[u8; 32]>,
}

impl TsRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut body = der::explicit(0, &der::integer(self.version));
        if let Some(t) = &self.nego_token {
            let item = der::tlv(der::SEQUENCE, &der::explicit(0, &der::octet_string(t)));
            body.extend(der::explicit(1, &der::tlv(der::SEQUENCE, &item)));
        }
        if let Some(a) = &self.auth_info {
            body.extend(der::explicit(2, &der::octet_string(a)));
        }
        if let Some(p) = &self.pub_key_auth {
            body.extend(der::explicit(3, &der::octet_string(p)));
        }
        if let Some(e) = self.error_code {
            body.extend(der::explicit(4, &der::integer(e as i32 as i64)));
        }
        if let Some(n) = &self.client_nonce {
            body.extend(der::explicit(5, &der::octet_string(n)));
        }
        der::tlv(der::SEQUENCE, &body)
    }

    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let (mut fields, _) = der::expect(buf, der::SEQUENCE)?;
        let mut req = TsRequest::default();
        while !fields.is_empty() {
            let (tag, inner, rest) = der::read(fields)?;
            fields = rest;
            match tag {
                t if t == der::ctx(0) => {
                    req.version = der::read_integer(der::expect(inner, der::INTEGER)?.0)?
                }
                t if t == der::ctx(1) => {
                    // NegoData : SEQUENCE OF SEQUENCE { [0] OCTET STRING } ; seul le premier sert.
                    let (items, _) = der::expect(inner, der::SEQUENCE)?;
                    let (item, _) = der::expect(items, der::SEQUENCE)?;
                    let (tok, _) = der::expect(item, der::ctx(0))?;
                    req.nego_token = Some(der::expect(tok, der::OCTET_STRING)?.0.to_vec());
                }
                t if t == der::ctx(2) => {
                    req.auth_info = Some(der::expect(inner, der::OCTET_STRING)?.0.to_vec())
                }
                t if t == der::ctx(3) => {
                    req.pub_key_auth = Some(der::expect(inner, der::OCTET_STRING)?.0.to_vec())
                }
                t if t == der::ctx(4) => {
                    req.error_code = Some(der::read_integer(der::expect(inner, der::INTEGER)?.0)? as u32)
                }
                t if t == der::ctx(5) => {
                    let n = der::expect(inner, der::OCTET_STRING)?.0;
                    req.client_nonce = Some(n.try_into().map_err(|_| Error::Invalid("nonce CredSSP"))?);
                }
                _ => {}
            }
        }
        Ok(req)
    }
}

/// Longueur du prochain TSRequest dans un flux, une fois l'en-tête DER reçu.
pub fn frame_len(buf: &[u8]) -> Option<usize> {
    der::total_len(buf)
}

fn password_creds(c: &Credentials) -> Vec<u8> {
    let mut body = der::explicit(0, &der::octet_string(&utf16le(&c.domain)));
    body.extend(der::explicit(1, &der::octet_string(&utf16le(&c.username))));
    body.extend(der::explicit(2, &der::octet_string(&utf16le(&c.password))));
    let pw = der::tlv(der::SEQUENCE, &body);
    // TSCredentials : credType 1 = mot de passe.
    let mut ts = der::explicit(0, &der::integer(1));
    ts.extend(der::explicit(1, &der::octet_string(&pw)));
    der::tlv(der::SEQUENCE, &ts)
}

fn binding_hash(magic: &[u8], nonce: &[u8; 32], public_key: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(magic);
    h.update(nonce);
    h.update(public_key);
    h.finalize().to_vec()
}

enum State {
    Start(NtlmClient),
    WaitChallenge(NtlmClient),
    WaitPubKeyAuth(alloc::boxed::Box<Established>, i64),
    Done,
}

pub struct CredSspClient {
    state: State,
    creds: Credentials,
    /// `subjectPublicKey` du certificat TLS du serveur (contenu du BIT STRING).
    server_public_key: Vec<u8>,
    nonce: [u8; 32],
}

/// Résultat d'une étape.
#[derive(Debug, PartialEq)]
pub enum Step {
    /// Envoyer ces octets et attendre la réponse.
    Send(Vec<u8>),
    /// Envoyer ces octets : l'authentification est terminée côté client.
    Finish(Vec<u8>),
}

impl CredSspClient {
    pub fn new(
        creds: Credentials,
        server_public_key: Vec<u8>,
        target_host: &str,
        rand: Randomness,
        nonce: [u8; 32],
    ) -> Self {
        let spn = String::from("TERMSRV/") + target_host;
        let ntlm = NtlmClient::new(creds.clone(), rand, spn);
        Self { state: State::Start(ntlm), creds, server_public_key, nonce }
    }

    /// Premier message (NEGOTIATE NTLM).
    pub fn start(&mut self) -> Result<Vec<u8>, Error> {
        let State::Start(mut ntlm) = core::mem::replace(&mut self.state, State::Done) else {
            return Err(Error::Invalid("CredSSP déjà démarré"));
        };
        let token = ntlm.negotiate();
        self.state = State::WaitChallenge(ntlm);
        Ok(TsRequest { version: VERSION, nego_token: Some(token), ..Default::default() }.encode())
    }

    pub fn step(&mut self, input: &[u8]) -> Result<Step, Error> {
        let req = TsRequest::decode(input)?;
        if let Some(code) = req.error_code {
            self.state = State::Done;
            return Err(Error::Server(code));
        }
        match core::mem::replace(&mut self.state, State::Done) {
            State::WaitChallenge(ntlm) => {
                let version = req.version.clamp(2, VERSION);
                let challenge = req.nego_token.ok_or(Error::Invalid("CHALLENGE NTLM absent"))?;
                let (auth, mut est) = ntlm.authenticate(&challenge)?;
                let proof = if version >= 5 {
                    binding_hash(CLIENT_SERVER_MAGIC, &self.nonce, &self.server_public_key)
                } else {
                    self.server_public_key.clone()
                };
                let (sig, data) = est.client.seal(&proof);
                let out = TsRequest {
                    version,
                    nego_token: Some(auth),
                    pub_key_auth: Some([&sig[..], &data].concat()),
                    client_nonce: (version >= 5).then_some(self.nonce),
                    ..Default::default()
                };
                self.state = State::WaitPubKeyAuth(alloc::boxed::Box::new(est), version);
                Ok(Step::Send(out.encode()))
            }
            State::WaitPubKeyAuth(mut est, version) => {
                let sealed = req.pub_key_auth.ok_or(Error::Invalid("preuve de clé du serveur absente"))?;
                if sealed.len() < 16 {
                    return Err(Error::Truncated("pubKeyAuth"));
                }
                let got = est.server.unseal(&sealed[..16], &sealed[16..])?;
                let expected = if version >= 5 {
                    binding_hash(SERVER_CLIENT_MAGIC, &self.nonce, &self.server_public_key)
                } else {
                    // Versions 2 à 4 : la clé publique avec son premier octet incrémenté.
                    let mut k = self.server_public_key.clone();
                    if let Some(b) = k.first_mut() {
                        *b = b.wrapping_add(1);
                    }
                    k
                };
                if got != expected {
                    return Err(Error::Invalid("la clé publique TLS ne correspond pas (intermédiaire ?)"));
                }
                let (sig, data) = est.client.seal(&password_creds(&self.creds));
                let out =
                    TsRequest { version, auth_info: Some([&sig[..], &data].concat()), ..Default::default() };
                Ok(Step::Finish(out.encode()))
            }
            State::Start(_) | State::Done => Err(Error::Invalid("étape CredSSP hors séquence")),
        }
    }
}

/// Résultat de l'« Early User Authorization Result PDU » (HYBRID_EX, MS-RDPBCGR 2.2.10.2).
pub fn early_user_auth_result(buf: &[u8; 4]) -> Result<(), Error> {
    match u32::from_le_bytes(*buf) {
        0 => Ok(()),
        5 => Err(Error::AccessDenied),
        other => Err(Error::Server(other)),
    }
}

/// Clé publique (`subjectPublicKey`, sans l'octet de bits inutilisés) d'un certificat X.509
/// DER : c'est elle que CredSSP lie à l'authentification.
pub fn subject_public_key(cert_der: &[u8]) -> Result<Vec<u8>, Error> {
    let (cert, _) = der::expect(cert_der, der::SEQUENCE)?;
    let (mut tbs, _) = der::expect(cert, der::SEQUENCE)?;
    // version [0] facultative, puis serialNumber, signature, issuer, validity, subject.
    if tbs.first() == Some(&der::ctx(0)) {
        tbs = der::read(tbs)?.2;
    }
    for _ in 0..5 {
        tbs = der::read(tbs)?.2;
    }
    let (spki, _) = der::expect(tbs, der::SEQUENCE)?;
    let (_, after_alg) = der::expect(spki, der::SEQUENCE)?;
    let (bits, _) = der::expect(after_alg, 0x03)?;
    match bits.split_first() {
        Some((0, key)) => Ok(key.to_vec()),
        _ => Err(Error::Invalid("BIT STRING de clé publique invalide")),
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn tsrequest_roundtrip() {
        let req = TsRequest {
            version: 6,
            nego_token: Some(vec![1, 2, 3]),
            pub_key_auth: Some(vec![9; 200]),
            client_nonce: Some([4; 32]),
            ..Default::default()
        };
        let enc = req.encode();
        assert_eq!(frame_len(&enc), Some(enc.len()));
        assert_eq!(TsRequest::decode(&enc).unwrap(), req);
    }

    #[test]
    fn error_code_reported() {
        let enc = TsRequest { version: 6, error_code: Some(0xC000_006D), ..Default::default() }.encode();
        let mut c = CredSspClient::new(
            Credentials { username: "u".into(), domain: String::new(), password: "p".into() },
            vec![1, 2, 3],
            "pc",
            Randomness { client_challenge: [0; 8], exported_session_key: [0; 16], now_filetime: 0 },
            [0; 32],
        );
        c.start().unwrap();
        assert_eq!(c.step(&enc), Err(Error::Server(0xC000_006D)));
    }

    #[test]
    fn first_message_is_v6_negotiate() {
        let mut c = CredSspClient::new(
            Credentials { username: "u".into(), domain: String::new(), password: "p".into() },
            vec![],
            "pc",
            Randomness { client_challenge: [0; 8], exported_session_key: [0; 16], now_filetime: 0 },
            [0; 32],
        );
        let req = TsRequest::decode(&c.start().unwrap()).unwrap();
        assert_eq!(req.version, 6);
        assert_eq!(&req.nego_token.unwrap()[..8], b"NTLMSSP\0");
    }
}
