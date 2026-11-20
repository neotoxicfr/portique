//! Chiffrement des secrets au repos et jetons de session.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::Rng;
use sha2::{Digest, Sha256};

const NONCE_LEN: usize = 24;

/// Chiffre les secrets stockés en base (mots de passe Windows, graines TOTP).
///
/// Format : nonce (24 octets) || texte chiffré + tag. Le contexte (`aad`) lie le secret
/// à sa ligne : on ne peut pas recopier le mot de passe chiffré d'une connexion sur une autre.
#[derive(Clone)]
pub struct Vault {
    cipher: XChaCha20Poly1305,
}

impl Vault {
    pub fn new(key: &[u8; 32]) -> Self {
        Self { cipher: XChaCha20Poly1305::new(key.into()) }
    }

    pub fn seal(&self, aad: &str, plaintext: &[u8]) -> Vec<u8> {
        let nonce: [u8; NONCE_LEN] = random_bytes();
        let ct = self
            .cipher
            .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad: aad.as_bytes() })
            .expect("XChaCha20-Poly1305 ne peut pas échouer au chiffrement");
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    pub fn open(&self, aad: &str, sealed: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(sealed.len() > NONCE_LEN, "secret chiffré tronqué");
        let (nonce, ct) = sealed.split_at(NONCE_LEN);
        let nonce = XNonce::try_from(nonce).expect("longueur vérifiée");
        self.cipher
            .decrypt(&nonce, Payload { msg: ct, aad: aad.as_bytes() })
            .map_err(|_| anyhow::anyhow!("déchiffrement impossible (clé maîtresse changée ?)"))
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rng().fill_bytes(&mut b);
    b
}

/// Nouveau jeton de session : (valeur du cookie, empreinte stockée en base).
pub fn new_session_token() -> (String, Vec<u8>) {
    let token = hex::encode(random_bytes::<32>());
    let hash = token_hash(&token);
    (token, hash)
}

pub fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_aad_binding() {
        let v = Vault::new(&[7; 32]);
        let sealed = v.seal("connection:1", b"hunter2");
        assert_eq!(v.open("connection:1", &sealed).unwrap(), b"hunter2");
        assert!(v.open("connection:2", &sealed).is_err());
        assert!(Vault::new(&[8; 32]).open("connection:1", &sealed).is_err());
    }

    #[test]
    fn nonces_differ() {
        let v = Vault::new(&[7; 32]);
        assert_ne!(v.seal("a", b"x"), v.seal("a", b"x"));
    }
}
