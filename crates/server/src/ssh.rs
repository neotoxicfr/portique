//! SSH vers les hôtes : clé ed25519 du service, chaîne de rebonds (ProxyJump), shell avec PTY.
//!
//! Contrairement au RDP, le serveur termine la session : il relaie le texte du terminal en clair
//! (sous WSS) entre le navigateur et l'hôte. La clé du service ouvre toutes les machines où elle est
//! posée : s'en servir exige la double authentification (voir `api::ssh`).

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Context;
use rand::Rng;
use russh::{
    Channel, client,
    keys::{
        HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate,
        ssh_key::{LineEnding, private::Ed25519Keypair},
    },
};

use crate::state::AppState;

/// Rebonds enchaînés au plus (cible comprise).
pub const MAX_HOPS: usize = 5;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const KEY_SETTING: &str = "ssh_key";

/// Clé du service : créée au premier besoin, chiffrée par la clé maîtresse dans `settings`.
pub async fn service_key(state: &AppState) -> anyhow::Result<PrivateKey> {
    let stored = || async {
        sqlx::query_scalar::<_, Vec<u8>>("SELECT value FROM settings WHERE key = ?")
            .bind(KEY_SETTING)
            .fetch_optional(&state.db)
            .await
    };
    if let Some(sealed) = stored().await? {
        let pem = state.vault.open("settings:ssh_key", &sealed)?;
        return PrivateKey::from_openssh(&pem).context("clé SSH du service illisible");
    }
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let mut key = PrivateKey::from(Ed25519Keypair::from_seed(&seed));
    key.set_comment("portique");
    let pem = key.to_openssh(LineEnding::LF)?;
    // Deux premières sessions simultanées : la première écrite gagne, l'autre la relit.
    sqlx::query("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)")
        .bind(KEY_SETTING)
        .bind(state.vault.seal("settings:ssh_key", pem.as_bytes()))
        .execute(&state.db)
        .await?;
    let sealed = stored().await?.context("clé SSH du service absente après création")?;
    PrivateKey::from_openssh(state.vault.open("settings:ssh_key", &sealed)?).context("clé SSH du service")
}

/// Ligne `authorized_keys` de la clé du service (sans options).
pub fn public_line(key: &PrivateKey) -> anyhow::Result<String> {
    Ok(key.public_key().to_openssh()?)
}

/// Un saut de la chaîne : la cible ou un rebond. `host` est l'adresse vue depuis le saut précédent.
pub struct Hop {
    pub id: i64,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Option<String>,
    /// Empreinte approuvée de la clé d'hôte (format OpenSSH `SHA256:…`).
    pub hostkey: Option<String>,
}

#[derive(Debug)]
pub enum OpenError {
    /// Clé d'hôte jamais approuvée : rien n'a été envoyé à ce saut (ni clé ni mot de passe).
    Unapproved {
        id: i64,
        name: String,
        fingerprint: String,
    },
    Failed(anyhow::Error),
}

impl From<anyhow::Error> for OpenError {
    fn from(e: anyhow::Error) -> Self {
        Self::Failed(e)
    }
}

pub struct Check {
    expected: Option<String>,
    seen: Arc<Mutex<Option<String>>>,
}

impl client::Handler for Check {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        // Clé d'hôte simple (OpenSSH, RouterOS) ; un certificat SSH n'est pas géré.
        let PublicKeyOrCertificate::PublicKey { key, .. } = key else { return Ok(false) };
        let fp = key.fingerprint(HashAlg::Sha256).to_string();
        let ok = self.expected.as_deref() == Some(fp.as_str());
        *self.seen.lock().unwrap() = Some(fp);
        Ok(ok)
    }
}

/// Session ouverte : les connexions de la chaîne (gardées en vie) et le canal du shell.
pub struct Opened {
    pub sessions: Vec<client::Handle<Check>>,
    pub channel: Channel<client::Msg>,
    /// Clés d'hôte approuvées à cette ouverture, à épingler : (hôte, empreinte).
    pub pinned: Vec<(i64, String)>,
}

/// Chaîne ouverte et authentifiée : les connexions, premier rebond d'abord, cible en dernier.
pub struct Chain {
    pub sessions: Vec<client::Handle<Check>>,
    /// Clés d'hôte approuvées à cette ouverture, à épingler : (hôte, empreinte).
    pub pinned: Vec<(i64, String)>,
}

/// Ouvre la chaîne `hops` (premier rebond d'abord, cible en dernier) puis un shell `cols`×`rows`.
/// `trust` : empreinte qu'un admin vient d'approuver pour l'hôte indiqué.
pub async fn open(
    hops: &[Hop],
    key: &PrivateKey,
    trust: Option<(i64, &str)>,
    cols: u16,
    rows: u16,
) -> Result<Opened, OpenError> {
    let Chain { sessions, pinned } = connect(hops, key, trust).await?;
    let last = sessions.last().context("aucun hôte")?;
    let channel = last.channel_open_session().await.context("ouverture du canal SSH")?;
    channel
        .request_pty(false, "xterm-256color", u32::from(cols), u32::from(rows), 0, 0, &[])
        .await
        .context("demande de terminal")?;
    channel.request_shell(false).await.context("lancement du shell")?;
    Ok(Opened { sessions, channel, pinned })
}

/// Ouvre et authentifie la chaîne `hops`, saut par saut.
pub async fn connect(hops: &[Hop], key: &PrivateKey, trust: Option<(i64, &str)>) -> Result<Chain, OpenError> {
    let key = Arc::new(key.clone());
    let config =
        Arc::new(client::Config { keepalive_interval: Some(Duration::from_secs(30)), ..Default::default() });
    let mut sessions: Vec<client::Handle<Check>> = Vec::new();
    let mut pinned = Vec::new();
    for hop in hops {
        let approved = trust.filter(|(id, _)| *id == hop.id).map(|(_, fp)| fp.to_owned());
        let expected = hop.hostkey.clone().or(approved);
        let seen = Arc::new(Mutex::new(None));
        let handler = Check { expected: expected.clone(), seen: seen.clone() };
        let connect = async {
            match sessions.last() {
                None => client::connect(config.clone(), (hop.host.as_str(), hop.port), handler).await,
                Some(prev) => {
                    let tunnel = prev
                        .channel_open_direct_tcpip(hop.host.as_str(), u32::from(hop.port), "127.0.0.1", 0)
                        .await?;
                    client::connect_stream(config.clone(), tunnel.into_stream(), handler).await
                }
            }
        };
        let mut session = match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                let got = seen.lock().unwrap().clone();
                return Err(match (expected, got) {
                    (None, Some(fingerprint)) => {
                        OpenError::Unapproved { id: hop.id, name: hop.name.clone(), fingerprint }
                    }
                    (Some(want), Some(got)) if want != got => OpenError::Failed(anyhow::anyhow!(
                        "la clé SSH de « {} » a changé (approuvée {want}, présentée {got})",
                        hop.name
                    )),
                    _ => OpenError::Failed(
                        anyhow::Error::from(e).context(format!("connexion à « {} »", hop.name)),
                    ),
                });
            }
            Err(_) => return Err(anyhow::anyhow!("« {} » ne répond pas (délai dépassé)", hop.name).into()),
        };
        if hop.hostkey.is_none()
            && let Some(fp) = seen.lock().unwrap().clone()
        {
            pinned.push((hop.id, fp));
        }
        let mut ok = session
            .authenticate_publickey(hop.user.as_str(), PrivateKeyWithHashAlg::new(key.clone(), None))
            .await
            .context("authentification par clé")?
            .success();
        if !ok && let Some(pw) = &hop.password {
            ok = session
                .authenticate_password(hop.user.as_str(), pw)
                .await
                .context("authentification")?
                .success();
        }
        if !ok {
            return Err(anyhow::anyhow!(
                "« {} » refuse l'utilisateur {} : clé du service absente de authorized_keys{}",
                hop.name,
                hop.user,
                if hop.password.is_some() { ", et mot de passe refusé" } else { "" }
            )
            .into());
        }
        sessions.push(session);
    }
    if sessions.is_empty() {
        return Err(anyhow::anyhow!("aucun hôte").into());
    }
    Ok(Chain { sessions, pinned })
}
