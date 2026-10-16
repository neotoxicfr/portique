//! Configuration par variables d'environnement.
//!
//! Chaque secret accepte `VAR` ou `VAR_FILE` (convention des images officielles, compatible
//! Docker secrets) : le fichier est lu et son saut de ligne final retiré. Définir les deux
//! est une erreur, pour ne jamais deviner laquelle gagne.

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, bail};
use base64::Engine;
use ipnet::IpNet;
use yawrdp_proto::AuthMode;

pub const PREFIX: &str = "YAWRDP_";

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub static_dir: PathBuf,
    pub public_url: url::Url,
    pub master_key: [u8; 32],
    pub admin_password: Option<String>,
    pub auth_mode: AuthMode,
    pub proxy: ProxyConfig,
    /// Cookies `Secure` : désactivable seulement pour du développement en HTTP local.
    pub secure_cookies: bool,
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub trusted: Vec<IpNet>,
    /// Proxys de confiance désignés par leur nom (ex. `traefik` sur un réseau Docker, dont
    /// l'adresse change à chaque redémarrage) ; résolus régulièrement (`refresh_trusted_hosts`).
    pub trusted_hosts: Vec<String>,
    pub resolved: std::sync::Arc<std::sync::RwLock<Vec<std::net::IpAddr>>>,
    pub user_header: String,
    pub groups_header: String,
    pub admin_group: Option<String>,
}

/// Source des variables : l'environnement réel en prod, une table en test.
pub trait Env {
    fn var(&self, key: &str) -> Option<String>;
}

pub struct ProcessEnv;

impl Env for ProcessEnv {
    fn var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

impl<const N: usize> Env for [(&str, &str); N] {
    fn var(&self, key: &str) -> Option<String> {
        self.iter().find(|(k, _)| *k == key).map(|(_, v)| v.to_string())
    }
}

fn plain(env: &dyn Env, name: &str) -> Option<String> {
    env.var(&format!("{PREFIX}{name}")).filter(|v| !v.is_empty())
}

/// Lit `YAWRDP_<name>` ou `YAWRDP_<name>_FILE`.
pub fn secret(env: &dyn Env, name: &str) -> anyhow::Result<Option<String>> {
    let direct = plain(env, name);
    let file = plain(env, &format!("{name}_FILE"));
    match (direct, file) {
        (Some(_), Some(_)) => bail!("{PREFIX}{name} et {PREFIX}{name}_FILE sont définis tous les deux"),
        (Some(v), None) => Ok(Some(v)),
        (None, Some(path)) => {
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("lecture de {PREFIX}{name}_FILE ({path})"))?;
            let v = raw.strip_suffix('\n').unwrap_or(&raw);
            let v = v.strip_suffix('\r').unwrap_or(v);
            Ok(Some(v.to_owned()).filter(|v| !v.is_empty()))
        }
        (None, None) => Ok(None),
    }
}

impl Config {
    pub fn from_env(env: &dyn Env) -> anyhow::Result<Self> {
        let listen = plain(env, "LISTEN")
            .unwrap_or_else(|| "0.0.0.0:8080".into())
            .parse()
            .context("YAWRDP_LISTEN invalide")?;
        let data_dir = PathBuf::from(plain(env, "DATA_DIR").unwrap_or_else(|| "/data".into()));
        let static_dir = PathBuf::from(plain(env, "STATIC_DIR").unwrap_or_else(|| "/app/web".into()));
        let public_url = plain(env, "PUBLIC_URL")
            .context("YAWRDP_PUBLIC_URL manquant (ex. https://rdp.example.com), requis pour les passkeys")?;
        let public_url = url::Url::parse(&public_url).context("YAWRDP_PUBLIC_URL invalide")?;

        let master_key = secret(env, "MASTER_KEY")?
            .context("YAWRDP_MASTER_KEY(_FILE) manquant : 32 octets en base64 (openssl rand -base64 32)")?;
        let master_key = decode_key(&master_key)?;

        let auth_mode = match plain(env, "AUTH_MODE").as_deref() {
            None | Some("builtin") => AuthMode::Builtin,
            Some("proxy") => AuthMode::Proxy,
            Some(other) => bail!("YAWRDP_AUTH_MODE inconnu : {other} (builtin ou proxy)"),
        };

        let (mut trusted, mut trusted_hosts) = (Vec::new(), Vec::new());
        for item in
            plain(env, "TRUSTED_PROXIES").unwrap_or_default().split([',', ' ']).filter(|s| !s.is_empty())
        {
            match parse_net(item) {
                Ok(n) => trusted.push(n),
                Err(_) if is_hostname(item) => trusted_hosts.push(item.to_owned()),
                Err(e) => return Err(e),
            }
        }
        if auth_mode == AuthMode::Proxy && trusted.is_empty() && trusted_hosts.is_empty() {
            bail!("YAWRDP_AUTH_MODE=proxy exige YAWRDP_TRUSTED_PROXIES (IP, CIDR ou nom du proxy)");
        }

        Ok(Self {
            listen,
            data_dir,
            static_dir,
            public_url,
            master_key,
            admin_password: secret(env, "ADMIN_PASSWORD")?,
            auth_mode,
            proxy: ProxyConfig {
                trusted,
                trusted_hosts,
                resolved: Default::default(),
                user_header: plain(env, "PROXY_USER_HEADER").unwrap_or_else(|| "Remote-User".into()),
                groups_header: plain(env, "PROXY_GROUPS_HEADER").unwrap_or_else(|| "Remote-Groups".into()),
                admin_group: plain(env, "PROXY_ADMIN_GROUP"),
            },
            secure_cookies: plain(env, "INSECURE_COOKIES").as_deref() != Some("1"),
        })
    }
}

fn is_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && s.chars().any(|c| c.is_ascii_alphabetic())
}

impl ProxyConfig {
    /// Adresse d'un proxy de confiance (CIDR configurés ou noms résolus) ?
    pub fn is_trusted(&self, ip: &std::net::IpAddr) -> bool {
        self.trusted.iter().any(|n| n.contains(ip)) || self.resolved.read().unwrap().contains(ip)
    }

    /// Résout les noms de proxys (au démarrage puis périodiquement). Une résolution ratée garde
    /// les adresses connues : une panne DNS passagère ne coupe pas l'accès.
    pub async fn refresh_trusted_hosts(&self) {
        if self.trusted_hosts.is_empty() {
            return;
        }
        let mut ips = Vec::new();
        for host in &self.trusted_hosts {
            match tokio::net::lookup_host((host.as_str(), 0)).await {
                Ok(addrs) => ips.extend(addrs.map(|a| a.ip())),
                Err(e) => tracing::warn!(host, "résolution du proxy de confiance impossible : {e}"),
            }
        }
        if !ips.is_empty() {
            ips.sort();
            ips.dedup();
            let mut cur = self.resolved.write().unwrap();
            if *cur != ips {
                tracing::info!(?ips, "proxys de confiance résolus");
                *cur = ips;
            }
        }
    }
}

fn decode_key(b64: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .context("YAWRDP_MASTER_KEY n'est pas du base64")?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("YAWRDP_MASTER_KEY fait {} octets, 32 attendus", v.len()))
}

fn parse_net(s: &str) -> anyhow::Result<IpNet> {
    s.parse::<IpNet>()
        .or_else(|_| s.parse::<std::net::IpAddr>().map(IpNet::from))
        .with_context(|| format!("proxy de confiance invalide : {s}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    #[test]
    fn secret_from_file_strips_newline() {
        let dir = std::env::temp_dir().join(format!("yawrdp-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pw");
        std::fs::write(&path, "s3cret\n").unwrap();
        let p = path.to_str().unwrap();
        let env = [("YAWRDP_ADMIN_PASSWORD_FILE", p)];
        assert_eq!(secret(&env, "ADMIN_PASSWORD").unwrap().as_deref(), Some("s3cret"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn secret_both_defined_is_error() {
        let env = [("YAWRDP_X", "a"), ("YAWRDP_X_FILE", "/nope")];
        assert!(secret(&env, "X").is_err());
    }

    #[test]
    fn proxy_mode_requires_trusted() {
        let env = [
            ("YAWRDP_PUBLIC_URL", "https://rdp.example.com"),
            ("YAWRDP_MASTER_KEY", KEY),
            ("YAWRDP_AUTH_MODE", "proxy"),
        ];
        assert!(Config::from_env(&env).is_err());
    }

    #[test]
    fn full_config() {
        let env = [
            ("YAWRDP_PUBLIC_URL", "https://rdp.example.com"),
            ("YAWRDP_MASTER_KEY", KEY),
            ("YAWRDP_AUTH_MODE", "proxy"),
            ("YAWRDP_TRUSTED_PROXIES", "172.16.0.0/12, 10.0.0.1, traefik"),
            ("YAWRDP_PROXY_ADMIN_GROUP", "admins"),
        ];
        let c = Config::from_env(&env).unwrap();
        assert_eq!(c.auth_mode, AuthMode::Proxy);
        assert_eq!(c.proxy.trusted.len(), 2);
        assert_eq!(c.proxy.trusted_hosts, ["traefik"]);
        assert_eq!(c.master_key[31], 31);
        assert!(c.secure_cookies);
    }

    #[test]
    fn short_key_rejected() {
        let env = [("YAWRDP_PUBLIC_URL", "https://rdp.example.com"), ("YAWRDP_MASTER_KEY", "AAAA")];
        assert!(Config::from_env(&env).is_err());
    }
}
