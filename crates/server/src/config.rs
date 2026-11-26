//! Configuration par variables d'environnement.
//!
//! Chaque secret accepte `VAR` ou `VAR_FILE` (convention des images officielles, compatible
//! Docker secrets) : le fichier est lu et son saut de ligne final retiré. Définir les deux
//! est une erreur, pour ne jamais deviner laquelle gagne.

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, bail};
use base64::Engine;
use ipnet::IpNet;
use portique_proto::AuthMode;

pub const PREFIX: &str = "PORTIQUE_";

#[derive(Clone)]
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
    /// Clés d'un tableau de bord (`Authorization: Bearer`) : lecture de l'état des machines, réveil.
    /// Absentes : les routes `/api/machine/*` répondent 404.
    pub status_key: Option<String>,
    pub wake_key: Option<String>,
}

// Debug à la main : la clé maîtresse et le mot de passe admin ne doivent jamais finir dans un journal.
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("listen", &self.listen)
            .field("data_dir", &self.data_dir)
            .field("static_dir", &self.static_dir)
            .field("public_url", &self.public_url)
            .field("master_key", &"<masquée>")
            .field("admin_password", &self.admin_password.as_ref().map(|_| "<masqué>"))
            .field("auth_mode", &self.auth_mode)
            .field("proxy", &self.proxy)
            .field("secure_cookies", &self.secure_cookies)
            .field("status_key", &self.status_key.as_ref().map(|_| "<masquée>"))
            .field("wake_key", &self.wake_key.as_ref().map(|_| "<masquée>"))
            .finish()
    }
}

/// Résultat d'une résolution de noms de proxys : instant et adresses.
pub type Resolved = (std::time::Instant, Vec<std::net::IpAddr>);

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub trusted: Vec<IpNet>,
    /// Proxys de confiance désignés par leur nom (ex. `traefik` sur un réseau Docker, dont
    /// l'adresse change à chaque redémarrage) ; résolus régulièrement (`refresh_trusted_hosts`).
    pub trusted_hosts: Vec<String>,
    /// Dernière résolution réussie des noms : (instant, adresses).
    pub resolved: std::sync::Arc<std::sync::RwLock<Option<Resolved>>>,
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

/// Lit `PORTIQUE_<name>` ou `PORTIQUE_<name>_FILE`.
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
            .context("PORTIQUE_LISTEN invalide")?;
        let data_dir = PathBuf::from(plain(env, "DATA_DIR").unwrap_or_else(|| "/data".into()));
        let static_dir = PathBuf::from(plain(env, "STATIC_DIR").unwrap_or_else(|| "/app/web".into()));
        let public_url = plain(env, "PUBLIC_URL").context(
            "PORTIQUE_PUBLIC_URL manquant (ex. https://rdp.example.com), requis pour les passkeys",
        )?;
        let public_url = url::Url::parse(&public_url).context("PORTIQUE_PUBLIC_URL invalide")?;

        let master_key = secret(env, "MASTER_KEY")?
            .context("PORTIQUE_MASTER_KEY(_FILE) manquant : 32 octets en base64 (openssl rand -base64 32)")?;
        let master_key = decode_key(&master_key)?;

        let auth_mode = match plain(env, "AUTH_MODE").as_deref() {
            None | Some("builtin") => AuthMode::Builtin,
            Some("proxy") => AuthMode::Proxy,
            Some(other) => bail!("PORTIQUE_AUTH_MODE inconnu : {other} (builtin ou proxy)"),
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
            bail!("PORTIQUE_AUTH_MODE=proxy exige PORTIQUE_TRUSTED_PROXIES (IP, CIDR ou nom du proxy)");
        }

        let status_key = machine_key(env, "STATUS_KEY")?;
        let wake_key = machine_key(env, "WAKE_KEY")?;
        if status_key.is_some() && status_key == wake_key {
            bail!("PORTIQUE_STATUS_KEY et PORTIQUE_WAKE_KEY doivent être différentes");
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
            status_key,
            wake_key,
        })
    }
}

/// Clé de tableau de bord : 32 caractères au moins (ex. `openssl rand -hex 32`), sans espace.
fn machine_key(env: &dyn Env, name: &str) -> anyhow::Result<Option<String>> {
    let key = secret(env, name)?;
    if let Some(k) = &key
        && (k.len() < 32 || k.chars().any(char::is_whitespace))
    {
        bail!("{PREFIX}{name} : 32 caractères au moins, sans espace (openssl rand -hex 32)");
    }
    Ok(key)
}

/// Fréquence de résolution des proxys désignés par nom, et durée de validité d'un résultat.
pub const RESOLVE_EVERY: std::time::Duration = std::time::Duration::from_secs(10);
pub const RESOLVED_TTL: std::time::Duration = std::time::Duration::from_secs(60);

fn is_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && s.chars().any(|c| c.is_ascii_alphabetic())
}

impl ProxyConfig {
    /// Adresse d'un proxy de confiance (CIDR configurés ou noms résolus récemment) ?
    pub fn is_trusted(&self, ip: &std::net::IpAddr) -> bool {
        // Écoute double pile (`[::]`) : un proxy IPv4 arrive en `::ffff:a.b.c.d`. On compare les deux
        // formes : un CIDR IPv4 vise la forme canonique, un CIDR `::ffff:…` l'adresse telle quelle.
        let ips = [*ip, ip.to_canonical()];
        if self.trusted.iter().any(|n| ips.iter().any(|ip| n.contains(ip))) {
            return true;
        }
        // Une adresse résolue n'est fiable que peu de temps : un conteneur peut hériter de
        // l'ancienne adresse du proxy après son redémarrage. Au-delà, on refuse (fail closed).
        self.resolved
            .read()
            .unwrap()
            .as_ref()
            .is_some_and(|(at, known)| at.elapsed() < RESOLVED_TTL && ips.iter().any(|ip| known.contains(ip)))
    }

    /// Résout les noms de proxys (au démarrage puis toutes les `RESOLVE_EVERY`). Une résolution
    /// ratée laisse expirer les adresses connues au bout de `RESOLVED_TTL`.
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
            if cur.as_ref().map(|(_, old)| old) != Some(&ips) {
                tracing::info!(?ips, "proxys de confiance résolus");
            }
            *cur = Some((std::time::Instant::now(), ips));
        }
    }
}

fn decode_key(b64: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .context("PORTIQUE_MASTER_KEY n'est pas du base64")?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("PORTIQUE_MASTER_KEY fait {} octets, 32 attendus", v.len()))
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
        let dir = std::env::temp_dir().join(format!("portique-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pw");
        std::fs::write(&path, "s3cret\n").unwrap();
        let p = path.to_str().unwrap();
        let env = [("PORTIQUE_ADMIN_PASSWORD_FILE", p)];
        assert_eq!(secret(&env, "ADMIN_PASSWORD").unwrap().as_deref(), Some("s3cret"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn secret_both_defined_is_error() {
        let env = [("PORTIQUE_X", "a"), ("PORTIQUE_X_FILE", "/nope")];
        assert!(secret(&env, "X").is_err());
    }

    #[test]
    fn proxy_mode_requires_trusted() {
        let env = [
            ("PORTIQUE_PUBLIC_URL", "https://rdp.example.com"),
            ("PORTIQUE_MASTER_KEY", KEY),
            ("PORTIQUE_AUTH_MODE", "proxy"),
        ];
        assert!(Config::from_env(&env).is_err());
    }

    #[test]
    fn machine_keys_long_and_distinct() {
        let long = "0123456789abcdef0123456789abcdef";
        let with = |status: &'static str, wake: &'static str| {
            let env = [
                ("PORTIQUE_PUBLIC_URL", "https://rdp.example.com"),
                ("PORTIQUE_MASTER_KEY", KEY),
                ("PORTIQUE_STATUS_KEY", status),
                ("PORTIQUE_WAKE_KEY", wake),
            ];
            Config::from_env(&env)
        };
        assert!(with("trop-courte", "fedcba9876543210fedcba9876543210").is_err());
        assert!(with("0123456789abcdef 123456789abcdef0", "fedcba9876543210fedcba9876543210").is_err());
        assert!(with(long, long).is_err(), "une même clé pour lire et réveiller");
        let c = with(long, "fedcba9876543210fedcba9876543210").unwrap();
        assert_eq!((c.status_key.as_deref(), c.wake_key.is_some()), (Some(long), true));
        assert!(!format!("{c:?}").contains(long), "clé dans le Debug");
    }

    #[test]
    fn full_config() {
        let env = [
            ("PORTIQUE_PUBLIC_URL", "https://rdp.example.com"),
            ("PORTIQUE_MASTER_KEY", KEY),
            ("PORTIQUE_AUTH_MODE", "proxy"),
            ("PORTIQUE_TRUSTED_PROXIES", "172.16.0.0/12, 10.0.0.1, traefik"),
            ("PORTIQUE_PROXY_ADMIN_GROUP", "admins"),
        ];
        let c = Config::from_env(&env).unwrap();
        assert_eq!(c.auth_mode, AuthMode::Proxy);
        assert_eq!(c.proxy.trusted.len(), 2);
        assert_eq!(c.proxy.trusted_hosts, ["traefik"]);
        assert_eq!(c.master_key[31], 31);
        assert!(c.secure_cookies);
    }

    #[test]
    fn resolved_proxies_expire() {
        let env = [
            ("PORTIQUE_PUBLIC_URL", "https://rdp.example.com"),
            ("PORTIQUE_MASTER_KEY", KEY),
            ("PORTIQUE_AUTH_MODE", "proxy"),
            ("PORTIQUE_TRUSTED_PROXIES", "traefik"),
        ];
        let c = Config::from_env(&env).unwrap();
        let ip: std::net::IpAddr = "172.20.0.45".parse().unwrap();
        assert!(!c.proxy.is_trusted(&ip), "rien de résolu : refus");
        *c.proxy.resolved.write().unwrap() = Some((std::time::Instant::now(), vec![ip]));
        assert!(c.proxy.is_trusted(&ip));
        let old = std::time::Instant::now() - RESOLVED_TTL - std::time::Duration::from_secs(1);
        *c.proxy.resolved.write().unwrap() = Some((old, vec![ip]));
        assert!(!c.proxy.is_trusted(&ip), "résolution périmée : refus");
    }

    #[test]
    fn mapped_ipv4_proxy_is_trusted_and_debug_hides_secrets() {
        let env = [
            ("PORTIQUE_PUBLIC_URL", "https://rdp.example.com"),
            ("PORTIQUE_MASTER_KEY", KEY),
            ("PORTIQUE_ADMIN_PASSWORD", "admin-password-123"),
            ("PORTIQUE_AUTH_MODE", "proxy"),
            ("PORTIQUE_TRUSTED_PROXIES", "172.16.0.0/12, ::ffff:192.0.2.9/128, traefik"),
        ];
        let c = Config::from_env(&env).unwrap();
        let mapped: std::net::IpAddr = "::ffff:172.18.0.2".parse().unwrap();
        assert!(c.proxy.is_trusted(&mapped), "CIDR IPv4");
        assert!(c.proxy.is_trusted(&"::ffff:192.0.2.9".parse().unwrap()), "CIDR IPv6 mappé");
        assert!(!c.proxy.is_trusted(&"::ffff:192.0.2.10".parse().unwrap()));
        *c.proxy.resolved.write().unwrap() =
            Some((std::time::Instant::now(), vec!["192.0.2.7".parse().unwrap()]));
        assert!(c.proxy.is_trusted(&"::ffff:192.0.2.7".parse().unwrap()), "nom résolu");
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("admin-password-123") && !dbg.contains("29, 30, 31"), "{dbg}");
    }

    #[test]
    fn short_key_rejected() {
        let env = [("PORTIQUE_PUBLIC_URL", "https://rdp.example.com"), ("PORTIQUE_MASTER_KEY", "AAAA")];
        assert!(Config::from_env(&env).is_err());
    }
}
