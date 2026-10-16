//! Wake-on-LAN : paquet magique UDP envoyé directement depuis le conteneur.

use std::net::SocketAddr;

pub const DEFAULT_TARGET: &str = "255.255.255.255:9";

pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let sep_ok = s.chars().all(|c| c.is_ascii_hexdigit() || ":-. ".contains(c));
    if hex.len() != 12 || !sep_ok {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, b) in mac.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(mac)
}

pub fn format_mac(mac: [u8; 6]) -> String {
    mac.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// `ip` seul → port 9.
pub fn parse_target(s: &str) -> Option<SocketAddr> {
    s.parse::<SocketAddr>()
        .ok()
        .or_else(|| s.parse::<std::net::IpAddr>().ok().map(|ip| SocketAddr::new(ip, 9)))
}

pub fn magic_packet(mac: [u8; 6]) -> [u8; 102] {
    let mut p = [0xFFu8; 102];
    for chunk in p[6..].as_chunks_mut::<6>().0 {
        chunk.copy_from_slice(&mac);
    }
    p
}

pub async fn send(mac: [u8; 6], target: SocketAddr) -> std::io::Result<()> {
    let bind: SocketAddr = if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap();
    let sock = tokio::net::UdpSocket::bind(bind).await?;
    sock.set_broadcast(true)?;
    let packet = magic_packet(mac);
    // Trois envois : l'UDP peut se perdre et un paquet magique en double est sans effet.
    for _ in 0..3 {
        sock.send_to(&packet, target).await?;
    }
    Ok(())
}

/// Valide un gabarit de commande de réveil : une ligne, `{mac}` présent, longueur raisonnable.
pub fn validate_command(template: &str) -> Result<(), &'static str> {
    if template.trim().is_empty() || template.len() > 500 {
        return Err("commande de réveil vide ou trop longue");
    }
    if template.contains(['\n', '\r', '\0']) {
        return Err("commande de réveil sur une seule ligne");
    }
    if !template.contains("{mac}") {
        return Err("la commande de réveil doit contenir {mac}");
    }
    Ok(())
}

/// Commande par défaut pour un routeur MikroTik (RouterOS).
pub const MIKROTIK_COMMAND: &str = "/tool wol interface=ether1 mac={mac}";

/// Clé d'hôte SSH jamais approuvée : la connexion s'est arrêtée avant l'authentification.
#[derive(Debug)]
pub struct UnapprovedHostKey(pub String);

impl std::fmt::Display for UnapprovedHostKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "clé SSH de l'hôte à approuver : {}", self.0)
    }
}

impl std::error::Error for UnapprovedHostKey {}

/// Réveil « par commande » : SSH (mot de passe) vers `host`, puis `template` où `{mac}` est remplacé
/// par l'adresse MAC. `pinned` : empreinte SHA-256 approuvée de la clé d'hôte. Sans elle, la
/// connexion s'arrête AVANT l'authentification (aucun mot de passe ne part) et renvoie
/// `UnapprovedHostKey` avec la clé présentée, à faire approuver par un admin.
pub async fn ssh_command(
    host: &str,
    user: &str,
    password: &str,
    template: &str,
    mac: [u8; 6],
    pinned: Option<&str>,
) -> anyhow::Result<()> {
    use std::sync::{Arc, Mutex};

    use anyhow::Context;
    use russh::{ChannelMsg, client};

    validate_command(template).map_err(|e| anyhow::anyhow!(e))?;

    struct Check {
        pinned: Option<String>,
        seen: Arc<Mutex<Option<String>>>,
    }
    impl client::Handler for Check {
        type Error = russh::Error;
        async fn check_server_key(
            &mut self,
            key: &russh::keys::PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            // Clé d'hôte simple attendue (RouterOS, OpenSSH) ; un certificat SSH n'est pas géré.
            let russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } = key else { return Ok(false) };
            let fp = key.fingerprint(russh::keys::HashAlg::Sha256).to_string();
            let ok = self.pinned.as_deref() == Some(fp.as_str());
            *self.seen.lock().unwrap() = Some(fp);
            Ok(ok)
        }
    }

    let seen = Arc::new(Mutex::new(None));
    let handler = Check { pinned: pinned.map(str::to_owned), seen: seen.clone() };
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(10)),
        ..Default::default()
    });
    let connect = client::connect(config, (host, 22), handler);
    let mut session = match tokio::time::timeout(std::time::Duration::from_secs(10), connect).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let fp = seen.lock().unwrap().clone();
            match (pinned, fp) {
                (None, Some(got)) => return Err(UnapprovedHostKey(got).into()),
                (Some(expected), Some(got)) if expected != got => {
                    anyhow::bail!("la clé SSH de l'hôte a changé (attendue {expected}, reçue {got})")
                }
                _ => return Err(e).context("connexion SSH"),
            }
        }
        Err(_) => anyhow::bail!("l'hôte SSH ne répond pas (délai dépassé)"),
    };
    let auth = session.authenticate_password(user, password).await.context("authentification SSH")?;
    anyhow::ensure!(auth.success(), "identifiants SSH refusés");
    let mut channel = session.channel_open_session().await.context("canal SSH")?;
    // La MAC est formatée par nous (hexadécimal et « : ») : rien d'injectable.
    let cmd = template.replace("{mac}", &format_mac(mac));
    channel.exec(true, cmd.as_bytes()).await.context("commande de réveil")?;
    let mut output = Vec::new();
    let mut status = None;
    while let Some(msg) = tokio::time::timeout(std::time::Duration::from_secs(10), channel.wait())
        .await
        .context("réponse de l'hôte")?
    {
        match msg {
            ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                output.extend_from_slice(&data)
            }
            ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
            ChannelMsg::Eof | ChannelMsg::Close => break,
            _ => {}
        }
    }
    let _ = session.disconnect(russh::Disconnect::ByApplication, "", "fr").await;
    let text = String::from_utf8_lossy(&output).trim().to_owned();
    // Code de sortie non nul, ou erreur RouterOS écrite dans la sortie : RouterOS répond 0 même quand
    // la commande échoue.
    let failed = ["failure:", "bad command", "syntax error", "expected end of command"]
        .iter()
        .any(|m| text.contains(m));
    anyhow::ensure!(status.unwrap_or(0) == 0 && !failed, "la commande a échoué : {text}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_formats() {
        let m = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        assert_eq!(parse_mac("00:1a:2b:3c:4d:5e"), Some(m));
        assert_eq!(parse_mac("00-1A-2B-3C-4D-5E"), Some(m));
        assert_eq!(parse_mac("001a.2b3c.4d5e"), Some(m));
        assert_eq!(parse_mac("00:1a:2b:3c:4d"), None);
        assert_eq!(parse_mac("zz:1a:2b:3c:4d:5e"), None);
        assert_eq!(format_mac(m), "00:1A:2B:3C:4D:5E");
    }

    #[test]
    fn packet_layout() {
        let p = magic_packet([1, 2, 3, 4, 5, 6]);
        assert_eq!(&p[..6], &[0xFF; 6]);
        assert_eq!(&p[96..], &[1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn command_template() {
        assert!(validate_command(MIKROTIK_COMMAND).is_ok());
        assert!(validate_command("/tool wol interface=ether1").is_err(), "{{mac}} obligatoire");
        assert!(validate_command("a {mac}\n/system reboot").is_err(), "une seule ligne");
        assert!(validate_command("").is_err());
    }

    #[test]
    fn target_default_port() {
        assert_eq!(parse_target("192.168.1.255").unwrap().port(), 9);
        assert_eq!(parse_target("192.168.1.255:7").unwrap().port(), 7);
        assert!(parse_target("pc.local").is_none());
    }
}
