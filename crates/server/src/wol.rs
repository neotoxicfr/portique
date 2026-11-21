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

/// Durée maximale d'une commande de réveil, de l'ouverture du canal à sa fermeture.
const WAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Sortie gardée pour y chercher une erreur ; au-delà, la commande n'est pas celle attendue.
const MAX_OUTPUT: usize = 64 * 1024;

/// Lance la commande de réveil (`template`, `{mac}` remplacé) sur une session SSH déjà authentifiée et
/// vérifie son résultat.
pub async fn run_wake_command<H: russh::client::Handler>(
    session: &russh::client::Handle<H>,
    template: &str,
    mac: [u8; 6],
) -> anyhow::Result<()> {
    use anyhow::Context;
    use russh::ChannelMsg;

    // Échéance absolue (ouverture du canal, exec, sortie) : un hôte qui écrit un peu avant chaque délai
    // ne garde pas la requête ouverte sans fin.
    let run = async {
        let mut channel = session.channel_open_session().await.context("canal SSH")?;
        // La MAC est formatée par nous (hexadécimal et « : ») : rien d'injectable.
        let cmd = template.replace("{mac}", &format_mac(mac));
        channel.exec(true, cmd.as_bytes()).await.context("commande de réveil")?;
        let mut output = Vec::new();
        let mut status = None;
        // Jusqu'à la fermeture du canal : le code de sortie peut arriver après la fin des données (Eof).
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                    anyhow::ensure!(
                        output.len() + data.len() <= MAX_OUTPUT,
                        "sortie de la commande trop longue (plus de {MAX_OUTPUT} octets) : résultat ignoré"
                    );
                    output.extend_from_slice(&data);
                }
                ChannelMsg::Failure => anyhow::bail!("l'hôte refuse d'exécuter la commande"),
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                ChannelMsg::ExitSignal { signal_name, .. } => {
                    anyhow::bail!("la commande a été interrompue (signal {signal_name:?})")
                }
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        anyhow::Ok((status, String::from_utf8_lossy(&output).trim().to_owned()))
    };
    let (status, text) = tokio::time::timeout(WAKE_TIMEOUT, run)
        .await
        .map_err(|_| anyhow::anyhow!("résultat du réveil inconnu : l'hôte n'a pas fini à temps"))??;
    if status.is_none() {
        // Accepté comme avant (RFC 4254 : « SHOULD ») ; tracé pour vérifier ce que fait l'hôte réel.
        tracing::warn!("commande de réveil terminée sans code de sortie");
    }
    // Le code de sortie fait foi ; la sortie de l'hôte accompagne l'échec.
    anyhow::ensure!(status.unwrap_or(0) == 0, "la commande a échoué : {text}");
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
        assert!(validate_command("wakeonlan {mac}").is_ok());
        assert!(validate_command("wakeonlan").is_err(), "{{mac}} obligatoire");
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
