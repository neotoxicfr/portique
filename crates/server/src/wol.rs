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
    fn target_default_port() {
        assert_eq!(parse_target("192.168.1.255").unwrap().port(), 9);
        assert_eq!(parse_target("192.168.1.255:7").unwrap().port(), 7);
        assert!(parse_target("pc.local").is_none());
    }
}
