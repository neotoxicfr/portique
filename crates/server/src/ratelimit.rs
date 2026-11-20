//! Limitation des tentatives de connexion, en mémoire.
//!
//! Clé = (IP, identifiant) et IP seule : on bloque à la fois l'acharnement sur un compte
//! et le balayage de comptes depuis une même adresse. Fenêtre glissante simple.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const WINDOW: Duration = Duration::from_secs(15 * 60);
const MAX_PER_ACCOUNT: usize = 5;
const MAX_PER_IP: usize = 20;

#[derive(Default)]
pub struct LoginLimiter {
    /// Clé → tentatives de la fenêtre : instant et numéro de réservation.
    failures: Mutex<HashMap<String, Vec<(Instant, u64)>>>,
    next: AtomicU64,
}

/// Réservation d'une tentative : `succeeded` ou `release` rendent à l'IP la place de CETTE tentative,
/// même si un succès concurrent du même compte a déjà effacé les entrées du compte.
#[derive(Debug, Clone, Copy)]
pub struct Ticket(u64);

/// Adresse de comptage : une machine IPv6 dispose de tout un /64, on compte donc par /64.
fn ip_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
        v4 => v4.to_string(),
    }
}

impl LoginLimiter {
    fn keys(ip: IpAddr, username: &str) -> [(String, usize); 2] {
        let ip = ip_key(ip);
        [(format!("{ip}|{}", username.to_lowercase()), MAX_PER_ACCOUNT), (ip, MAX_PER_IP)]
    }

    /// Réserve une tentative : plafonds vérifiés et tentative comptée sous le même verrou, avant tout travail
    /// coûteux (base, Argon2). Compter seulement après coup laisserait des requêtes parallèles passer toutes
    /// avant le premier échec noté. Une tentative qui échoue reste comptée.
    pub fn reserve(&self, ip: IpAddr, username: &str) -> Option<Ticket> {
        let now = Instant::now();
        let mut map = self.failures.lock().unwrap();
        let keys = Self::keys(ip, username);
        let allowed = keys.iter().all(|(k, max)| {
            map.get_mut(k).is_none_or(|v| {
                v.retain(|(t, _)| now.duration_since(*t) < WINDOW);
                v.len() < *max
            })
        });
        let ticket = allowed.then(|| Ticket(self.next.fetch_add(1, Ordering::Relaxed)));
        if let Some(Ticket(n)) = ticket {
            for (k, _) in keys {
                map.entry(k).or_default().push((now, n));
            }
        }
        // Évite une croissance sans fin sous attaque : purge des entrées expirées.
        if map.len() > 10_000 {
            map.retain(|_, v| v.iter().any(|(t, _)| now.duration_since(*t) < WINDOW));
        }
        ticket
    }

    /// Tentative réussie : échecs du compte effacés, place de cette réservation rendue à l'IP (et à elle
    /// seule : un succès ne rend jamais la place d'une autre tentative).
    pub fn succeeded(&self, ip: IpAddr, username: &str, Ticket(n): Ticket) {
        let [(account, _), (ip, _)] = Self::keys(ip, username);
        let mut map = self.failures.lock().unwrap();
        map.remove(&account);
        if let Some(v) = map.get_mut(&ip) {
            v.retain(|(_, id)| *id != n);
        }
    }

    /// Réservation rendue sans verdict (mot de passe bon, code TOTP encore à saisir).
    pub fn release(&self, ip: IpAddr, username: &str, Ticket(n): Ticket) {
        let mut map = self.failures.lock().unwrap();
        for (k, _) in Self::keys(ip, username) {
            if let Some(v) = map.get_mut(&k) {
                v.retain(|(_, id)| *id != n);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_five_per_account() {
        let l = LoginLimiter::default();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        // Tentatives en vol, aucune encore conclue : la sixième est déjà refusée.
        let tickets: Vec<_> = (0..MAX_PER_ACCOUNT).map(|_| l.reserve(ip, "alice").unwrap()).collect();
        assert!(l.reserve(ip, "Alice").is_none());
        assert!(l.reserve(ip, "autre").is_some());
        l.succeeded(ip, "alice", tickets[0]);
        assert!(l.reserve(ip, "alice").is_some());
    }

    #[test]
    fn ipv6_counts_per_64_and_foreign_ticket_refunds_nothing() {
        let l = LoginLimiter::default();
        for i in 0..MAX_PER_IP {
            let ip: IpAddr = format!("2001:db8:1:2::{:x}", i + 1).parse().unwrap();
            assert!(l.reserve(ip, &format!("u{i}")).is_some());
        }
        let other: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        // Une réussite réservée ailleurs ne rend aucune place à ce /64.
        let elsewhere = l.reserve("2001:db8:1:3::1".parse().unwrap(), "u0").unwrap();
        l.succeeded(other, "u0", elsewhere);
        assert!(l.reserve(other, "nouveau").is_none(), "même /64 : plafond atteint");
        assert!(l.reserve("2001:db8:1:3::1".parse().unwrap(), "nouveau").is_some(), "autre /64 : libre");
    }

    #[test]
    fn released_and_successful_attempts_do_not_count() {
        let l = LoginLimiter::default();
        let ip: IpAddr = "192.0.2.2".parse().unwrap();
        for i in 0..MAX_PER_IP + 5 {
            let user = format!("u{}", i % 3);
            let t = l.reserve(ip, &user).unwrap_or_else(|| panic!("tentative {i}"));
            if i % 2 == 0 { l.release(ip, &user, t) } else { l.succeeded(ip, &user, t) }
        }
        // Deux connexions parallèles du même compte : le premier succès efface les entrées du compte, le
        // second rend quand même sa place à l'IP.
        for i in 0..MAX_PER_IP {
            let (a, b) = (l.reserve(ip, "alice").unwrap(), l.reserve(ip, "alice").unwrap());
            l.succeeded(ip, "alice", a);
            l.succeeded(ip, "alice", b);
            assert!(l.failures.lock().unwrap()[&ip_key(ip)].is_empty(), "paire {i}");
        }
        for i in 0..MAX_PER_IP {
            assert!(l.reserve(ip, &format!("v{i}")).is_some(), "place {i} rendue");
        }
    }
}
