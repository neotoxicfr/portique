//! Limitation des tentatives de connexion, en mémoire.
//!
//! Clé = (IP, identifiant) et IP seule : on bloque à la fois l'acharnement sur un compte
//! et le balayage de comptes depuis une même adresse. Fenêtre glissante simple.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const WINDOW: Duration = Duration::from_secs(15 * 60);
const MAX_PER_ACCOUNT: usize = 5;
const MAX_PER_IP: usize = 20;

#[derive(Default)]
pub struct LoginLimiter {
    inner: Mutex<Inner>,
    next: AtomicU64,
}

#[derive(Default)]
struct Inner {
    /// Clé → tentatives de la fenêtre : instant et numéro de réservation.
    attempts: HashMap<String, Vec<(Instant, u64)>>,
    /// Réservations encore sans verdict : un succès du compte ne les efface pas.
    in_flight: HashSet<u64>,
}

/// Réservation d'une tentative : `succeeded` ou `release` rendent à l'IP la place de CETTE tentative,
/// même si un succès concurrent du même compte a déjà effacé les entrées du compte. Abandonnée sans
/// verdict (erreur, défi expiré), elle devient un échec conclu.
pub struct Ticket {
    limiter: Arc<LoginLimiter>,
    n: u64,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.limiter.inner.lock() {
            inner.in_flight.remove(&self.n);
        }
    }
}

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
    /// Identifiant replié comme `COLLATE NOCASE` (ASCII seulement) : « Élodie » et « élodie » sont deux
    /// comptes en base, ils ne partagent pas leur plafond.
    fn keys(ip: IpAddr, username: &str) -> [(String, usize); 2] {
        let ip = ip_key(ip);
        [(format!("{ip}|{}", username.to_ascii_lowercase()), MAX_PER_ACCOUNT), (ip, MAX_PER_IP)]
    }

    /// Réserve une tentative : plafonds vérifiés et tentative comptée sous le même verrou, avant tout travail
    /// coûteux (base, Argon2). Compter seulement après coup laisserait des requêtes parallèles passer toutes
    /// avant le premier échec noté. Une tentative qui échoue reste comptée.
    pub fn reserve(self: &Arc<Self>, ip: IpAddr, username: &str) -> Option<Ticket> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        let Inner { attempts: map, in_flight } = &mut *inner;
        let keys = Self::keys(ip, username);
        let allowed = keys.iter().all(|(k, max)| {
            map.get_mut(k).is_none_or(|v| {
                v.retain(|(t, _)| now.duration_since(*t) < WINDOW);
                v.len() < *max
            })
        });
        let n = allowed.then(|| self.next.fetch_add(1, Ordering::Relaxed));
        if let Some(n) = n {
            for (k, _) in keys {
                map.entry(k).or_default().push((now, n));
            }
            in_flight.insert(n);
        }
        // Évite une croissance sans fin sous attaque : purge des entrées expirées.
        if map.len() > 10_000 {
            map.retain(|_, v| v.iter().any(|(t, _)| now.duration_since(*t) < WINDOW));
        }
        drop(inner);
        n.map(|n| Ticket { limiter: Arc::clone(self), n })
    }

    /// Tentative réussie : échecs conclus du compte effacés, place de cette réservation rendue à l'IP (et à
    /// elle seule : un succès ne rend jamais la place d'une autre tentative). Les autres tentatives du
    /// compte encore en vol restent comptées, sinon un succès laisserait passer de nouvelles tentatives
    /// au-delà du plafond du compte.
    pub fn succeeded(&self, ip: IpAddr, username: &str, t: Ticket) {
        let [(account, _), (ip, _)] = Self::keys(ip, username);
        let mut inner = self.inner.lock().unwrap();
        let Inner { attempts, in_flight } = &mut *inner;
        if let Some(v) = attempts.get_mut(&account) {
            v.retain(|(_, id)| *id != t.n && in_flight.contains(id));
        }
        if let Some(v) = attempts.get_mut(&ip) {
            v.retain(|(_, id)| *id != t.n);
        }
        drop(inner);
    }

    /// Réservation rendue sans verdict (mot de passe bon, code TOTP encore à saisir).
    pub fn release(&self, ip: IpAddr, username: &str, t: Ticket) {
        let mut inner = self.inner.lock().unwrap();
        for (k, _) in Self::keys(ip, username) {
            if let Some(v) = inner.attempts.get_mut(&k) {
                v.retain(|(_, id)| *id != t.n);
            }
        }
        drop(inner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_five_per_account() {
        let l = Arc::new(LoginLimiter::default());
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        // Tentatives en vol, aucune encore conclue : la sixième est déjà refusée.
        let mut tickets: Vec<_> = (0..MAX_PER_ACCOUNT).map(|_| l.reserve(ip, "alice").unwrap()).collect();
        assert!(l.reserve(ip, "Alice").is_none());
        assert!(l.reserve(ip, "autre").is_some());
        // Repli ASCII seulement, comme la base : « Élodie » n'épuise pas le plafond d'« élodie ».
        let _elodie: Vec<_> = (0..MAX_PER_ACCOUNT).map(|_| l.reserve(ip, "Élodie").unwrap()).collect();
        assert!(l.reserve(ip, "élodie").is_some());
        l.succeeded(ip, "alice", tickets.remove(0));
        // Le succès ne rend que sa place : les quatre autres tentatives sont toujours en vol.
        let fifth = l.reserve(ip, "alice").expect("place du succès rendue");
        assert!(l.reserve(ip, "alice").is_none(), "tentatives en vol effacées par le succès");
        // Abandonnées sans verdict, elles deviennent des échecs, que le succès suivant efface.
        drop(tickets);
        assert!(l.reserve(ip, "alice").is_none());
        l.succeeded(ip, "alice", fifth);
        let again: Vec<_> = (0..MAX_PER_ACCOUNT).map(|_| l.reserve(ip, "alice")).collect();
        assert!(again.iter().all(Option::is_some));
    }

    #[test]
    fn ipv6_counts_per_64_and_foreign_ticket_refunds_nothing() {
        let l = Arc::new(LoginLimiter::default());
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
        let l = Arc::new(LoginLimiter::default());
        let ip: IpAddr = "192.0.2.2".parse().unwrap();
        for i in 0..MAX_PER_IP + 5 {
            let user = format!("u{}", i % 3);
            let t = l.reserve(ip, &user).unwrap_or_else(|| panic!("tentative {i}"));
            if i % 2 == 0 { l.release(ip, &user, t) } else { l.succeeded(ip, &user, t) }
        }
        // Deux connexions parallèles du même compte : chaque succès rend sa place à l'IP, l'ordre n'y
        // change rien.
        for i in 0..MAX_PER_IP {
            let (a, b) = (l.reserve(ip, "alice").unwrap(), l.reserve(ip, "alice").unwrap());
            l.succeeded(ip, "alice", a);
            l.succeeded(ip, "alice", b);
            assert!(l.inner.lock().unwrap().attempts[&ip_key(ip)].is_empty(), "paire {i}");
        }
        for i in 0..MAX_PER_IP {
            assert!(l.reserve(ip, &format!("v{i}")).is_some(), "place {i} rendue");
        }
    }
}
