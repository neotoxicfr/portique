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
/// Clés suivies au plus. Pleine, la table est purgée des clés expirées au plus une fois par `PURGE_EVERY`
/// (un parcours complet à chaque appel, sous le verrou commun, ralentirait toutes les connexions) ; toujours
/// pleine, elle refuse les nouvelles clés et garde les plafonds des comptes et adresses déjà suivis.
const MAX_KEYS: usize = 10_000;
const PURGE_EVERY: Duration = Duration::from_secs(60);

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
    /// Dernière purge des clés expirées.
    purged: Option<Instant>,
}

/// Réservation d'une tentative : `succeeded` ou `release` rendent à l'IP la place de CETTE tentative,
/// même si un succès concurrent du même compte a déjà effacé les entrées du compte. Abandonnée sans
/// verdict (erreur, défi expiré), elle devient un échec conclu. Elle porte ses clés (compte, adresse) et
/// son limiteur : un verdict ne touche que les compteurs de la tentative réservée, même rendu sous une
/// autre adresse (fin d'une connexion par passkey).
pub struct Ticket {
    limiter: Arc<LoginLimiter>,
    n: u64,
    keys: [String; 2],
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

impl Ticket {
    /// Tentative réussie : échecs conclus du compte effacés, place de cette réservation rendue à l'IP (et à
    /// elle seule : un succès ne rend jamais la place d'une autre tentative). Les autres tentatives du
    /// compte encore en vol restent comptées, sinon un succès laisserait passer de nouvelles tentatives
    /// au-delà du plafond du compte.
    pub fn succeeded(self) {
        let mut inner = self.limiter.inner.lock().unwrap();
        let Inner { attempts, in_flight, .. } = &mut *inner;
        let [account, ip] = &self.keys;
        if let Some(v) = attempts.get_mut(account) {
            v.retain(|(_, id)| *id != self.n && in_flight.contains(id));
        }
        if let Some(v) = attempts.get_mut(ip) {
            v.retain(|(_, id)| *id != self.n);
        }
        drop(inner);
    }

    /// Réservation rendue sans verdict (mot de passe bon, code TOTP encore à saisir).
    pub fn release(self) {
        let mut inner = self.limiter.inner.lock().unwrap();
        for k in &self.keys {
            if let Some(v) = inner.attempts.get_mut(k) {
                v.retain(|(_, id)| *id != self.n);
            }
        }
        drop(inner);
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
        let Inner { attempts: map, in_flight, purged } = &mut *inner;
        let keys = Self::keys(ip, username);
        let room = |map: &HashMap<_, _>| {
            map.len() + keys.iter().filter(|(k, _)| !map.contains_key(k)).count() <= MAX_KEYS
        };
        if !room(map) && purged.is_none_or(|t| now.duration_since(t) >= PURGE_EVERY) {
            map.retain(|_, v| v.iter().any(|(t, _)| now.duration_since(*t) < WINDOW));
            *purged = Some(now);
        }
        let allowed = room(map)
            && keys.iter().all(|(k, max)| {
                map.get_mut(k).is_none_or(|v| {
                    v.retain(|(t, _)| now.duration_since(*t) < WINDOW);
                    v.len() < *max
                })
            });
        let n = allowed.then(|| self.next.fetch_add(1, Ordering::Relaxed));
        if let Some(n) = n {
            for (k, _) in &keys {
                map.entry(k.clone()).or_default().push((now, n));
            }
            in_flight.insert(n);
        }
        drop(inner);
        let [(account, _), (ip, _)] = keys;
        n.map(|n| Ticket { limiter: Arc::clone(self), n, keys: [account, ip] })
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
        tickets.remove(0).succeeded();
        // Le succès ne rend que sa place : les quatre autres tentatives sont toujours en vol.
        let fifth = l.reserve(ip, "alice").expect("place du succès rendue");
        assert!(l.reserve(ip, "alice").is_none(), "tentatives en vol effacées par le succès");
        // Abandonnées sans verdict, elles deviennent des échecs, que le succès suivant efface.
        drop(tickets);
        assert!(l.reserve(ip, "alice").is_none());
        fifth.succeeded();
        let again: Vec<_> = (0..MAX_PER_ACCOUNT).map(|_| l.reserve(ip, "alice")).collect();
        assert!(again.iter().all(Option::is_some));
    }

    #[test]
    fn ipv6_counts_per_64_and_a_verdict_touches_only_its_own_keys() {
        let l = Arc::new(LoginLimiter::default());
        for i in 0..MAX_PER_IP {
            let ip: IpAddr = format!("2001:db8:1:2::{:x}", i + 1).parse().unwrap();
            assert!(l.reserve(ip, &format!("u{i}")).is_some());
        }
        let other: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        assert!(l.reserve(other, "nouveau").is_none(), "même /64 : plafond atteint");
        // Une réussite d'u0 réservée sur un autre /64 ne rend aucune place à ce /64 et n'efface pas
        // l'échec qu'u0 y a laissé.
        l.reserve("2001:db8:1:3::1".parse().unwrap(), "u0").unwrap().succeeded();
        let count = |k: &str| l.inner.lock().unwrap().attempts.get(k).map_or(0, Vec::len);
        assert_eq!(count("2001:db8:1:2::/64"), MAX_PER_IP);
        assert_eq!(count("2001:db8:1:2::/64|u0"), 1, "échec d'u0 sur l'autre /64 effacé");
        assert_eq!(count("2001:db8:1:3::/64|u0") + count("2001:db8:1:3::/64"), 0);
        assert!(l.reserve(other, "nouveau").is_none(), "même /64 : plafond atteint");
        assert!(l.reserve("2001:db8:1:3::1".parse().unwrap(), "nouveau").is_some(), "autre /64 : libre");
    }

    /// Table pleine : purge des clés expirées au plus une fois par `PURGE_EVERY`, aucune nouvelle clé tant
    /// qu'il n'y a pas de place, les clés déjà suivies gardent leurs compteurs.
    #[test]
    fn full_table_is_purged_at_most_once_per_interval_and_keeps_its_keys() {
        let l = Arc::new(LoginLimiter::default());
        let ip = |n: u8| IpAddr::from([192, 0, 2, n]);
        let fill = |at: Instant, n: usize| {
            let mut inner = l.inner.lock().unwrap();
            for k in 0..n {
                inner.attempts.insert(format!("x{k}"), vec![(at, u64::MAX)]);
            }
        };
        let len = || l.inner.lock().unwrap().attempts.len();
        let expired = Instant::now().checked_sub(WINDOW + Duration::from_secs(1)).unwrap();
        drop(l.reserve(ip(1), "alice").unwrap()); // un échec conclu

        fill(expired, MAX_KEYS - 2);
        assert!(l.reserve(ip(2), "bob").is_some(), "clés expirées purgées");
        assert_eq!(len(), 4);
        // Purge récente : la suivante attend, la table pleine ne prend aucune nouvelle clé.
        fill(expired, MAX_KEYS - 4);
        assert!(l.reserve(ip(3), "carol").is_none());
        assert_eq!(len(), MAX_KEYS);
        let again = l.reserve(ip(1), "alice").expect("clés déjà suivies");
        assert_eq!(l.inner.lock().unwrap().attempts["192.0.2.1|alice"].len(), 2, "échec d'alice gardé");
        drop(again);
        l.inner.lock().unwrap().purged = Instant::now().checked_sub(PURGE_EVERY);
        assert!(l.reserve(ip(3), "carol").is_some(), "purge passée");
        assert_eq!(len(), 6);
        // Pleine de clés actives : rien à purger, toujours aucune nouvelle clé.
        fill(Instant::now(), MAX_KEYS - 6);
        l.inner.lock().unwrap().purged = Instant::now().checked_sub(PURGE_EVERY);
        assert!(l.reserve(ip(4), "dave").is_none());
        assert_eq!(len(), MAX_KEYS);
    }

    #[test]
    fn released_and_successful_attempts_do_not_count() {
        let l = Arc::new(LoginLimiter::default());
        let ip: IpAddr = "192.0.2.2".parse().unwrap();
        for i in 0..MAX_PER_IP + 5 {
            let user = format!("u{}", i % 3);
            let t = l.reserve(ip, &user).unwrap_or_else(|| panic!("tentative {i}"));
            if i % 2 == 0 { t.release() } else { t.succeeded() }
        }
        // Deux connexions parallèles du même compte : chaque succès rend sa place à l'IP, l'ordre n'y
        // change rien.
        for i in 0..MAX_PER_IP {
            let (a, b) = (l.reserve(ip, "alice").unwrap(), l.reserve(ip, "alice").unwrap());
            a.succeeded();
            b.succeeded();
            assert!(l.inner.lock().unwrap().attempts[&ip_key(ip)].is_empty(), "paire {i}");
        }
        for i in 0..MAX_PER_IP {
            assert!(l.reserve(ip, &format!("v{i}")).is_some(), "place {i} rendue");
        }
    }
}
