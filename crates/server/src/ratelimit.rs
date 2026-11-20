//! Limitation des tentatives de connexion, en mémoire.
//!
//! Clé = (IP, identifiant) et IP seule : on bloque à la fois l'acharnement sur un compte
//! et le balayage de comptes depuis une même adresse. Fenêtre glissante simple.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

const WINDOW: Duration = Duration::from_secs(15 * 60);
const MAX_PER_ACCOUNT: usize = 5;
const MAX_PER_IP: usize = 20;

#[derive(Default)]
pub struct LoginLimiter {
    failures: Mutex<HashMap<String, Vec<Instant>>>,
}

impl LoginLimiter {
    fn keys(ip: IpAddr, username: &str) -> [(String, usize); 2] {
        [(format!("{ip}|{}", username.to_lowercase()), MAX_PER_ACCOUNT), (ip.to_string(), MAX_PER_IP)]
    }

    /// Réserve une tentative : plafonds vérifiés et tentative comptée sous le même verrou, avant tout travail
    /// coûteux (base, Argon2). Compter seulement après coup laisserait des requêtes parallèles passer toutes
    /// avant le premier échec noté. Une tentative qui échoue reste comptée.
    pub fn reserve(&self, ip: IpAddr, username: &str) -> bool {
        let now = Instant::now();
        let mut map = self.failures.lock().unwrap();
        let keys = Self::keys(ip, username);
        let allowed = keys.iter().all(|(k, max)| {
            map.get_mut(k).is_none_or(|v| {
                v.retain(|t| now.duration_since(*t) < WINDOW);
                v.len() < *max
            })
        });
        if allowed {
            for (k, _) in keys {
                map.entry(k).or_default().push(now);
            }
        }
        // Évite une croissance sans fin sous attaque : purge des entrées expirées.
        if map.len() > 10_000 {
            map.retain(|_, v| v.iter().any(|t| now.duration_since(*t) < WINDOW));
        }
        allowed
    }

    /// Tentative réussie : compteur du compte effacé, réservation rendue à l'IP.
    pub fn succeeded(&self, ip: IpAddr, username: &str) {
        let [(account, _), (ip, _)] = Self::keys(ip, username);
        let mut map = self.failures.lock().unwrap();
        map.remove(&account);
        if let Some(v) = map.get_mut(&ip) {
            v.pop();
        }
    }

    /// Réservation rendue sans verdict (mot de passe bon, code TOTP encore à saisir).
    pub fn release(&self, ip: IpAddr, username: &str) {
        let mut map = self.failures.lock().unwrap();
        for (k, _) in Self::keys(ip, username) {
            if let Some(v) = map.get_mut(&k) {
                v.pop();
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
        for _ in 0..MAX_PER_ACCOUNT {
            assert!(l.reserve(ip, "alice"));
        }
        assert!(!l.reserve(ip, "Alice"));
        assert!(l.reserve(ip, "autre"));
        l.succeeded(ip, "alice");
        assert!(l.reserve(ip, "alice"));
    }

    #[test]
    fn released_and_successful_attempts_do_not_count() {
        let l = LoginLimiter::default();
        let ip: IpAddr = "192.0.2.2".parse().unwrap();
        for i in 0..MAX_PER_IP + 5 {
            let user = format!("u{}", i % 3);
            assert!(l.reserve(ip, &user), "tentative {i}");
            if i % 2 == 0 { l.release(ip, &user) } else { l.succeeded(ip, &user) }
        }
    }
}
