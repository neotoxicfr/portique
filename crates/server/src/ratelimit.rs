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

    /// Vrai si une nouvelle tentative est autorisée.
    pub fn allowed(&self, ip: IpAddr, username: &str) -> bool {
        let now = Instant::now();
        let mut map = self.failures.lock().unwrap();
        Self::keys(ip, username).iter().all(|(k, max)| {
            map.get_mut(k).is_none_or(|v| {
                v.retain(|t| now.duration_since(*t) < WINDOW);
                v.len() < *max
            })
        })
    }

    pub fn failed(&self, ip: IpAddr, username: &str) {
        let now = Instant::now();
        let mut map = self.failures.lock().unwrap();
        for (k, _) in Self::keys(ip, username) {
            map.entry(k).or_default().push(now);
        }
        // Évite une croissance sans fin sous attaque : purge des entrées expirées.
        if map.len() > 10_000 {
            map.retain(|_, v| v.iter().any(|t| now.duration_since(*t) < WINDOW));
        }
    }

    pub fn succeeded(&self, ip: IpAddr, username: &str) {
        let [(account, _), _] = Self::keys(ip, username);
        self.failures.lock().unwrap().remove(&account);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_five_per_account() {
        let l = LoginLimiter::default();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..MAX_PER_ACCOUNT {
            assert!(l.allowed(ip, "alice"));
            l.failed(ip, "alice");
        }
        assert!(!l.allowed(ip, "Alice"));
        assert!(l.allowed(ip, "autre"));
        l.succeeded(ip, "alice");
        assert!(l.allowed(ip, "alice"));
    }
}
