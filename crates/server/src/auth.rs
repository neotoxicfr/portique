//! Identification de l'utilisateur : cookie de session (mode intégré) ou en-têtes du proxy.

use std::net::{IpAddr, SocketAddr};

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use axum::{
    extract::{ConnectInfo, FromRef, FromRequestParts},
    http::{HeaderMap, request::Parts},
};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use portique_proto::{AuthMode, Me};
use sqlx::{SqliteConnection, SqliteExecutor, SqlitePool};
use time::OffsetDateTime;

use crate::{
    config::ProxyConfig,
    crypto,
    state::{AppError, AppState},
};

pub const SESSION_COOKIE: &str = "portique_session";
const SESSION_DAYS: i64 = 30;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub id: i64,
    pub username: String,
    pub password_hash: Option<String>,
    pub totp_secret: Option<Vec<u8>>,
    pub is_admin: bool,
    pub external: bool,
    pub webauthn_id: String,
}

impl UserRow {
    pub fn me(&self) -> Me {
        Me {
            id: self.id,
            username: self.username.clone(),
            is_admin: self.is_admin,
            totp_enabled: self.totp_secret.is_some(),
            external: self.external,
        }
    }
}

macro_rules! user_columns {
    () => {
        "id, username, password_hash, totp_secret, is_admin, external, webauthn_id"
    };
}

pub async fn user_by_id(db: &SqlitePool, id: i64) -> sqlx::Result<Option<UserRow>> {
    sqlx::query_as(concat!("SELECT ", user_columns!(), " FROM users WHERE id = ?"))
        .bind(id)
        .fetch_optional(db)
        .await
}

pub async fn user_by_name(db: &SqlitePool, name: &str) -> sqlx::Result<Option<UserRow>> {
    sqlx::query_as(concat!("SELECT ", user_columns!(), " FROM users WHERE username = ?"))
        .bind(name)
        .fetch_optional(db)
        .await
}

static ARGON2_PERMITS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

/// Calcul Argon2 (~19 Mio, des dizaines de ms) hors des workers async, quelques-uns à la fois : la mémoire
/// du conteneur est bornée et une rafale de connexions ne doit pas bloquer les relais en cours.
async fn argon2<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> anyhow::Result<T> {
    let permit = ARGON2_PERMITS.acquire().await?;
    // Le permis suit le calcul : une requête abandonnée (client parti) n'arrête pas la tâche bloquante,
    // elle ne doit pas non plus rendre sa place avant la fin.
    Ok(tokio::task::spawn_blocking(move || {
        let _permit = permit;
        f()
    })
    .await?)
}

fn hash_password_sync(pw: &str) -> anyhow::Result<String> {
    Ok(Argon2::default()
        .hash_password(pw.as_bytes())
        .map_err(|e| anyhow::anyhow!("argon2 : {e}"))?
        .to_string())
}

fn verify_password_sync(pw: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
}

pub async fn hash_password(pw: &str) -> anyhow::Result<String> {
    let pw = pw.to_owned();
    argon2(move || hash_password_sync(&pw)).await?
}

pub async fn verify_password(pw: &str, hash: &str) -> bool {
    let (pw, hash) = (pw.to_owned(), hash.to_owned());
    argon2(move || verify_password_sync(&pw, &hash)).await.unwrap_or(false)
}

/// Hash factice pour que la vérification prenne le même temps quand le compte n'existe pas.
pub async fn dummy_verify(pw: &str) {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let pw = pw.to_owned();
    let _ = argon2(move || {
        let h = DUMMY.get_or_init(|| hash_password_sync("portique-dummy").expect("argon2"));
        verify_password_sync(&pw, h)
    })
    .await;
}

pub fn validate_password(pw: &str) -> Result<(), AppError> {
    if pw.chars().count() < 12 {
        return Err(AppError::BadRequest("mot de passe trop court (12 caractères minimum)".into()));
    }
    Ok(())
}

pub fn validate_username(name: &str) -> Result<(), AppError> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name.chars().all(|c| c.is_alphanumeric() || "._-@".contains(c));
    if ok { Ok(()) } else { Err(AppError::BadRequest("identifiant invalide".into())) }
}

/// Vérifie un code TOTP et consomme son pas par une seule écriture conditionnelle, sans lecture préalable :
/// un pas déjà consommé est refusé par l'écriture même, et de deux requêtes concurrentes avec le même code,
/// une seule l'emporte. Dans une transaction (connexion), elle en est ainsi la première instruction : une
/// lecture d'abord y deviendrait une écriture sur un instantané périmé (SQLITE_BUSY sous concurrence).
/// L'écriture exige aussi la graine vérifiée : retirée ou remplacée entre-temps (remise à zéro de la 2FA),
/// le code ne vaut plus rien.
pub async fn consume_totp(
    state: &AppState,
    db: impl SqliteExecutor<'_>,
    u: &UserRow,
    sealed: &[u8],
    code: &str,
) -> Result<bool, AppError> {
    let secret = state.vault.open(&format!("totp:{}", u.id), sealed)?;
    let Some(step) = crate::totp::verify(&secret, &u.username, code, 0)? else {
        return Ok(false);
    };
    let r =
        sqlx::query("UPDATE users SET totp_last = ?1 WHERE id = ?2 AND totp_last < ?1 AND totp_secret = ?3")
            .bind(step)
            .bind(u.id)
            .bind(sealed)
            .execute(db)
            .await?;
    Ok(r.rows_affected() == 1)
}

/// Preuve vérifiée sur laquelle repose une nouvelle session.
pub enum Proof<'a> {
    /// Mot de passe, et graine TOTP s'il y en avait une, tels qu'ils étaient lors de la vérification.
    Password { hash: &'a str, totp: Option<&'a [u8]> },
    /// Passkey utilisée (ligne de `passkeys`).
    Passkey(i64),
}

/// Ouvre une session et renvoie le cookie à poser ; elle est marquée `mfa` si la preuve comprend un second
/// facteur (TOTP ou passkey). La preuve est revérifiée dans l'INSERT même : un changement de mot de passe,
/// une remise à zéro de la 2FA ou une passkey retirée pendant la connexion ne laisse pas naître de session
/// après la révocation (SQLite sérialise les écritures : avant, la révocation l'efface ; après, l'INSERT échoue).
/// `db` : la transaction de la connexion, qui consomme aussi le code TOTP.
pub async fn open_session(
    state: &AppState,
    db: &mut SqliteConnection,
    jar: CookieJar,
    user_id: i64,
    proof: Proof<'_>,
) -> Result<CookieJar, AppError> {
    let (token, hash) = crypto::new_session_token();
    let expires = OffsetDateTime::now_utc() + time::Duration::days(SESSION_DAYS);
    sqlx::query("DELETE FROM sessions WHERE expires_at < unixepoch()").execute(&mut *db).await?;
    let insert =
        |sql: &'static str| sqlx::query(sql).bind(hash.clone()).bind(user_id).bind(expires.unix_timestamp());
    let r = match proof {
        Proof::Password { hash: pw, totp } => {
            insert(
                "INSERT INTO sessions (token_hash, user_id, expires_at, mfa) SELECT ?1, ?2, ?3, ?4
                 WHERE EXISTS (SELECT 1 FROM users WHERE id = ?2 AND password_hash IS ?5 AND totp_secret IS ?6)",
            )
            .bind(totp.is_some())
            .bind(pw)
            .bind(totp)
            .execute(&mut *db)
            .await?
        }
        Proof::Passkey(id) => {
            insert(
                "INSERT INTO sessions (token_hash, user_id, expires_at, mfa) SELECT ?1, ?2, ?3, 1
                 WHERE EXISTS (SELECT 1 FROM passkeys WHERE id = ?4 AND user_id = ?2)",
            )
            .bind(id)
            .execute(&mut *db)
            .await?
        }
    };
    // Facteurs bons mais révoqués entre-temps : 409 distinct d'un 401, pour que la page de connexion
    // ne parle pas de mauvais mot de passe. Il n'apprend rien à qui n'a pas déjà prouvé ces facteurs.
    if r.rows_affected() == 0 {
        return Err(AppError::Conflict("réglages du compte changés pendant la connexion, recommence".into()));
    }
    let cookie = Cookie::build((SESSION_COOKIE, token))
        .path("/")
        .http_only(true)
        .secure(state.cfg.secure_cookies)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::days(SESSION_DAYS))
        .build();
    Ok(jar.add(cookie))
}

pub async fn close_session(state: &AppState, jar: CookieJar) -> Result<CookieJar, AppError> {
    if let Some(c) = jar.get(SESSION_COOKIE) {
        sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
            .bind(crypto::token_hash(c.value()))
            .execute(&state.db)
            .await?;
    }
    Ok(jar.remove(Cookie::build(SESSION_COOKIE).path("/")))
}

/// IP réelle du client : le pair TCP, ou le premier saut non fiable de `X-Forwarded-For`
/// si le pair est un proxy de confiance.
pub fn client_ip(peer: IpAddr, headers: &HeaderMap, proxy: &ProxyConfig) -> IpAddr {
    let trusted = |ip: &IpAddr| proxy.is_trusted(ip);
    if !trusted(&peer) {
        return peer;
    }
    let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) else {
        return peer;
    };
    xff.rsplit(',').filter_map(|s| s.trim().parse::<IpAddr>().ok()).find(|ip| !trusted(ip)).unwrap_or(peer)
}

/// Utilisateur authentifié de la requête.
pub struct CurrentUser(pub UserRow);

/// Utilisateur authentifié et administrateur.
pub struct AdminUser(pub UserRow);

/// IP du client (après proxy de confiance).
pub struct ClientIp(pub IpAddr);

impl<S> FromRequestParts<S> for ClientIp
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let peer = peer_ip(parts, state).await?;
        let state = AppState::from_ref(state);
        Ok(ClientIp(client_ip(peer, &parts.headers, &state.cfg.proxy)))
    }
}

async fn peer_ip<S: Send + Sync>(parts: &mut Parts, state: &S) -> Result<IpAddr, AppError> {
    ConnectInfo::<SocketAddr>::from_request_parts(parts, state)
        .await
        .map(|c| c.0.ip())
        .map_err(|_| AppError::Internal(anyhow::anyhow!("ConnectInfo absent")))
}

impl<S> FromRequestParts<S> for CurrentUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app = AppState::from_ref(state);
        match app.cfg.auth_mode {
            AuthMode::Builtin => from_cookie(&app, parts).await,
            AuthMode::Proxy => {
                let peer = peer_ip(parts, state).await?;
                from_proxy(&app, parts, peer).await
            }
        }
        .map(CurrentUser)
    }
}

impl<S> FromRequestParts<S> for AdminUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let CurrentUser(u) = CurrentUser::from_request_parts(parts, state).await?;
        if u.is_admin { Ok(AdminUser(u)) } else { Err(AppError::Forbidden) }
    }
}

async fn from_cookie(state: &AppState, parts: &Parts) -> Result<UserRow, AppError> {
    let jar = CookieJar::from_headers(&parts.headers);
    let token = jar.get(SESSION_COOKIE).ok_or(AppError::Unauthorized)?;
    let user_id: Option<i64> =
        sqlx::query_scalar("SELECT user_id FROM sessions WHERE token_hash = ? AND expires_at >= unixepoch()")
            .bind(crypto::token_hash(token.value()))
            .fetch_optional(&state.db)
            .await?;
    let user_id = user_id.ok_or(AppError::Unauthorized)?;
    user_by_id(&state.db, user_id).await?.ok_or(AppError::Unauthorized)
}

async fn from_proxy(state: &AppState, parts: &Parts, peer: IpAddr) -> Result<UserRow, AppError> {
    let proxy = &state.cfg.proxy;
    if !proxy.is_trusted(&peer) {
        tracing::warn!(%peer, "requête hors proxy de confiance refusée");
        return Err(AppError::Unauthorized);
    }
    let header = |name: &str| {
        parts.headers.get(name).and_then(|v| v.to_str().ok()).map(str::trim).filter(|s| !s.is_empty())
    };
    let username = header(&proxy.user_header).ok_or(AppError::Unauthorized)?;
    validate_username(username).map_err(|_| AppError::Unauthorized)?;
    let is_admin = match (&proxy.admin_group, header(&proxy.groups_header)) {
        (Some(admin), Some(groups)) => groups.split(',').any(|g| g.trim() == admin),
        _ => false,
    };

    // Le proxy fait foi : compte créé à la volée, rôle admin resynchronisé à chaque requête.
    sqlx::query(
        "INSERT INTO users (username, is_admin, external, webauthn_id) VALUES (?, ?, 1, ?)
         ON CONFLICT (username) DO UPDATE SET is_admin = excluded.is_admin",
    )
    .bind(username)
    .bind(is_admin)
    .bind(uuid::Uuid::new_v4().to_string())
    .execute(&state.db)
    .await?;
    user_by_name(&state.db, username).await?.ok_or(AppError::Unauthorized)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy(trusted: &[&str]) -> ProxyConfig {
        ProxyConfig {
            trusted: trusted.iter().map(|s| s.parse().unwrap()).collect(),
            trusted_hosts: Vec::new(),
            resolved: Default::default(),
            user_header: "Remote-User".into(),
            groups_header: "Remote-Groups".into(),
            admin_group: None,
        }
    }

    #[test]
    fn client_ip_ignores_xff_from_untrusted_peer() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        let peer = "8.8.8.8".parse().unwrap();
        assert_eq!(client_ip(peer, &h, &proxy(&["10.0.0.0/8"])), peer);
    }

    #[test]
    fn client_ip_takes_first_untrusted_hop() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "6.6.6.6, 1.2.3.4, 10.0.0.2".parse().unwrap());
        let peer = "10.0.0.1".parse().unwrap();
        let ip = client_ip(peer, &h, &proxy(&["10.0.0.0/8"]));
        assert_eq!(ip, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    /// La preuve est revérifiée à l'INSERT : une révocation survenue après la vérification gagne.
    #[tokio::test]
    async fn stale_proof_opens_no_session() {
        let s = crate::api::ssh::tests::state("builtin").await;
        let u = user_by_name(&s.db, "admin").await.unwrap().unwrap();
        let hash = u.password_hash.clone().unwrap();
        let (st, uid) = (&s, u.id);
        let open = move |proof| async move {
            let mut db = st.db.acquire().await.unwrap();
            open_session(st, &mut db, CookieJar::new(), uid, proof).await
        };
        assert!(open(Proof::Password { hash: &hash, totp: None }).await.is_ok());
        // Mot de passe changé (et sessions supprimées) entre la vérification et l'INSERT.
        sqlx::query("UPDATE users SET password_hash = 'autre' WHERE id = ?")
            .bind(u.id)
            .execute(&s.db)
            .await
            .unwrap();
        let r = open(Proof::Password { hash: &hash, totp: None }).await;
        assert!(matches!(r, Err(AppError::Conflict(_))), "ancien mot de passe");
        // 2FA remise à zéro par un admin pendant la connexion « mot de passe + TOTP ».
        sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(&hash)
            .bind(u.id)
            .execute(&s.db)
            .await
            .unwrap();
        let r = open(Proof::Password { hash: &hash, totp: Some(&[1]) }).await;
        assert!(matches!(r, Err(AppError::Conflict(_))), "TOTP retiré");
        // Passkey retirée après l'émission du défi.
        assert!(matches!(open(Proof::Passkey(42)).await, Err(AppError::Conflict(_))), "passkey retirée");
        sqlx::query("INSERT INTO passkeys (id, user_id, name, credential) VALUES (42, ?, 'clé', '{}')")
            .bind(u.id)
            .execute(&s.db)
            .await
            .unwrap();
        assert!(open(Proof::Passkey(42)).await.is_ok());
        let mfa: Vec<bool> =
            sqlx::query_scalar("SELECT mfa FROM sessions ORDER BY rowid").fetch_all(&s.db).await.unwrap();
        assert_eq!(mfa, [false, true]);
        // L'identifiant d'une passkey supprimée n'est jamais redonné à la suivante (migration 0007).
        let add = || async {
            sqlx::query_scalar::<_, i64>(
                "INSERT INTO passkeys (user_id, name, credential) VALUES (?, 'k', '{}') RETURNING id",
            )
            .bind(u.id)
            .fetch_one(&s.db)
            .await
            .unwrap()
        };
        let first = add().await;
        sqlx::query("DELETE FROM passkeys WHERE id = ?").bind(first).execute(&s.db).await.unwrap();
        assert_ne!(add().await, first, "identifiant réattribué");
    }

    /// Deux requêtes avec le même code lisent le même `totp_last` : une seule consomme le pas.
    #[tokio::test]
    async fn totp_step_consumed_once_under_concurrency() {
        let s = crate::api::ssh::tests::state("builtin").await;
        let u = user_by_name(&s.db, "admin").await.unwrap().unwrap();
        let secret = crate::totp::new_secret();
        let sealed = s.vault.seal(&format!("totp:{}", u.id), &secret);
        sqlx::query("UPDATE users SET totp_secret = ? WHERE id = ?")
            .bind(&sealed)
            .bind(u.id)
            .execute(&s.db)
            .await
            .unwrap();
        let code = crate::totp::build(&secret, &u.username).unwrap().generate_current().to_string();
        let (a, b, c) = tokio::join!(
            consume_totp(&s, &s.db, &u, &sealed, &code),
            consume_totp(&s, &s.db, &u, &sealed, &code),
            consume_totp(&s, &s.db, &u, &sealed, &code)
        );
        let ok = [a.unwrap(), b.unwrap(), c.unwrap()];
        assert_eq!(ok.iter().filter(|o| **o).count(), 1, "{ok:?}");
    }

    /// Graine lue avant une remise à zéro de la 2FA : son code n'est plus accepté ni son pas consommé.
    #[tokio::test]
    async fn totp_code_of_a_removed_seed_is_refused() {
        let s = crate::api::ssh::tests::state("builtin").await;
        let u = user_by_name(&s.db, "admin").await.unwrap().unwrap();
        let secret = crate::totp::new_secret();
        let sealed = s.vault.seal(&format!("totp:{}", u.id), &secret);
        let code = crate::totp::build(&secret, &u.username).unwrap().generate_current().to_string();
        assert!(!consume_totp(&s, &s.db, &u, &sealed, &code).await.unwrap());
        let last: i64 = sqlx::query_scalar("SELECT totp_last FROM users WHERE id = ?")
            .bind(u.id)
            .fetch_one(&s.db)
            .await
            .unwrap();
        assert_eq!(last, 0);
    }

    #[tokio::test]
    async fn argon2_permit_held_until_computation_ends() {
        // Chaque calcul bloque jusqu'à la fermeture de son canal `gates`.
        let (started, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
        let (gates, tasks): (Vec<_>, Vec<_>) = (0..4)
            .map(|_| {
                let (gate, wait) = std::sync::mpsc::channel::<()>();
                let started = started.clone();
                let task = tokio::spawn(argon2(move || {
                    started.send(()).unwrap();
                    let _ = wait.recv();
                }));
                (gate, task)
            })
            .unzip();
        // Délai borné : un calcul qui ne démarre pas fait échouer le test (et l'abandon de `gates` libère
        // ceux qui ont démarré) au lieu de le bloquer.
        let all_started = async {
            for _ in 0..4 {
                started_rx.recv().await.unwrap();
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), all_started).await.expect("calculs démarrés");
        // Requêtes abandonnées pendant le calcul : les calculs continuent, leurs permis aussi.
        for t in &tasks {
            t.abort();
        }
        for t in tasks {
            assert!(t.await.unwrap_err().is_cancelled());
        }
        assert_eq!(ARGON2_PERMITS.available_permits(), 0);
        drop(gates);
        let all = tokio::time::timeout(std::time::Duration::from_secs(5), ARGON2_PERMITS.acquire_many(4));
        assert!(all.await.is_ok(), "permis rendus à la fin des calculs");
    }

    #[tokio::test]
    async fn password_roundtrip() {
        let h = hash_password("correct horse battery").await.unwrap();
        assert!(verify_password("correct horse battery", &h).await);
        assert!(!verify_password("wrong", &h).await);
    }
}
