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
use sqlx::SqlitePool;
use time::OffsetDateTime;
use yawrdp_proto::{AuthMode, Me};

use crate::{
    config::ProxyConfig,
    crypto,
    state::{AppError, AppState},
};

pub const SESSION_COOKIE: &str = "yawrdp_session";
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

pub fn hash_password(pw: &str) -> anyhow::Result<String> {
    Ok(Argon2::default()
        .hash_password(pw.as_bytes())
        .map_err(|e| anyhow::anyhow!("argon2 : {e}"))?
        .to_string())
}

pub fn verify_password(pw: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
}

/// Hash factice pour que la vérification prenne le même temps quand le compte n'existe pas.
pub fn dummy_verify(pw: &str) {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let h = DUMMY.get_or_init(|| hash_password("yawrdp-dummy").expect("argon2"));
    let _ = verify_password(pw, h);
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

/// Ouvre une session et renvoie le cookie à poser.
pub async fn open_session(state: &AppState, jar: CookieJar, user_id: i64) -> Result<CookieJar, AppError> {
    let (token, hash) = crypto::new_session_token();
    let expires = OffsetDateTime::now_utc() + time::Duration::days(SESSION_DAYS);
    sqlx::query("DELETE FROM sessions WHERE expires_at < unixepoch()").execute(&state.db).await?;
    sqlx::query("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(hash)
        .bind(user_id)
        .bind(expires.unix_timestamp())
        .execute(&state.db)
        .await?;
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

    #[test]
    fn password_roundtrip() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("wrong", &h));
    }
}
