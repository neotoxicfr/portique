pub mod api;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod ratelimit;
pub mod state;
pub mod totp;
pub mod wol;

use std::{str::FromStr, sync::Arc};

use anyhow::Context;
use axum::{
    Router,
    extract::Request,
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::Response,
};
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use tower_http::{
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
    trace::TraceLayer,
};
use webauthn_rs::WebauthnBuilder;
use yawrdp_proto::AuthMode;

use crate::{
    config::Config,
    crypto::Vault,
    ratelimit::LoginLimiter,
    state::{AppState, Ceremonies},
};

/// En-tête exigé sur toute requête API qui modifie quelque chose. Un site tiers ne peut pas
/// l'ajouter sans pré-vol CORS (que l'on ne sert pas) : protection CSRF sans jeton.
pub const CSRF_HEADER: &str = "x-yawrdp";

pub async fn open_db(url: &str) -> anyhow::Result<SqlitePool> {
    let opts = SqliteConnectOptions::from_str(url)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true);
    // Une base en mémoire n'existe que dans sa connexion : une seule pour tout le pool.
    let max = if url.contains(":memory:") { 1 } else { 8 };
    let pool = SqlitePoolOptions::new().max_connections(max).connect_with(opts).await?;
    sqlx::migrate!("./migrations").run(&pool).await.context("migrations")?;
    Ok(pool)
}

pub fn build_state(cfg: Config, db: SqlitePool) -> anyhow::Result<AppState> {
    let rp_id = cfg.public_url.host_str().context("YAWRDP_PUBLIC_URL sans hôte")?.to_owned();
    let webauthn = WebauthnBuilder::new(&rp_id, &cfg.public_url)
        .context("configuration WebAuthn")?
        .rp_name("yawrdp")
        .build()
        .context("configuration WebAuthn")?;
    Ok(AppState {
        db,
        vault: Vault::new(&cfg.master_key),
        cfg: Arc::new(cfg),
        webauthn: Arc::new(webauthn),
        limiter: Arc::new(LoginLimiter::default()),
        ceremonies: Arc::new(Ceremonies::default()),
    })
}

/// Crée le compte `admin` au premier démarrage (mode intégré, base sans aucun admin).
pub async fn bootstrap_admin(state: &AppState) -> anyhow::Result<()> {
    if state.cfg.auth_mode == AuthMode::Proxy {
        return Ok(());
    }
    let admins: i64 =
        sqlx::query_scalar("SELECT count(*) FROM users WHERE is_admin").fetch_one(&state.db).await?;
    if admins > 0 {
        return Ok(());
    }
    let pw = state.cfg.admin_password.as_deref().context(
        "aucun admin en base : définir YAWRDP_ADMIN_PASSWORD(_FILE) pour créer le compte « admin »",
    )?;
    auth::validate_password(pw).map_err(|e| anyhow::anyhow!("YAWRDP_ADMIN_PASSWORD : {e}"))?;
    sqlx::query(
        "INSERT INTO users (username, password_hash, is_admin, webauthn_id) VALUES ('admin', ?, 1, ?)
         ON CONFLICT (username) DO UPDATE SET password_hash = excluded.password_hash, is_admin = 1",
    )
    .bind(auth::hash_password(pw)?)
    .bind(uuid::Uuid::new_v4().to_string())
    .execute(&state.db)
    .await?;
    tracing::warn!("compte « admin » créé : pense à activer TOTP ou une passkey");
    Ok(())
}

async fn csrf_guard(req: Request, next: Next) -> Result<Response, StatusCode> {
    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if !safe && !req.headers().contains_key(CSRF_HEADER) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(next.run(req).await)
}

/// Content-Security-Policy : tout vient du site lui-même. Le seul script inline (amorce du wasm
/// générée par trunk) est autorisé par son empreinte, recalculée au démarrage depuis index.html.
pub fn content_security_policy(index_html: &str) -> String {
    use base64::Engine;
    use sha2::Digest;
    let mut hashes = String::new();
    let mut rest = index_html;
    while let Some(start) = rest.find("<script") {
        rest = &rest[start..];
        let Some(open_end) = rest.find('>') else { break };
        let tag = &rest[..open_end];
        let body_start = open_end + 1;
        let Some(close) = rest[body_start..].find("</script>") else { break };
        if !tag.contains("src=") {
            let digest = sha2::Sha256::digest(&rest.as_bytes()[body_start..body_start + close]);
            hashes
                .push_str(&format!(" 'sha256-{}'", base64::engine::general_purpose::STANDARD.encode(digest)));
        }
        rest = &rest[body_start + close..];
    }
    format!(
        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'{hashes}; style-src 'self' 'unsafe-inline'; \
         img-src 'self' data: blob:; connect-src 'self'; worker-src 'self'; manifest-src 'self'; \
         object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    )
}

/// CSP recalculée quand index.html change (déploiement du front sans redémarrer le serveur).
#[derive(Clone)]
struct CspCache {
    path: std::path::PathBuf,
    cached: Arc<std::sync::Mutex<(Option<std::time::SystemTime>, HeaderValue)>>,
}

impl CspCache {
    fn new(path: std::path::PathBuf) -> Self {
        let empty = HeaderValue::from_str(&content_security_policy("")).expect("CSP ASCII");
        Self { path, cached: Arc::new(std::sync::Mutex::new((None, empty))) }
    }

    fn current(&self) -> HeaderValue {
        let mtime = std::fs::metadata(&self.path).and_then(|m| m.modified()).ok();
        let mut c = self.cached.lock().unwrap();
        if mtime.is_some() && c.0 != mtime {
            let html = std::fs::read_to_string(&self.path).unwrap_or_default();
            if let Ok(v) = HeaderValue::from_str(&content_security_policy(&html)) {
                *c = (mtime, v);
            }
        }
        c.1.clone()
    }
}

pub fn app(state: AppState) -> Router {
    let static_dir = state.cfg.static_dir.clone();
    let spa = ServeDir::new(&static_dir).fallback(ServeFile::new(static_dir.join("index.html")));

    let api = api::router().layer(middleware::from_fn(csrf_guard)).layer(SetResponseHeaderLayer::overriding(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    ));

    let hdr = |name: &'static str, value: &'static str| {
        SetResponseHeaderLayer::overriding(HeaderName::from_static(name), HeaderValue::from_static(value))
    };

    let csp = CspCache::new(static_dir.join("index.html"));

    Router::new()
        .nest("/api", api)
        .fallback_service(spa)
        .layer(middleware::from_fn(move |req: Request, next: Next| {
            let value = csp.current();
            async move {
                let mut res = next.run(req).await;
                res.headers_mut().insert(header::CONTENT_SECURITY_POLICY, value);
                res
            }
        }))
        .layer(hdr("x-content-type-options", "nosniff"))
        .layer(hdr("x-frame-options", "DENY"))
        .layer(hdr("referrer-policy", "no-referrer"))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[cfg(test)]
mod tests {
    #[test]
    fn csp_hashes_inline_scripts_only() {
        let html = r#"<script type="module">init()</script><script src="/x.js"></script>"#;
        let csp = super::content_security_policy(html);
        // sha256("init()") en base64.
        assert!(csp.contains("'sha256-"), "{csp}");
        assert_eq!(csp.matches("'sha256-").count(), 1);
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(!csp.contains("unsafe-eval'") || csp.contains("wasm-unsafe-eval"));
    }
}
