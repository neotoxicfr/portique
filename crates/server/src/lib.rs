pub mod api;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod ratelimit;
pub mod ssh;
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
use portique_proto::AuthMode;
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

use crate::{
    config::Config,
    crypto::Vault,
    ratelimit::LoginLimiter,
    state::{AppState, Ceremonies},
};

/// En-tête exigé sur toute requête API qui modifie quelque chose. Un site tiers ne peut pas
/// l'ajouter sans pré-vol CORS (que l'on ne sert pas) : protection CSRF sans jeton.
pub const CSRF_HEADER: &str = "x-portique";

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
    let rp_id = cfg.public_url.host_str().context("PORTIQUE_PUBLIC_URL sans hôte")?.to_owned();
    let webauthn = WebauthnBuilder::new(&rp_id, &cfg.public_url)
        .context("configuration WebAuthn")?
        .rp_name("Portique")
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
        "aucun admin en base : définir PORTIQUE_ADMIN_PASSWORD(_FILE) pour créer le compte « admin »",
    )?;
    auth::validate_password(pw).map_err(|e| anyhow::anyhow!("PORTIQUE_ADMIN_PASSWORD : {e}"))?;
    sqlx::query(
        "INSERT INTO users (username, password_hash, is_admin, webauthn_id) VALUES ('admin', ?, 1, ?)
         ON CONFLICT (username) DO UPDATE SET password_hash = excluded.password_hash, is_admin = 1",
    )
    .bind(auth::hash_password(pw).await?)
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

/// Cache des fichiers du front : les noms empreintés par trunk (`nom-<16 hex>.ext`) ne changent
/// jamais de contenu ; le reste (page, service worker, manifeste, scripts de préparation) est
/// revalidé à chaque fois, sinon le navigateur garde une ancienne page qui charge un ancien front.
fn static_cache_control(path: &str) -> Option<&'static str> {
    if path.starts_with("/api/") {
        return None;
    }
    let name = path.rsplit('/').next().unwrap_or_default();
    let stem = name.split('.').next().unwrap_or_default();
    let fingerprinted = stem
        .rsplit_once('-')
        .map(|(_, h)| h.split('_').next().unwrap_or_default()) // `…-<hex>_bg.wasm`
        .is_some_and(|h| h.len() == 16 && h.bytes().all(|b| b.is_ascii_hexdigit()));
    Some(if fingerprinted { "public, max-age=31536000, immutable" } else { "no-cache" })
}

pub fn app(state: AppState) -> Router {
    let static_dir = state.cfg.static_dir.clone();
    // Front compressé (gzip ou brotli selon le navigateur) : le wasm passe de 1,3 Mo à 0,5 Mo, même sans
    // reverse proxy qui compresse. L'API et le WebSocket ne passent pas par là.
    let spa = tower_http::compression::Compression::new(
        ServeDir::new(&static_dir).fallback(ServeFile::new(static_dir.join("index.html"))),
    );

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
            let cache = static_cache_control(req.uri().path());
            async move {
                let mut res = next.run(req).await;
                res.headers_mut().insert(header::CONTENT_SECURITY_POLICY, value);
                if let Some(mut c) = cache {
                    // Nom empreinté absent du disque (onglet ancien, déploiement en cours) : la réponse est
                    // le repli index.html ou une erreur, à ne pas garder un an sous l'URL de l'asset.
                    let html = res
                        .headers()
                        .get(header::CONTENT_TYPE)
                        .is_some_and(|v| v.as_bytes().starts_with(b"text/html"));
                    if !res.status().is_success() || html {
                        c = "no-cache";
                    }
                    res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static(c));
                }
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
    /// 0008 : comptes et hôtes reconstruits sans perdre ce qui les référence (sessions, passkeys, droits,
    /// rebonds), clés étrangères rétablies ; un identifiant supprimé n'est plus redonné.
    #[tokio::test]
    async fn rebuild_keeps_children_and_ids_are_never_reused() {
        use super::*;
        let opts = SqliteConnectOptions::from_str("sqlite::memory:").unwrap().foreign_keys(true);
        let db = SqlitePoolOptions::new().max_connections(1).connect_with(opts).await.unwrap();
        let migrator = sqlx::migrate!("./migrations");
        migrator.run_to(7, &db).await.unwrap();
        sqlx::raw_sql(
            "INSERT INTO users (username, webauthn_id) VALUES ('alice', 'a'), ('bob', 'b');
             INSERT INTO sessions (token_hash, user_id, expires_at, mfa) VALUES (x'01', 1, 0, 1), (x'02', 2, 0, 0);
             INSERT INTO passkeys (user_id, name, credential) VALUES (2, 'clé', '{}');
             INSERT INTO connections (name, host, port) VALUES ('pc', '192.0.2.1', 3389), ('rebond', '192.0.2.2', 22);
             UPDATE connections SET ssh_jump_id = 2, wol_via_id = 2 WHERE id = 1;
             INSERT INTO connection_access (connection_id, user_id) VALUES (1, 1), (2, 2);",
        )
        .execute(&db)
        .await
        .unwrap();
        migrator.run(&db).await.unwrap();
        let n = |sql: &'static str| sqlx::query_scalar::<_, i64>(sql).fetch_one(&db);
        assert_eq!(n("PRAGMA foreign_keys").await.unwrap(), 1, "clés étrangères rétablies");
        let kept = "SELECT (SELECT count(*) FROM users) * 1000 + (SELECT count(*) FROM sessions) * 100
                    + (SELECT count(*) FROM passkeys) * 10 + (SELECT count(*) FROM connection_access)";
        assert_eq!(n(kept).await.unwrap(), 2212, "comptes, sessions, passkeys, droits");
        assert_eq!(n("SELECT ssh_jump_id + wol_via_id FROM connections WHERE id = 1").await.unwrap(), 4);

        // bob porte le plus grand identifiant : supprimé, il emporte ses lignes, et carol ne prend pas sa place.
        sqlx::raw_sql(
            "DELETE FROM users WHERE id = 2; INSERT INTO users (username, webauthn_id) VALUES ('carol', 'c');
             DELETE FROM connections WHERE id = 2; INSERT INTO connections (name, host, port) VALUES ('nas', '192.0.2.3', 22);",
        )
        .execute(&db)
        .await
        .unwrap();
        assert_eq!(n("SELECT id FROM users WHERE username = 'carol'").await.unwrap(), 3);
        assert_eq!(n("SELECT id FROM connections WHERE name = 'nas'").await.unwrap(), 3);
        assert_eq!(n(kept).await.unwrap(), 2101, "lignes de bob et du rebond supprimées en cascade");
        assert_eq!(
            n("SELECT count(*) FROM connections WHERE ssh_jump_id IS NULL AND wol_via_id IS NULL")
                .await
                .unwrap(),
            2
        );
    }

    #[test]
    fn static_cache_control_by_name() {
        use super::static_cache_control as c;
        assert_eq!(c("/portique-web-705c14e6e4113241_bg.wasm"), Some("public, max-age=31536000, immutable"));
        assert_eq!(c("/style-d9330bfebee7e4ea.css"), Some("public, max-age=31536000, immutable"));
        assert_eq!(c("/"), Some("no-cache"));
        assert_eq!(c("/session/1"), Some("no-cache"));
        assert_eq!(c("/sw.js"), Some("no-cache"));
        assert_eq!(c("/setup/portique.ps1"), Some("no-cache"));
        assert_eq!(c("/api/me"), None);
    }

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
