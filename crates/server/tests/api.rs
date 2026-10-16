//! Parcours HTTP de bout en bout sur une base SQLite en mémoire.

use std::net::SocketAddr;

use axum::{
    Router,
    body::Body,
    extract::connect_info::MockConnectInfo,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use yawrdp_server::{CSRF_HEADER, app, bootstrap_admin, build_state, config::Config, open_db};

const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const ADMIN_PW: &str = "admin-password-123";

async fn setup(extra: &[(&'static str, &'static str)], peer: &str) -> Router {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let mut env = vec![
        ("YAWRDP_PUBLIC_URL", "https://rdp.example.com"),
        ("YAWRDP_MASTER_KEY", KEY),
        ("YAWRDP_ADMIN_PASSWORD", ADMIN_PW),
        ("YAWRDP_STATIC_DIR", "/nonexistent"),
    ];
    env.extend_from_slice(extra);
    struct V(Vec<(&'static str, &'static str)>);
    impl yawrdp_server::config::Env for V {
        fn var(&self, k: &str) -> Option<String> {
            self.0.iter().find(|(a, _)| *a == k).map(|(_, v)| v.to_string())
        }
    }
    let cfg = Config::from_env(&V(env)).unwrap();
    let db = open_db("sqlite::memory:").await.unwrap();
    let state = build_state(cfg, db).unwrap();
    bootstrap_admin(&state).await.unwrap();
    let peer: SocketAddr = peer.parse().unwrap();
    app(state).layer(MockConnectInfo(peer))
}

struct Resp {
    status: StatusCode,
    cookie: Option<String>,
    body: Value,
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> Resp {
    let mut req = Request::builder().method(method).uri(uri).header(CSRF_HEADER, "1");
    if let Some(c) = cookie {
        req = req.header(header::COOKIE, c);
    }
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let req = match body {
        Some(b) => req.header(header::CONTENT_TYPE, "application/json").body(Body::from(b.to_string())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let cookie = res
        .headers()
        .get(header::SET_COOKIE)
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned());
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Resp { status, cookie, body }
}

async fn login(app: &Router, user: &str, pw: &str) -> String {
    let r = call(app, "POST", "/api/auth/login", None, Some(json!({"username": user, "password": pw})), &[])
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    r.cookie.expect("cookie de session")
}

#[tokio::test]
async fn builtin_login_and_admin_flow() {
    let app = setup(&[], "203.0.113.5:4000").await;

    let r = call(&app, "GET", "/api/me", None, None, &[]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    let admin = login(&app, "admin", ADMIN_PW).await;
    let r = call(&app, "GET", "/api/me", Some(&admin), None, &[]).await;
    assert_eq!(r.body["is_admin"], true);

    // Création d'un utilisateur et d'une connexion qui lui est ouverte.
    let r = call(
        &app,
        "POST",
        "/api/admin/users",
        Some(&admin),
        Some(json!({"username": "alice", "password": "alice-password-1"})),
        &[],
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED);
    let users = call(&app, "GET", "/api/admin/users", Some(&admin), None, &[]).await.body;
    let alice_id =
        users.as_array().unwrap().iter().find(|u| u["username"] == "alice").unwrap()["id"].as_i64().unwrap();

    let r = call(
        &app,
        "POST",
        "/api/admin/connections",
        Some(&admin),
        Some(json!({
            "name": "PC", "host": "10.8.0.2", "username": "alice", "password": "windows-pw",
            "wol_mac": "00-1a-2b-3c-4d-5e", "allowed_users": [alice_id]
        })),
        &[],
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["port"], 3389);
    assert_eq!(r.body["has_password"], true);
    assert_eq!(r.body["wol_mac"], "00:1A:2B:3C:4D:5E");
    assert!(r.body.get("password").is_none(), "le mot de passe ne ressort jamais");
    call(
        &app,
        "POST",
        "/api/admin/connections",
        Some(&admin),
        Some(json!({"name": "Autre", "host": "10.8.0.3"})),
        &[],
    )
    .await;

    let alice = login(&app, "alice", "alice-password-1").await;
    let list = call(&app, "GET", "/api/connections", Some(&alice), None, &[]).await.body;
    assert_eq!(list.as_array().unwrap().len(), 1, "alice ne voit que sa connexion");
    assert_eq!(list[0]["can_wake"], true);

    let r = call(&app, "GET", "/api/admin/users", Some(&alice), None, &[]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    // Déconnexion : le cookie ne vaut plus rien.
    call(&app, "POST", "/api/auth/logout", Some(&alice), None, &[]).await;
    let r = call(&app, "GET", "/api/me", Some(&alice), None, &[]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn csrf_header_required() {
    let app = setup(&[], "203.0.113.5:4000").await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({"username": "admin", "password": ADMIN_PW}).to_string()))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn rate_limit_after_failures() {
    let app = setup(&[], "203.0.113.5:4000").await;
    for _ in 0..5 {
        let r = call(
            &app,
            "POST",
            "/api/auth/login",
            None,
            Some(json!({"username": "admin", "password": "nope"})),
            &[],
        )
        .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    let r = call(
        &app,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({"username": "admin", "password": ADMIN_PW})),
        &[],
    )
    .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn totp_enrolment_then_required() {
    let app = setup(&[], "203.0.113.5:4000").await;
    let admin = login(&app, "admin", ADMIN_PW).await;
    // Session seule (mot de passe absent ou faux) : refusé.
    for body in [json!({}), json!({"password": "nope"})] {
        let r = call(&app, "POST", "/api/account/totp/setup", Some(&admin), Some(body), &[]).await;
        assert!(r.status.is_client_error(), "{:?}", r.body);
    }
    let setup =
        call(&app, "POST", "/api/account/totp/setup", Some(&admin), Some(json!({"password": ADMIN_PW})), &[])
            .await
            .body;
    let secret = setup["secret_base32"].as_str().unwrap();
    assert!(setup["qr_svg"].as_str().unwrap().starts_with("<?xml"));

    let totp = totp_rs::Builder::new()
        .with_secret(totp_rs::Secret::try_from_base32(secret).unwrap())
        .with_account_name("admin")
        .build()
        .unwrap();
    let r = call(
        &app,
        "POST",
        "/api/account/totp/confirm",
        Some(&admin),
        Some(json!({"code": totp.generate_current().to_string()})),
        &[],
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);

    let r = call(
        &app,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({"username": "admin", "password": ADMIN_PW})),
        &[],
    )
    .await;
    assert_eq!(r.body["status"], "totp_required");
    assert!(r.cookie.is_none());

    // Le code déjà utilisé à la confirmation est refusé (anti-rejeu).
    let r = call(
        &app,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "username": "admin", "password": ADMIN_PW, "totp": totp.generate_current().to_string()
        })),
        &[],
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn proxy_mode() {
    let extra = [
        ("YAWRDP_AUTH_MODE", "proxy"),
        ("YAWRDP_TRUSTED_PROXIES", "172.18.0.0/16"),
        ("YAWRDP_PROXY_ADMIN_GROUP", "admins"),
    ];
    let app = setup(&extra, "172.18.0.4:5000").await;

    let r = call(
        &app,
        "GET",
        "/api/me",
        None,
        None,
        &[("Remote-User", "alice"), ("Remote-Groups", "users,admins")],
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["is_admin"], true);
    assert_eq!(r.body["external"], true);

    let r =
        call(&app, "GET", "/api/me", None, None, &[("Remote-User", "alice"), ("Remote-Groups", "users")]).await;
    assert_eq!(r.body["is_admin"], false, "rôle resynchronisé depuis le proxy");

    let r = call(
        &app,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({"username": "admin", "password": ADMIN_PW})),
        &[],
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "login intégré désactivé");

    let info = call(&app, "GET", "/api/info", None, None, &[]).await.body;
    assert_eq!(info["auth_mode"], "proxy");

    // En-tête forgé hors proxy de confiance : refusé.
    let outsider = setup(&extra, "198.51.100.7:5000").await;
    let r = call(&outsider, "GET", "/api/me", None, None, &[("Remote-User", "alice")]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn stolen_session_cannot_touch_2fa() {
    let app = setup(&[], "203.0.113.5:4000").await;
    let admin = login(&app, "admin", ADMIN_PW).await;

    // Ajout de passkey : le mot de passe est exigé avant même le défi WebAuthn.
    let r = call(
        &app,
        "POST",
        "/api/account/passkeys/register/start",
        Some(&admin),
        Some(json!({"password": "x"})),
        &[],
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = call(
        &app,
        "POST",
        "/api/account/passkeys/register/start",
        Some(&admin),
        Some(json!({"password": ADMIN_PW})),
        &[],
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert!(r.body["ceremony"].is_string());

    // Active le TOTP, puis tente de le remplacer : refusé tant qu'il est actif.
    let s =
        call(&app, "POST", "/api/account/totp/setup", Some(&admin), Some(json!({"password": ADMIN_PW})), &[])
            .await
            .body;
    let totp = totp_rs::Builder::new()
        .with_secret(totp_rs::Secret::try_from_base32(s["secret_base32"].as_str().unwrap()).unwrap())
        .with_account_name("admin")
        .build()
        .unwrap();
    let code = totp.generate_current().to_string();
    call(&app, "POST", "/api/account/totp/confirm", Some(&admin), Some(json!({"code": code})), &[]).await;
    let r =
        call(&app, "POST", "/api/account/totp/setup", Some(&admin), Some(json!({"password": ADMIN_PW})), &[])
            .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    // Avec TOTP actif, mot de passe seul ne suffit plus pour une passkey ni pour désactiver.
    let r = call(
        &app,
        "POST",
        "/api/account/passkeys/register/start",
        Some(&admin),
        Some(json!({"password": ADMIN_PW})),
        &[],
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = call(
        &app,
        "POST",
        "/api/account/totp/disable",
        Some(&admin),
        Some(json!({"password": ADMIN_PW, "totp": code})),
        &[],
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "code déjà utilisé : rejeu refusé");
}
