//! Parcours HTTP de bout en bout sur une base SQLite en mémoire.

use std::net::SocketAddr;

use axum::{
    Router,
    body::Body,
    extract::connect_info::MockConnectInfo,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use portique_server::{CSRF_HEADER, app, bootstrap_admin, build_state, config::Config, open_db};
use serde_json::{Value, json};
use tower::ServiceExt;

const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const ADMIN_PW: &str = "admin-password-123";

async fn setup(extra: &[(&'static str, &'static str)], peer: &str) -> Router {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let mut env = vec![
        ("PORTIQUE_PUBLIC_URL", "https://rdp.example.com"),
        ("PORTIQUE_MASTER_KEY", KEY),
        ("PORTIQUE_ADMIN_PASSWORD", ADMIN_PW),
        ("PORTIQUE_STATIC_DIR", "/nonexistent"),
    ];
    env.extend_from_slice(extra);
    struct V(Vec<(&'static str, &'static str)>);
    impl portique_server::config::Env for V {
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
    let pc_id = r.body["id"].as_i64().unwrap();
    let r = call(
        &app,
        "POST",
        "/api/admin/connections",
        Some(&admin),
        Some(json!({"name": "Autre", "host": "10.8.0.3"})),
        &[],
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let other_id = r.body["id"].as_i64().unwrap();

    let alice = login(&app, "alice", "alice-password-1").await;
    let list = call(&app, "GET", "/api/connections", Some(&alice), None, &[]).await.body;
    let ids: Vec<i64> = list.as_array().unwrap().iter().map(|c| c["id"].as_i64().unwrap()).collect();
    assert!(ids.contains(&pc_id) && !ids.contains(&other_id), "alice ne voit que sa connexion : {ids:?}");
    assert_eq!(list[0]["can_wake"], true);

    let r = call(&app, "GET", "/api/admin/users", Some(&alice), None, &[]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    // Déconnexion : le cookie ne vaut plus rien.
    call(&app, "POST", "/api/auth/logout", Some(&alice), None, &[]).await;
    let r = call(&app, "GET", "/api/me", Some(&alice), None, &[]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    // 2FA remise à zéro par un admin (facteur perdu ou volé) : les sessions ouvertes tombent.
    let alice = login(&app, "alice", "alice-password-1").await;
    let path = format!("/api/admin/users/{alice_id}/reset-2fa");
    let r = call(&app, "POST", &path, Some(&alice), None, &[]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "réservé aux admins");
    let r = call(&app, "POST", &path, Some(&admin), None, &[]).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
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
    // Même code pour la confirmation et le rejeu : le test ne dépend pas du changement de pas de 30 s.
    let code = totp.generate_current().to_string();
    let r =
        call(&app, "POST", "/api/account/totp/confirm", Some(&admin), Some(json!({"code": code})), &[]).await;
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
            "username": "admin", "password": ADMIN_PW, "totp": code
        })),
        &[],
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn proxy_mode() {
    let extra = [
        ("PORTIQUE_AUTH_MODE", "proxy"),
        ("PORTIQUE_TRUSTED_PROXIES", "172.18.0.0/16"),
        ("PORTIQUE_PROXY_ADMIN_GROUP", "admins"),
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

    let r = call(&app, "GET", "/api/me", None, None, &[("Remote-User", "alice"), ("Remote-Groups", "users")])
        .await;
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

#[tokio::test]
async fn ssh_hosts_jumps_and_terminal_prefs() {
    let app = setup(&[], "203.0.113.9:4000").await;
    let admin = login(&app, "admin", ADMIN_PW).await;
    let post = |body: Value| {
        let (app, admin) = (app.clone(), admin.clone());
        async move { call(&app, "POST", "/api/admin/connections", Some(&admin), Some(body), &[]).await }
    };

    // Ni RDP ni SSH : refusé.
    let r = post(json!({"name": "Vide", "host": "10.0.0.1", "rdp": false})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    let gw = post(json!({"name": "Passerelle", "host": "10.0.0.2", "rdp": false,
        "ssh": {"user": "root", "password": "pw-ssh"}}))
    .await;
    assert_eq!(gw.status, StatusCode::CREATED, "{:?}", gw.body);
    assert_eq!(gw.body["rdp"], false);
    assert_eq!(gw.body["ssh"]["port"], 22);
    assert_eq!(gw.body["ssh"]["has_password"], true);
    assert!(gw.body["ssh"].get("password").is_none(), "le mot de passe SSH ne ressort jamais");
    let gw_id = gw.body["id"].as_i64().unwrap();

    let pc = post(json!({"name": "PC", "host": "192.0.2.50", "username": "alice",
        "ssh": {"user": "alice", "port": 2201, "jump": {"kind": "known", "id": gw_id}, "theme": "alerte"}}))
    .await;
    assert_eq!(pc.status, StatusCode::CREATED, "{:?}", pc.body);
    assert_eq!(pc.body["ssh"]["jump"], json!({"kind": "known", "id": gw_id}));
    let pc_id = pc.body["id"].as_i64().unwrap();

    // Boucle : la passerelle ne peut pas passer par le PC qui passe par elle.
    let r = call(
        &app,
        "PUT",
        &format!("/api/admin/connections/{gw_id}"),
        Some(&admin),
        Some(json!({"name": "Passerelle", "host": "10.0.0.2", "rdp": false,
            "ssh": {"user": "root", "jump": {"kind": "known", "id": pc_id}}})),
        &[],
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    // Rebond qui n'est pas un hôte SSH, thème inconnu : refusés.
    let rdp_only = post(json!({"name": "RDP seul", "host": "10.0.0.3"})).await.body["id"].as_i64().unwrap();
    let to_rdp_only = json!({"kind": "known", "id": rdp_only});
    let r = post(json!({"name": "X", "host": "10.0.0.4", "ssh": {"user": "a", "jump": to_rdp_only}})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = post(
        json!({"name": "X", "host": "10.0.0.4", "rdp": false, "ssh": {"user": "a", "jump": to_rdp_only}}),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = post(json!({"name": "X", "host": "10.0.0.4", "ssh": {"user": "a", "theme": "fluo"}})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // Un refus ne laisse rien en base : ni hôte créé à moitié, ni renommage d'un hôte existant.
    let r = call(
        &app,
        "PUT",
        &format!("/api/admin/connections/{rdp_only}"),
        Some(&admin),
        Some(json!({"name": "Renommé", "host": "10.0.0.3", "ssh": {"user": "a", "jump": to_rdp_only}})),
        &[],
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let all = call(&app, "GET", "/api/admin/connections", Some(&admin), None, &[]).await.body;
    let names: Vec<&str> = all.as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert!(!names.contains(&"X") && !names.contains(&"Renommé"), "{names:?}");

    let list = call(&app, "GET", "/api/connections", Some(&admin), None, &[]).await.body;
    let pc = list.as_array().unwrap().iter().find(|c| c["name"] == "PC").unwrap();
    assert_eq!((pc["rdp"].as_bool(), pc["ssh"].as_bool()), (Some(true), Some(true)));

    // Réveil par un hôte SSH déclaré : un autre hôte, qui a le SSH.
    let wol = |via: i64| {
        json!({"name": "PC", "host": "192.0.2.50", "username": "alice", "wol_mac": "00:11:22:33:44:55",
        "ssh": {"user": "alice", "port": 2201, "jump": {"kind": "known", "id": gw_id}},
        "wol_command": {"via": {"kind": "known", "id": via}, "command": "wakeonlan {mac}"}})
    };
    for bad in [pc_id, rdp_only] {
        let r =
            call(&app, "PUT", &format!("/api/admin/connections/{pc_id}"), Some(&admin), Some(wol(bad)), &[])
                .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "réveil par {bad} : {:?}", r.body);
    }
    let r =
        call(&app, "PUT", &format!("/api/admin/connections/{pc_id}"), Some(&admin), Some(wol(gw_id)), &[])
            .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["wol_command"]["via"], json!({"kind": "known", "id": gw_id}));
    // SSH coupé ensuite sur l'hôte de réveil : le réveil est refusé, pas tenté avec ses identifiants.
    let r = call(
        &app,
        "PUT",
        &format!("/api/admin/connections/{gw_id}"),
        Some(&admin),
        Some(json!({"name": "Passerelle", "host": "10.0.0.2"})),
        &[],
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = call(&app, "POST", &format!("/api/connections/{pc_id}/wake"), Some(&admin), None, &[]).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.body["error"].as_str().unwrap().contains("n'a pas de SSH"), "{:?}", r.body);
    // Hôte de réveil et rebond supprimés : le PC passe par des copies saisies, mot de passe compris.
    let r = call(&app, "DELETE", &format!("/api/admin/connections/{gw_id}"), Some(&admin), None, &[]).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let all = call(&app, "GET", "/api/admin/connections", Some(&admin), None, &[]).await.body;
    let pc = all.as_array().unwrap().iter().find(|c| c["id"] == pc_id).unwrap();
    for hop in [&pc["wol_command"]["via"], &pc["ssh"]["jump"]] {
        assert_eq!(hop["kind"], "host", "{pc:?}");
        assert_eq!((hop["host"].as_str(), hop["user"].as_str()), (Some("10.0.0.2"), Some("root")));
        assert_eq!(hop["has_password"], true);
    }
    // Copies d'une passerelle au SSH coupé : coupées aussi, le réveil reste refusé.
    let r = call(&app, "POST", &format!("/api/connections/{pc_id}/wake"), Some(&admin), None, &[]).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.body["error"].as_str().unwrap().contains("n'a pas de SSH"), "{:?}", r.body);

    // Clé du service : créée une fois, stable ensuite.
    let k1 = call(&app, "GET", "/api/admin/ssh-key", Some(&admin), None, &[]).await.body;
    let k2 = call(&app, "GET", "/api/admin/ssh-key", Some(&admin), None, &[]).await.body;
    assert!(k1["public"].as_str().unwrap().starts_with("ssh-ed25519 AAAA"), "{k1:?}");
    assert_eq!(k1, k2);

    // Préférences de terminal : défauts, puis validation.
    let p = call(&app, "GET", "/api/account/terminal", Some(&admin), None, &[]).await.body;
    assert_eq!(p["theme"], "sombre");
    assert_eq!(p["combos"][0], "Ctrl+C");
    let r = call(
        &app,
        "PUT",
        "/api/account/terminal",
        Some(&admin),
        Some(json!({"theme": "nord", "combos": ["Ctrl+C", "Alt+B"]})),
        &[],
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = call(
        &app,
        "PUT",
        "/api/account/terminal",
        Some(&admin),
        Some(json!({"theme": "nord", "combos": ["Shift+C"]})),
        &[],
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // Ctrl+C et Ctrl+c envoient le même octet : doublon. Alt+B et Alt+b, non.
    let dup = json!({"theme": "nord", "combos": ["Ctrl+C", "Ctrl+c"]});
    let r = call(&app, "PUT", "/api/account/terminal", Some(&admin), Some(dup), &[]).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "combinaison en double");
    let alt = json!({"theme": "nord", "combos": ["Alt+B", "Alt+b"]});
    let r = call(&app, "PUT", "/api/account/terminal", Some(&admin), Some(alt), &[]).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let back = json!({"theme": "nord", "combos": ["Ctrl+C", "Alt+B"]});
    assert_eq!(
        call(&app, "PUT", "/api/account/terminal", Some(&admin), Some(back), &[]).await.status,
        StatusCode::OK
    );
    let p = call(&app, "GET", "/api/account/terminal", Some(&admin), None, &[]).await.body;
    assert_eq!(p, json!({"theme": "nord", "combos": ["Ctrl+C", "Alt+B"]}));
}

/// Un nom empreinté absent du disque reçoit le repli (index.html ou 404) : jamais `immutable`.
#[tokio::test]
async fn missing_fingerprinted_asset_is_not_cached_forever() {
    let app = setup(&[], "203.0.113.10:4000").await;
    let req = Request::builder().uri("/portique-web-0123456789abcdef_bg.wasm").body(Body::empty()).unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert!(!res.status().is_success());
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-cache");
}
