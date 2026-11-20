//! Session SSH par WebSocket : le serveur ouvre la chaîne de rebonds avec la clé du service, puis
//! relaie le terminal (binaire dans les deux sens, `SshControl` en texte pour le redimensionnement).

use std::time::Instant;

use axum::{
    Json,
    extract::{
        Path, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::HeaderMap,
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use portique_proto::{AuthMode, ServiceKey, SshControl, SshMessage};
use russh::ChannelMsg;

use crate::{
    api::{
        account::terminal_prefs,
        connections::{Row, find_allowed},
        session::{REVALIDATE_EVERY, same_origin, still_allowed},
    },
    auth::{AdminUser, ClientIp, CurrentUser, UserRow},
    ssh::{self, Hop, OpenError},
    state::{ApiResult, AppError, AppState, bad},
};

#[derive(serde::Deserialize)]
pub struct OpenQuery {
    cols: Option<u16>,
    rows: Option<u16>,
    /// Empreinte (format OpenSSH) qu'un admin approuve pour l'hôte `trust_for`.
    trust: Option<String>,
    trust_for: Option<i64>,
}

/// Clé publique du service, à poser dans `authorized_keys` des hôtes.
pub async fn service_key(State(state): State<AppState>, _: AdminUser) -> ApiResult<Json<ServiceKey>> {
    let key = ssh::service_key(&state).await?;
    Ok(Json(ServiceKey { public: ssh::public_line(&key)? }))
}

/// La clé du service ouvre toutes les machines : en mode intégré, la session doit avoir été ouverte
/// avec un second facteur (TOTP ou passkey) ; avoir une 2FA enregistrée ne suffit pas (un mot de passe
/// volé permettrait d'en enregistrer une). En mode proxy, c'est au proxy d'exiger la 2FA.
async fn session_has_mfa(state: &AppState, user: &UserRow, token: Option<&[u8]>) -> ApiResult<bool> {
    if state.cfg.auth_mode == AuthMode::Proxy {
        return Ok(true);
    }
    let Some(token) = token else { return Ok(false) };
    let mfa: Option<bool> =
        sqlx::query_scalar("SELECT mfa FROM sessions WHERE token_hash = ? AND user_id = ?")
            .bind(token)
            .bind(user.id)
            .fetch_optional(&state.db)
            .await?;
    Ok(mfa == Some(true))
}

pub async fn open(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    ClientIp(ip): ClientIp,
    Path(id): Path<i64>,
    Query(q): Query<OpenQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    // Contrôle d'origine : refus net, c'est lui qui protège le WebSocket des pages tierces.
    if !same_origin(&headers, &state.cfg.public_url) {
        return Err(AppError::Forbidden);
    }
    let token = axum_extra::extract::CookieJar::from_headers(&headers)
        .get(crate::auth::SESSION_COOKIE)
        .map(|c| crate::crypto::token_hash(c.value()));
    let size = (q.cols.unwrap_or(80).clamp(10, 500), q.rows.unwrap_or(24).clamp(5, 300));
    // Les autres refus passent par le WebSocket : le navigateur ne montre pas le corps d'un refus HTTP
    // à l'ouverture, l'utilisateur ne verrait que « session terminée » sans la raison.
    let prepared = prepare(&state, &user, id, q.trust.zip(q.trust_for), token.as_deref()).await;
    Ok(ws.max_message_size(1 << 20).on_upgrade(move |mut socket| async move {
        match prepared {
            Ok((hops, host_theme, trust)) => {
                run(state, user, ip, hops, host_theme, trust, size, token, socket).await
            }
            Err(e) => {
                send(&mut socket, &SshMessage::Error { message: crate::state::user_message(e) }).await;
                let _ = socket.close().await;
            }
        }
    }))
}

type Prepared = (Vec<Hop>, Option<String>, Option<(i64, String)>);

/// Contrôles d'accès d'une ouverture de terminal : hôte autorisé et en SSH, session à double
/// authentification, approbation de clé réservée aux admins.
async fn prepare(
    state: &AppState,
    user: &UserRow,
    id: i64,
    trust: Option<(String, i64)>,
    token: Option<&[u8]>,
) -> ApiResult<Prepared> {
    let row = find_allowed(&state.db, user.id, user.is_admin, id).await?;
    if !row.ssh_enabled {
        return Err(bad("pas de SSH sur cet hôte"));
    }
    if !session_has_mfa(state, user, token).await? {
        return Err(bad(
            "le SSH exige une session ouverte avec la double authentification : active un TOTP ou une passkey, \
             puis reconnecte-toi avec",
        ));
    }
    let trust = match trust {
        Some((fp, host)) if user.is_admin => Some((host, fp)),
        Some(_) => return Err(AppError::Forbidden),
        None => None,
    };
    let host_theme = row.ssh_theme.clone();
    Ok((chain(state, row).await?, host_theme, trust))
}

/// Chaîne des sauts, premier rebond d'abord, cible en dernier. Les rebonds n'ont pas à être
/// accessibles à l'utilisateur : seul l'accès à la cible compte.
pub(crate) async fn chain(state: &AppState, target: Row) -> ApiResult<Vec<Hop>> {
    // Vérifié ici pour tous les appelants (terminal, réveil par un hôte) : le SSH a pu être coupé depuis.
    if !target.ssh_enabled {
        return Err(bad(format!("« {} » n'a pas de SSH", target.name)));
    }
    let mut rows = vec![target];
    while let Some(jump) = rows.last().and_then(|r| r.ssh_jump_id) {
        if rows.len() >= ssh::MAX_HOPS || rows.iter().any(|r| r.id == jump) {
            return Err(bad("chaîne de rebonds invalide (boucle ou trop longue)"));
        }
        let r = find_allowed(&state.db, 0, true, jump).await?;
        if !r.ssh_enabled {
            return Err(bad(format!("le rebond « {} » n'a pas de SSH", r.name)));
        }
        rows.push(r);
    }
    rows.reverse();
    rows.into_iter()
        .map(|r| {
            let password = match &r.ssh_password {
                Some(sealed) => Some(
                    String::from_utf8_lossy(&state.vault.open(&format!("ssh:{}", r.id), sealed)?)
                        .into_owned(),
                ),
                None => None,
            };
            Ok(Hop {
                id: r.id,
                name: r.name,
                host: r.host,
                port: r.ssh_port as u16,
                user: r.ssh_user,
                password,
                hostkey: r.ssh_hostkey,
            })
        })
        .collect()
}

async fn send(socket: &mut WebSocket, msg: &SshMessage) {
    if let Ok(json) = serde_json::to_string(msg) {
        let _ = socket.send(Message::Text(json.into())).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn run(
    state: AppState,
    user: UserRow,
    ip: std::net::IpAddr,
    hops: Vec<Hop>,
    host_theme: Option<String>,
    trust: Option<(i64, String)>,
    (cols, rows): (u16, u16),
    token: Option<Vec<u8>>,
    mut socket: WebSocket,
) {
    let target = hops.last().map(|h| (h.id, h.name.clone())).unwrap_or_default();
    let fail = |message: String| SshMessage::Error { message };
    let key = match ssh::service_key(&state).await {
        Ok(k) => k,
        Err(e) => return send(&mut socket, &fail(format!("clé SSH du service : {e:#}"))).await,
    };
    let started = Instant::now();
    tracing::info!(user = user.username, %ip, connection = target.1, hops = hops.len(), "ouverture SSH");
    let trust_ref = trust.as_ref().map(|(id, fp)| (*id, fp.as_str()));
    let opened = match ssh::open(&hops, &key, trust_ref, cols, rows).await {
        Ok(o) => o,
        Err(OpenError::Unapproved { id, name, fingerprint }) => {
            let msg = SshMessage::UntrustedHostKey {
                connection_id: id,
                name,
                fingerprint,
                can_approve: user.is_admin,
            };
            send(&mut socket, &msg).await;
            let _ = socket.close().await;
            return;
        }
        Err(OpenError::Failed(e)) => {
            tracing::warn!(user = user.username, connection = target.1, "échec SSH : {e:#}");
            return send(&mut socket, &fail(format!("{e:#}"))).await;
        }
    };
    for (id, fp) in &opened.pinned {
        let _ = sqlx::query("UPDATE connections SET ssh_hostkey = ? WHERE id = ? AND ssh_hostkey IS NULL")
            .bind(fp)
            .bind(id)
            .execute(&state.db)
            .await;
        tracing::info!(
            user = user.username,
            host = id,
            fingerprint = fp,
            "clé SSH d'hôte approuvée et épinglée"
        );
    }
    let prefs = terminal_prefs(&state.db, user.id).await.unwrap_or_else(|_| portique_proto::TerminalPrefs {
        theme: portique_proto::TERMINAL_THEMES[0].into(),
        combos: portique_proto::DEFAULT_COMBOS.iter().map(|c| (*c).into()).collect(),
    });
    send(&mut socket, &SshMessage::Ready { theme: host_theme.unwrap_or(prefs.theme), combos: prefs.combos })
        .await;

    let _sessions = opened.sessions;
    let (mut from_host, to_host) = opened.channel.split();
    let (mut ws_tx, mut ws_rx) = socket.split();
    let upstream = async {
        while let Some(Ok(msg)) = ws_rx.next().await {
            match msg {
                Message::Binary(b) => {
                    if to_host.data(&b[..]).await.is_err() {
                        break;
                    }
                }
                Message::Text(t) => {
                    if let Ok(SshControl::Resize { cols, rows }) = serde_json::from_str(&t) {
                        let (c, r) = (cols.clamp(10, 500), rows.clamp(5, 300));
                        let _ = to_host.window_change(u32::from(c), u32::from(r), 0, 0).await;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        let _ = to_host.eof().await;
    };
    let downstream = async {
        while let Some(msg) = from_host.wait().await {
            match msg {
                ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                    if ws_tx.send(Message::Binary(data.to_vec().into())).await.is_err() {
                        break;
                    }
                }
                ChannelMsg::Eof | ChannelMsg::Close | ChannelMsg::ExitStatus { .. } => break,
                _ => {}
            }
        }
        let _ = ws_tx.close().await;
    };
    let watchdog = async {
        let mut tick = tokio::time::interval(REVALIDATE_EVERY);
        tick.tick().await;
        loop {
            tick.tick().await;
            if !still_allowed(&state, user.id, target.0, token.as_deref()).await {
                tracing::info!(user = user.username, connection = target.1, "session révoquée : coupure SSH");
                break;
            }
        }
    };
    tokio::select! {
        _ = upstream => {}
        _ = downstream => {}
        _ = watchdog => {}
    }
    tracing::info!(
        user = user.username,
        connection = target.1,
        seconds = started.elapsed().as_secs(),
        "fin SSH"
    );
}

#[cfg(test)]
mod tests {
    use super::session_has_mfa;
    use crate::config::{Config, Env};

    struct V(Vec<(&'static str, &'static str)>);
    impl Env for V {
        fn var(&self, k: &str) -> Option<String> {
            self.0.iter().find(|(a, _)| *a == k).map(|(_, v)| v.to_string())
        }
    }

    async fn state(mode: &'static str) -> crate::state::AppState {
        let mut env = vec![
            ("PORTIQUE_PUBLIC_URL", "https://portique.example.com"),
            ("PORTIQUE_MASTER_KEY", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="), // gitleaks:allow (octets 0..31, factice)
            ("PORTIQUE_ADMIN_PASSWORD", "admin-password-123"),
            ("PORTIQUE_AUTH_MODE", mode),
        ];
        if mode == "proxy" {
            env.push(("PORTIQUE_TRUSTED_PROXIES", "127.0.0.1"));
        }
        let db = crate::open_db("sqlite::memory:").await.unwrap();
        let s = crate::build_state(Config::from_env(&V(env)).unwrap(), db).unwrap();
        crate::bootstrap_admin(&s).await.unwrap();
        s
    }

    /// Le SSH dépend de la façon dont la SESSION a été ouverte, pas de la 2FA enregistrée sur le compte :
    /// avec un mot de passe volé, on pourrait enregistrer sa propre 2FA dans une session sans second facteur.
    #[tokio::test]
    async fn ssh_requires_a_session_opened_with_a_second_factor() {
        let s = state("builtin").await;
        let mut user = crate::auth::user_by_name(&s.db, "admin").await.unwrap().unwrap();
        user.totp_secret = Some(vec![1]); // 2FA enregistrée sur le compte
        for (token, mfa) in [(b"sans".as_slice(), false), (b"avec".as_slice(), true)] {
            sqlx::query("INSERT INTO sessions (token_hash, user_id, expires_at, mfa) VALUES (?, ?, unixepoch() + 60, ?)")
                .bind(token)
                .bind(user.id)
                .bind(mfa)
                .execute(&s.db)
                .await
                .unwrap();
        }
        assert!(!session_has_mfa(&s, &user, Some(b"sans")).await.unwrap(), "mot de passe seul : refusé");
        assert!(session_has_mfa(&s, &user, Some(b"avec")).await.unwrap());
        assert!(!session_has_mfa(&s, &user, None).await.unwrap(), "pas de session : refusé");
        assert!(!session_has_mfa(&s, &user, Some(b"inconnue")).await.unwrap());
        // Mode proxy : la 2FA est l'affaire du proxy.
        let p = state("proxy").await;
        assert!(session_has_mfa(&p, &user, None).await.unwrap());
    }
}
