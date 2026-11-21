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
use sqlx::SqliteConnection;

use crate::{
    api::{
        account::terminal_prefs,
        connections::{find_allowed, find_hop},
        session::{REVALIDATE_EVERY, same_origin, still_allowed},
    },
    auth::{AdminUser, ClientIp, CurrentUser, UserRow},
    crypto::Vault,
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
/// Exception voulue : le réveil par un hôte SSH (`connections::wake`), qui ne lance que la commande de
/// l'admin avec une MAC de la base.
pub(crate) async fn session_has_mfa(
    state: &AppState,
    user: &UserRow,
    token: Option<&[u8]>,
) -> ApiResult<bool> {
    if state.cfg.auth_mode == AuthMode::Proxy {
        return Ok(true);
    }
    let Some(token) = token else { return Ok(false) };
    let mfa: Option<bool> = sqlx::query_scalar(
        "SELECT mfa FROM sessions WHERE token_hash = ? AND user_id = ? AND expires_at >= unixepoch()",
    )
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

/// Durée maximale d'ouverture de toute la chaîne, shell compris.
const OPEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// Octets reçus du navigateur pendant l'ouverture, gardés pour l'hôte.
const MAX_PENDING: usize = 64 * 1024;

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
    Ok((chain(state, row.id).await?, host_theme, trust))
}

/// Chaîne des sauts, premier rebond d'abord, cible en dernier, lue dans une transaction : une suppression
/// d'hôte qui convertit les références entre deux lectures ne la casse pas. Les rebonds n'ont pas à être
/// accessibles à l'utilisateur : seul l'accès à la cible compte.
pub(crate) async fn chain(state: &AppState, target: i64) -> ApiResult<Vec<Hop>> {
    let mut tx = state.db.begin().await?;
    chain_in(&mut tx, &state.vault, target).await
}

/// `chain` sur une connexion déjà ouverte (et son instantané).
pub(crate) async fn chain_in(db: &mut SqliteConnection, vault: &Vault, target: i64) -> ApiResult<Vec<Hop>> {
    let target = find_hop(&mut *db, target).await?;
    // Vérifié ici pour tous les appelants (terminal, réveil par un hôte) : le SSH a pu être coupé depuis.
    if !target.ssh_enabled {
        return Err(bad(format!("« {} » n'a pas de SSH", target.name)));
    }
    let mut rows = vec![target];
    while let Some(jump) = rows.last().and_then(|r| r.ssh_jump_id) {
        if rows.len() >= ssh::MAX_HOPS || rows.iter().any(|r| r.id == jump) {
            return Err(bad("chaîne de rebonds invalide (boucle ou trop longue)"));
        }
        let r = find_hop(&mut *db, jump).await?;
        if !r.ssh_enabled {
            return Err(bad(format!("le rebond « {} » n'a pas de SSH", r.name)));
        }
        rows.push(r);
    }
    rows.reverse();
    rows.into_iter()
        .map(|r| {
            let password = match &r.ssh_password {
                Some(sealed) => {
                    Some(String::from_utf8_lossy(&vault.open(&format!("ssh:{}", r.id), sealed)?).into_owned())
                }
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

/// Épingle les clés d'hôte approuvées à cette ouverture, si l'adresse et le port du saut n'ont pas changé
/// depuis sa lecture : sinon la clé de l'ancien hôte serait épinglée sur le nouveau.
async fn pin(state: &AppState, user: &UserRow, hops: &[Hop], pinned: &[(i64, String)]) {
    for (id, fp) in pinned {
        let Some(hop) = hops.iter().find(|h| h.id == *id) else { continue };
        let done = sqlx::query(
            "UPDATE connections SET ssh_hostkey = ?, ssh_hostkey_pending = NULL
             WHERE id = ? AND ssh_hostkey IS NULL AND host = ? AND ssh_port = ?",
        )
        .bind(fp)
        .bind(id)
        .bind(&hop.host)
        .bind(i64::from(hop.port))
        .execute(&state.db)
        .await
        .is_ok_and(|r| r.rows_affected() == 1);
        if done {
            tracing::info!(
                user = user.username,
                host = id,
                fingerprint = fp,
                "clé SSH d'hôte approuvée et épinglée"
            );
        }
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
    // Ouverture bornée dans le temps et abandonnée si l'onglet se ferme : sinon la tâche et les connexions
    // de la chaîne resteraient pendues sur un hôte muet, à chaque nouvelle tentative.
    // Ce que le navigateur envoie entre-temps (saisie, redimensionnement) est gardé pour l'hôte ; au-delà
    // de `MAX_PENDING`, l'ouverture échoue plutôt que de perdre une partie de la saisie.
    let opening = tokio::time::timeout(OPEN_TIMEOUT, ssh::open(&hops, &key, trust_ref, cols, rows));
    let mut pending = Vec::new();
    // Fin de l'attente côté navigateur : `true` si la saisie dépasse la limite, `false` si l'onglet se ferme.
    let gone = async {
        let mut kept = 0;
        while let Some(Ok(msg)) = socket.recv().await {
            if matches!(msg, Message::Close(_)) {
                break;
            }
            // Chaque message coûte au moins 64 octets : des messages vides ne font pas grossir la file sans fin.
            kept += 64
                + match &msg {
                    Message::Binary(b) => b.len(),
                    Message::Text(t) => t.len(),
                    _ => 0,
                };
            if kept > MAX_PENDING {
                return true;
            }
            pending.push(Ok::<_, axum::Error>(msg));
        }
        false
    };
    let opened = tokio::select! {
        r = opening => r.unwrap_or_else(|_| Err(anyhow::anyhow!("ouverture SSH trop longue (délai dépassé)").into())),
        overflow = gone => {
            if overflow {
                tracing::info!(user = user.username, connection = target.1, "saisie trop abondante pendant l'ouverture SSH");
                let message = "trop de saisie pendant l'ouverture du terminal, rien n'a été envoyé : réessaie".into();
                return send(&mut socket, &fail(message)).await;
            }
            tracing::info!(user = user.username, connection = target.1, "onglet fermé pendant l'ouverture SSH");
            return;
        }
    };
    let opened = match opened {
        Ok(o) => o,
        Err(OpenError::Unapproved { id, name, fingerprint, pinned }) => {
            pin(&state, &user, &hops, &pinned).await;
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
    pin(&state, &user, &hops, &opened.pinned).await;
    let prefs = terminal_prefs(&state.db, user.id).await.unwrap_or_else(|_| portique_proto::TerminalPrefs {
        theme: portique_proto::TERMINAL_THEMES[0].into(),
        combos: portique_proto::DEFAULT_COMBOS.iter().map(|c| (*c).into()).collect(),
    });
    send(
        &mut socket,
        &SshMessage::Ready {
            name: target.1.clone(),
            theme: host_theme.unwrap_or(prefs.theme),
            combos: prefs.combos,
        },
    )
    .await;
    if !opened.early.is_empty() {
        let _ = socket.send(Message::Binary(opened.early.into())).await;
    }

    let _sessions = opened.sessions;
    let (mut from_host, to_host) = opened.channel.split();
    let (mut ws_tx, mut ws_rx) = socket.split();
    let upstream = async {
        let mut incoming = futures_util::stream::iter(pending).chain(&mut ws_rx);
        while let Some(Ok(msg)) = incoming.next().await {
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
                // Pas `ExitStatus` : la fin du processus peut précéder ses derniers octets.
                ChannelMsg::Eof | ChannelMsg::Close => break,
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
            if !still_allowed(&state, user.id, target.0, token.as_deref(), |r| r.ssh_enabled).await {
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
pub(crate) mod tests {
    use super::session_has_mfa;
    use crate::config::{Config, Env};

    struct V(Vec<(&'static str, &'static str)>);
    impl Env for V {
        fn var(&self, k: &str) -> Option<String> {
            self.0.iter().find(|(a, _)| *a == k).map(|(_, v)| v.to_string())
        }
    }

    /// État complet sur une base en mémoire, compte `admin` créé (servi aussi aux tests des autres modules).
    pub(crate) async fn state(mode: &'static str) -> crate::state::AppState {
        state_on(mode, crate::open_db("sqlite::memory:").await.unwrap()).await
    }

    /// Comme `state`, sur une base déjà migrée (préparée à une version antérieure, par exemple).
    pub(crate) async fn state_on(mode: &'static str, db: sqlx::SqlitePool) -> crate::state::AppState {
        let mut env = vec![
            ("PORTIQUE_PUBLIC_URL", "https://portique.example.com"),
            ("PORTIQUE_MASTER_KEY", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="), // gitleaks:allow (octets 0..31, factice)
            ("PORTIQUE_ADMIN_PASSWORD", "admin-password-123"),
            ("PORTIQUE_AUTH_MODE", mode),
        ];
        if mode == "proxy" {
            env.push(("PORTIQUE_TRUSTED_PROXIES", "127.0.0.1"));
        }
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
        sqlx::query("UPDATE sessions SET expires_at = unixepoch() - 1 WHERE token_hash = ?")
            .bind(b"avec".as_slice())
            .execute(&s.db)
            .await
            .unwrap();
        assert!(!session_has_mfa(&s, &user, Some(b"avec")).await.unwrap(), "session expirée : refusée");
        // Mode proxy : la 2FA est l'affaire du proxy.
        let p = state("proxy").await;
        assert!(session_has_mfa(&p, &user, None).await.unwrap());
    }

    /// Un compte à passkey seule se connecte encore au mot de passe : cette session-là ne doit pas
    /// enrôler un autre facteur, sinon un mot de passe volé suffit à ouvrir le SSH.
    #[tokio::test]
    async fn a_password_only_session_cannot_add_a_factor_to_a_protected_account() {
        use crate::{api::account::second_factor_gate, auth::SESSION_COOKIE, crypto::token_hash};
        use axum_extra::extract::{CookieJar, cookie::Cookie};
        let s = state("builtin").await;
        let user = crate::auth::user_by_name(&s.db, "admin").await.unwrap().unwrap();
        for (token, mfa) in [("sans", false), ("avec", true)] {
            sqlx::query("INSERT INTO sessions (token_hash, user_id, expires_at, mfa) VALUES (?, ?, unixepoch() + 60, ?)")
                .bind(token_hash(token))
                .bind(user.id)
                .bind(mfa)
                .execute(&s.db)
                .await
                .unwrap();
        }
        let jar = |t: &'static str| CookieJar::new().add(Cookie::new(SESSION_COOKIE, t));
        assert!(second_factor_gate(&s, &user, &jar("sans")).await.is_ok(), "premier facteur : libre");
        sqlx::query("INSERT INTO passkeys (user_id, name, credential) VALUES (?, 'clé', '{}')")
            .bind(user.id)
            .execute(&s.db)
            .await
            .unwrap();
        assert!(second_factor_gate(&s, &user, &jar("sans")).await.is_err(), "mot de passe seul : refusé");
        assert!(second_factor_gate(&s, &user, &jar("avec")).await.is_ok());
        // Retirer la passkey depuis la session au mot de passe seul rouvrirait l'enrôlement libre.
        let id: i64 = sqlx::query_scalar("SELECT id FROM passkeys").fetch_one(&s.db).await.unwrap();
        let delete = |t| {
            crate::api::account::passkey_delete(
                axum::extract::State(s.clone()),
                crate::auth::CurrentUser(user.clone()),
                jar(t),
                axum::extract::Path(id),
            )
        };
        assert!(delete("sans").await.is_err(), "suppression au mot de passe seul : refusée");
        assert!(delete("avec").await.is_ok());
        let mut totp = user.clone();
        totp.totp_secret = Some(vec![1]);
        assert!(second_factor_gate(&s, &totp, &jar("sans")).await.is_err(), "TOTP actif : refusé aussi");
    }

    /// Clé approuvée depuis le terminal : celle qu'un réveil avait mise en attente n'est plus à approuver.
    #[tokio::test]
    async fn pinning_clears_the_pending_hostkey() {
        let s = state("builtin").await;
        let user = crate::auth::user_by_name(&s.db, "admin").await.unwrap().unwrap();
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO connections (name, host, port, ssh_enabled, ssh_port, ssh_hostkey_pending)
             VALUES ('saisi', '192.0.2.1', 3389, 1, 22, 'SHA256:vue') RETURNING id",
        )
        .fetch_one(&s.db)
        .await
        .unwrap();
        let hop = super::Hop {
            id,
            name: "saisi".into(),
            host: "192.0.2.1".into(),
            port: 22,
            user: "root".into(),
            password: None,
            hostkey: None,
        };
        super::pin(&s, &user, &[hop], &[(id, "SHA256:vue".into())]).await;
        let (key, pending): (Option<String>, Option<String>) =
            sqlx::query_as("SELECT ssh_hostkey, ssh_hostkey_pending FROM connections WHERE id = ?")
                .bind(id)
                .fetch_one(&s.db)
                .await
                .unwrap();
        assert_eq!((key.as_deref(), pending), (Some("SHA256:vue"), None));
    }
}
