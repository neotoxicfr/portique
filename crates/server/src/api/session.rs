//! Session RDP par WebSocket : le serveur ouvre la connexion authentifiée (TLS épinglé + NLA,
//! identifiants Windows jamais transmis au navigateur), puis relaie les octets bruts.

use std::time::Instant;

use axum::{
    extract::{
        Path, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, header},
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use portique_proto::SessionMessage;
use rdp_auth::ntlm::Credentials;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    api::connections::{Row, find_allowed},
    auth::{ClientIp, CurrentUser, UserRow},
    state::{ApiResult, AppError, AppState, bad},
};

/// Le WebSocket n'est pas protégé par CORS : on exige que l'origine soit le site lui-même
/// (sinon une page tierce pourrait ouvrir une session avec le cookie de l'utilisateur).
pub(crate) fn same_origin(headers: &HeaderMap, public: &url::Url) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else { return false };
    url::Url::parse(origin).is_ok_and(|o| o.origin() == public.origin())
}

#[derive(serde::Deserialize)]
pub struct OpenQuery {
    /// Empreinte approuvée par un admin pour un premier contact (hexa SHA-256).
    trust: Option<String>,
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
    if !same_origin(&headers, &state.cfg.public_url) {
        return Err(AppError::Forbidden);
    }
    // Empreinte du cookie de session : la session RDP tombe si la session web est révoquée.
    let token = axum_extra::extract::CookieJar::from_headers(&headers)
        .get(crate::auth::SESSION_COOKIE)
        .map(|c| crate::crypto::token_hash(c.value()));
    // Refus transmis par le WebSocket : le navigateur ne montre pas le corps d'un refus HTTP à l'ouverture.
    let prepared = prepare(&state, &user, id, q.trust.as_deref()).await;
    Ok(ws.max_message_size(1 << 20).on_upgrade(move |socket| async move {
        match prepared {
            Ok((row, trust)) => {
                let _live = state.live.enter(row.id, crate::state::Live::Rdp);
                run(state, user, ip, row, trust, token, socket).await
            }
            Err(e) => {
                // Refus (accès, hôte sans RDP, empreinte invalide) : durable. Erreur interne (base
                // momentanément indisponible) ou trop de tentatives : la reconnexion peut réussir.
                let lasting = matches!(
                    e,
                    AppError::Unauthorized
                        | AppError::Forbidden
                        | AppError::NotFound
                        | AppError::BadRequest(_)
                );
                fail(socket, crate::state::user_message(e), lasting).await
            }
        }
    }))
}

/// Contrôles d'accès d'une ouverture de bureau : hôte autorisé et en RDP, approbation réservée aux admins.
async fn prepare(
    state: &AppState,
    user: &UserRow,
    id: i64,
    trust: Option<&str>,
) -> ApiResult<(Row, Option<[u8; 32]>)> {
    let row = find_allowed(&state.db, user.id, user.is_admin, id).await?;
    if !row.rdp_enabled {
        return Err(bad("pas de RDP sur cet hôte"));
    }
    let trust = match trust {
        Some(t) if user.is_admin => Some(
            <[u8; 32]>::try_from(hex::decode(t).map_err(|_| bad("empreinte invalide"))?)
                .map_err(|_| bad("empreinte invalide"))?,
        ),
        Some(_) => return Err(AppError::Forbidden),
        None => None,
    };
    Ok((row, trust))
}

async fn send_text(socket: &mut WebSocket, msg: &SessionMessage) {
    if let Ok(json) = serde_json::to_string(msg) {
        let _ = socket.send(Message::Text(json.into())).await;
    }
}

/// `lasting` : refus durable, le navigateur ne relance pas la connexion.
async fn fail(mut socket: WebSocket, message: String, lasting: bool) {
    send_text(&mut socket, &SessionMessage::Error { message, lasting }).await;
    let _ = socket.close().await;
}

/// La session web, l'accès à la connexion et le protocole du relais (`enabled` : RDP ou SSH, l'autre
/// pouvant rester actif sur le même hôte) sont-ils toujours valides ?
pub(crate) async fn still_allowed(
    state: &AppState,
    user_id: i64,
    connection_id: i64,
    token: Option<&[u8]>,
    enabled: fn(&Row) -> bool,
) -> bool {
    let user = match crate::auth::user_by_id(&state.db, user_id).await {
        Ok(Some(u)) => u,
        _ => return false,
    };
    if state.cfg.auth_mode == portique_proto::AuthMode::Builtin {
        let Some(token) = token else { return false };
        let alive: Result<Option<i64>, _> = sqlx::query_scalar(
            "SELECT 1 FROM sessions WHERE token_hash = ? AND user_id = ? AND expires_at >= unixepoch()",
        )
        .bind(token)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await;
        if !matches!(alive, Ok(Some(_))) {
            return false;
        }
    }
    find_allowed(&state.db, user.id, user.is_admin, connection_id).await.is_ok_and(|r| enabled(&r))
}

pub(crate) const REVALIDATE_EVERY: std::time::Duration = std::time::Duration::from_secs(30);

async fn run(
    state: AppState,
    user: UserRow,
    ip: std::net::IpAddr,
    row: Row,
    trust: Option<[u8; 32]>,
    token: Option<Vec<u8>>,
    mut socket: WebSocket,
) {
    let password = match &row.password {
        Some(sealed) => match state.vault.open(&format!("connection:{}", row.id), sealed) {
            Ok(p) => String::from_utf8_lossy(&p).into_owned(),
            Err(e) => return fail(socket, format!("mot de passe illisible : {e}"), true).await,
        },
        None => {
            return fail(socket, "aucun mot de passe Windows enregistré pour cette connexion".into(), true)
                .await;
        }
    };
    let target = rdp_connect::Target {
        host: row.host.clone(),
        port: row.port as u16,
        credentials: Credentials { username: row.username.clone(), domain: row.domain.clone(), password },
    };
    let stored = row.cert_sha256.as_deref().and_then(|b| <[u8; 32]>::try_from(b).ok());
    let pinned = stored.or(trust);
    let started = Instant::now();
    tracing::info!(user = user.username, %ip, connection = row.name, "ouverture de session");
    let connected = match rdp_connect::connect(&target, pinned).await {
        Ok(c) => c,
        Err(rdp_connect::ConnectError::UntrustedCertificate(fingerprint)) => {
            send_text(
                &mut socket,
                &SessionMessage::UntrustedCertificate { fingerprint, can_approve: user.is_admin },
            )
            .await;
            let _ = socket.close().await;
            return;
        }
        Err(e) => {
            tracing::warn!(user = user.username, connection = row.name, "échec de connexion : {e}");
            // Identifiants refusés ou certificat changé : réessayer ne changera rien. Le reste (PC
            // injoignable, délai, TLS, négociation) peut venir d'un PC qui redémarre.
            let lasting = matches!(
                e,
                rdp_connect::ConnectError::Auth(_) | rdp_connect::ConnectError::CertificateMismatch { .. }
            );
            return fail(socket, e.to_string(), lasting).await;
        }
    };
    let tm = connected.timings;
    tracing::info!(
        connection = row.name,
        tcp_ms = tm.tcp,
        x224_ms = tm.x224,
        tls_ms = tm.tls,
        nla_ms = tm.nla,
        total_ms = started.elapsed().as_millis() as u64,
        "connexion RDP prête"
    );
    // Empreinte approuvée par un admin et vérifiée avant CredSSP : on l'épingle, si la cible n'a pas changé
    // entre-temps (sinon le certificat de l'ancien PC serait épinglé sur le nouveau).
    let pinned_now = stored.is_none()
        && sqlx::query(
            "UPDATE connections SET cert_sha256 = ? WHERE id = ? AND cert_sha256 IS NULL AND host = ? AND port = ?",
        )
        .bind(connected.cert_sha256.to_vec())
        .bind(row.id)
        .bind(&row.host)
        .bind(row.port)
        .execute(&state.db)
        .await
        .is_ok_and(|r| r.rows_affected() == 1);
    if pinned_now {
        tracing::info!(
            user = user.username,
            connection = row.name,
            fingerprint = rdp_connect::hex(&connected.cert_sha256),
            "certificat approuvé et épinglé"
        );
    }
    send_text(
        &mut socket,
        &SessionMessage::Ready {
            selected_protocol: connected.selected_protocol,
            negotiation_flags: connected.negotiation_flags,
            username: row.username.clone(),
            domain: row.domain.clone(),
        },
    )
    .await;

    let (mut ws_tx, mut ws_rx) = socket.split();
    let (mut rdp_rx, mut rdp_tx) = tokio::io::split(connected.stream);
    let (mut up, mut down) = (0u64, 0u64);
    let to_pc = async {
        while let Some(Ok(msg)) = ws_rx.next().await {
            match msg {
                Message::Binary(b) => {
                    up += b.len() as u64;
                    // TLS : sans flush, la fin d'un message chiffré peut rester en tampon jusqu'à
                    // l'écriture suivante (une frappe isolée partirait en retard).
                    if rdp_tx.write_all(&b).await.is_err() || rdp_tx.flush().await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        let _ = rdp_tx.shutdown().await;
    };
    let to_browser = async {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match rdp_rx.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    down += n as u64;
                    if ws_tx.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = ws_tx.close().await;
    };
    let watchdog = async {
        let mut tick = tokio::time::interval(REVALIDATE_EVERY);
        tick.tick().await;
        loop {
            tick.tick().await;
            if !still_allowed(&state, user.id, row.id, token.as_deref(), |r| r.rdp_enabled).await {
                tracing::info!(user = user.username, connection = row.name, "session révoquée : coupure");
                break;
            }
        }
    };
    // La première moitié qui se termine coupe les autres (fin RDP, fermeture, révocation).
    tokio::select! {
        _ = to_pc => {}
        _ = to_browser => {}
        _ = watchdog => {}
    }
    tracing::info!(
        user = user.username,
        connection = row.name,
        seconds = started.elapsed().as_secs(),
        up_kib = up / 1024,
        down_kib = down / 1024,
        "fin de session"
    );
}

#[cfg(test)]
mod tests {
    /// Couper le RDP d'un hôte coupe ses relais RDP ouverts, pas ses terminaux SSH (et inversement).
    #[tokio::test]
    async fn watchdog_checks_the_relay_protocol() {
        let s = crate::api::ssh::tests::state("builtin").await;
        let admin = crate::auth::user_by_name(&s.db, "admin").await.unwrap().unwrap();
        let token = crate::crypto::token_hash("jeton");
        sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, expires_at, mfa) VALUES (?, ?, unixepoch() + 60, 1)",
        )
        .bind(&token)
        .bind(admin.id)
        .execute(&s.db)
        .await
        .unwrap();
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO connections (name, host, port, rdp_enabled, ssh_enabled) VALUES ('H', '192.0.2.10', 3389, 0, 1)
             RETURNING id",
        )
        .fetch_one(&s.db)
        .await
        .unwrap();
        assert!(!super::still_allowed(&s, admin.id, id, Some(&token), |r| r.rdp_enabled).await);
        assert!(super::still_allowed(&s, admin.id, id, Some(&token), |r| r.ssh_enabled).await);
    }
}
