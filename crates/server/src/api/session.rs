//! Session RDP par WebSocket : le serveur ouvre la connexion authentifiée (TLS épinglé + NLA,
//! identifiants Windows jamais transmis au navigateur), puis relaie les octets bruts.

use std::time::Instant;

use axum::{
    extract::{
        Path, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, header},
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use rdp_auth::ntlm::Credentials;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yawrdp_proto::SessionMessage;

use crate::{
    api::connections::{Row, find_allowed},
    auth::{ClientIp, CurrentUser, UserRow},
    state::{ApiResult, AppError, AppState, bad},
};

/// Le WebSocket n'est pas protégé par CORS : on exige que l'origine soit le site lui-même
/// (sinon une page tierce pourrait ouvrir une session avec le cookie de l'utilisateur).
fn same_origin(headers: &HeaderMap, public: &url::Url) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else { return false };
    url::Url::parse(origin).is_ok_and(|o| o.origin() == public.origin())
}

pub async fn open(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    ClientIp(ip): ClientIp,
    Path(id): Path<i64>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    if !same_origin(&headers, &state.cfg.public_url) {
        return Err(AppError::Forbidden);
    }
    let row = find_allowed(&state.db, user.id, user.is_admin, id).await?;
    if row.protocol != "rdp" {
        return Err(bad("seul le RDP est disponible pour l'instant"));
    }
    Ok(ws.max_message_size(1 << 20).on_upgrade(move |socket| run(state, user, ip, row, socket)))
}

async fn send_text(socket: &mut WebSocket, msg: &SessionMessage) {
    if let Ok(json) = serde_json::to_string(msg) {
        let _ = socket.send(Message::Text(json.into())).await;
    }
}

async fn fail(mut socket: WebSocket, message: String) {
    send_text(&mut socket, &SessionMessage::Error { message }).await;
    let _ = socket.close().await;
}

async fn run(state: AppState, user: UserRow, ip: std::net::IpAddr, row: Row, mut socket: WebSocket) {
    let password = match &row.password {
        Some(sealed) => match state.vault.open(&format!("connection:{}", row.id), sealed) {
            Ok(p) => String::from_utf8_lossy(&p).into_owned(),
            Err(e) => return fail(socket, format!("mot de passe illisible : {e}")).await,
        },
        None => {
            return fail(socket, "aucun mot de passe Windows enregistré pour cette connexion".into()).await;
        }
    };
    let target = rdp_connect::Target {
        host: row.host.clone(),
        port: row.port as u16,
        credentials: Credentials { username: row.username.clone(), domain: row.domain.clone(), password },
    };
    let pinned = row.cert_sha256.as_deref().and_then(|b| <[u8; 32]>::try_from(b).ok());
    let started = Instant::now();
    tracing::info!(user = user.username, %ip, connection = row.name, "ouverture de session");
    let connected = match rdp_connect::connect(&target, pinned).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(user = user.username, connection = row.name, "échec de connexion : {e}");
            return fail(socket, e.to_string()).await;
        }
    };
    if pinned.is_none() {
        // Confiance au premier usage : l'empreinte est mémorisée pour les fois suivantes.
        let _ = sqlx::query("UPDATE connections SET cert_sha256 = ? WHERE id = ? AND cert_sha256 IS NULL")
            .bind(connected.cert_sha256.to_vec())
            .bind(row.id)
            .execute(&state.db)
            .await;
        tracing::info!(
            connection = row.name,
            fingerprint = rdp_connect::hex(&connected.cert_sha256),
            "certificat épinglé"
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
                    if rdp_tx.write_all(&b).await.is_err() {
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
    // La première moitié qui se termine coupe l'autre.
    tokio::select! {
        _ = to_pc => {}
        _ = to_browser => {}
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
