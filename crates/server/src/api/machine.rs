//! Accès d'un tableau de bord, de machine à machine : état des machines en lecture et réveil, chacun par sa
//! clé (`Authorization: Bearer`, `PORTIQUE_STATUS_KEY` et `PORTIQUE_WAKE_KEY`). Ni cookie ni proxy
//! d'authentification : la clé ne vient pas toute seule avec une requête d'une page tierce, d'où l'absence
//! de garde CSRF. Rien d'autre n'est accessible ainsi : ni adresse, ni MAC, ni compte, ni ouverture de session.

use std::time::Duration;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    routing::{get, post},
};
use serde::Serialize;
use tokio::{net::TcpStream, task::JoinSet, time::timeout};

use crate::{
    api::connections::{Row, wake_row},
    auth::ClientIp,
    state::{ApiResult, AppError, AppState},
};

pub fn router() -> Router<AppState> {
    Router::new().route("/machine/status", get(status)).route("/machine/wake/{id}", post(wake))
}

/// Délai d'une sonde « en ligne » : un PC en veille ne répond pas, la réponse ne l'attend pas plus.
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

#[derive(Serialize, Default, Clone, Copy)]
pub struct Sessions {
    pub rdp: u32,
    pub ssh: u32,
}

#[derive(Serialize)]
pub struct Machine {
    pub id: i64,
    pub name: String,
    pub rdp: bool,
    pub ssh: bool,
    pub can_wake: bool,
    /// Port du bureau (ou du SSH direct) joignable ; `None` quand Portique ne joint la machine que par un rebond.
    pub online: Option<bool>,
    pub sessions: Sessions,
}

#[derive(Serialize)]
pub struct Status {
    pub machines: Vec<Machine>,
    /// Machines dont `online` vaut `true`.
    pub online: usize,
    pub sessions: Sessions,
}

/// Clé présentée en `Authorization: Bearer`. Route désactivée (clé non configurée) : 404, comme si elle
/// n'existait pas. Comparaison sur les empreintes : sa durée ne dit rien de la clé attendue.
fn check(headers: &HeaderMap, expected: Option<&str>, ip: std::net::IpAddr, what: &str) -> ApiResult<()> {
    let expected = expected.ok_or(AppError::NotFound)?;
    let given = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    if crate::crypto::token_hash(given) != crate::crypto::token_hash(expected) {
        tracing::warn!(%ip, "clé de {what} refusée");
        return Err(AppError::Unauthorized);
    }
    Ok(())
}

pub async fn status(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
) -> ApiResult<Json<Status>> {
    check(&headers, state.cfg.status_key.as_deref(), ip, "lecture")?;
    let rows: Vec<Row> = sqlx::query_as(concat!(
        "SELECT ",
        crate::api::connections::columns!(),
        " FROM connections WHERE inline_for IS NULL ORDER BY name COLLATE NOCASE"
    ))
    .fetch_all(&state.db)
    .await?;
    // Sondes en parallèle : le port que Portique joint lui-même (bureau, sinon SSH sans rebond).
    let mut probes = JoinSet::new();
    for (i, r) in rows.iter().enumerate() {
        let port = if r.rdp_enabled {
            r.port
        } else if r.ssh_enabled && r.ssh_jump_id.is_none() {
            r.ssh_port
        } else {
            continue;
        };
        let (host, port) = (r.host.clone(), u16::try_from(port).unwrap_or(0));
        probes.spawn(async move {
            let up =
                matches!(timeout(PROBE_TIMEOUT, TcpStream::connect((host.as_str(), port))).await, Ok(Ok(_)));
            (i, up)
        });
    }
    let mut online = vec![None; rows.len()];
    while let Some(done) = probes.join_next().await {
        if let Ok((i, up)) = done {
            online[i] = Some(up);
        }
    }
    let mut total = Sessions::default();
    let machines: Vec<Machine> = rows
        .into_iter()
        .zip(online)
        .map(|(row, online)| {
            let [r, s] = state.live.count(row.id);
            total.rdp += r;
            total.ssh += s;
            Machine {
                id: row.id,
                name: row.name,
                rdp: row.rdp_enabled,
                ssh: row.ssh_enabled,
                can_wake: row.wol_mac.is_some(),
                online,
                sessions: Sessions { rdp: r, ssh: s },
            }
        })
        .collect();
    let online = machines.iter().filter(|m| m.online == Some(true)).count();
    Ok(Json(Status { machines, online, sessions: total }))
}

pub async fn wake(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    check(&headers, state.cfg.wake_key.as_deref(), ip, "réveil")?;
    let row: Row = sqlx::query_as(concat!(
        "SELECT ",
        crate::api::connections::columns!(),
        " FROM connections WHERE id = ? AND inline_for IS NULL"
    ))
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;
    wake_row(&state, &row, "clé de réveil", false).await
}
