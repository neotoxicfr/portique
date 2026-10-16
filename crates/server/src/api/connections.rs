//! Connexions : liste pour l'utilisateur, CRUD pour l'admin, réveil (WoL).

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use sqlx::SqlitePool;
use yawrdp_proto::{ConnectionAdmin, ConnectionInput, ConnectionSummary, Protocol};

use crate::{
    auth::{AdminUser, CurrentUser},
    state::{ApiResult, AppError, AppState, bad},
    wol,
};

#[derive(sqlx::FromRow)]
pub(crate) struct Row {
    pub(crate) id: i64,
    pub(crate) name: String,
    pub(crate) protocol: String,
    pub(crate) host: String,
    pub(crate) port: i64,
    pub(crate) username: String,
    pub(crate) domain: String,
    pub(crate) password: Option<Vec<u8>>,
    pub(crate) wol_mac: Option<String>,
    pub(crate) wol_target: Option<String>,
    pub(crate) cert_sha256: Option<Vec<u8>>,
    pub(crate) wol_ssh_host: Option<String>,
    pub(crate) wol_ssh_user: Option<String>,
    pub(crate) wol_ssh_password: Option<Vec<u8>>,
    pub(crate) wol_ssh_command: Option<String>,
    pub(crate) wol_ssh_hostkey: Option<String>,
}

macro_rules! columns {
    () => {
        "id, name, protocol, host, port, username, domain, password, wol_mac, wol_target, cert_sha256, \
         wol_ssh_host, wol_ssh_user, wol_ssh_password, wol_ssh_command, wol_ssh_hostkey"
    };
}

fn protocol(s: &str) -> Protocol {
    if s == "ssh" { Protocol::Ssh } else { Protocol::Rdp }
}

fn protocol_str(p: Protocol) -> &'static str {
    match p {
        Protocol::Rdp => "rdp",
        Protocol::Ssh => "ssh",
    }
}

/// Connexion accessible à l'utilisateur ? Les admins voient tout.
async fn save_wol_command(
    state: &AppState,
    id: i64,
    cmd: &Option<yawrdp_proto::WolCommandInput>,
) -> ApiResult<()> {
    let Some(r) = cmd else {
        sqlx::query(
            "UPDATE connections SET wol_ssh_host = NULL, wol_ssh_user = NULL, wol_ssh_password = NULL,
             wol_ssh_command = NULL, wol_ssh_hostkey = NULL WHERE id = ?",
        )
        .bind(id)
        .execute(&state.db)
        .await?;
        return Ok(());
    };
    let host = r.host.trim();
    let ok = |v: &str, extra: &str| {
        !v.is_empty() && v.len() <= 253 && v.chars().all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
    };
    if !ok(host, ".-:") || r.user.trim().is_empty() {
        return Err(bad("réveil par commande : hôte et utilisateur requis"));
    }
    wol::validate_command(r.command.trim()).map_err(bad)?;
    sqlx::query(
        "UPDATE connections SET wol_ssh_host = ?, wol_ssh_user = ?, wol_ssh_command = ?,
         wol_ssh_hostkey = CASE WHEN wol_ssh_host IS ? THEN wol_ssh_hostkey ELSE NULL END WHERE id = ?",
    )
    .bind(host)
    .bind(r.user.trim())
    .bind(r.command.trim())
    .bind(host)
    .bind(id)
    .execute(&state.db)
    .await?;
    if let Some(pw) = r.password.as_deref().filter(|p| !p.is_empty()) {
        sqlx::query("UPDATE connections SET wol_ssh_password = ? WHERE id = ?")
            .bind(state.vault.seal(&format!("wol-ssh:{id}"), pw.as_bytes()))
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    Ok(())
}

pub(crate) async fn find_allowed(db: &SqlitePool, user_id: i64, is_admin: bool, id: i64) -> ApiResult<Row> {
    sqlx::query_as(concat!(
        "SELECT ",
        columns!(),
        " FROM connections c WHERE id = ?1 AND (?3 OR EXISTS (
            SELECT 1 FROM connection_access a WHERE a.connection_id = c.id AND a.user_id = ?2))"
    ))
    .bind(id)
    .bind(user_id)
    .bind(is_admin)
    .fetch_optional(db)
    .await?
    .ok_or(AppError::NotFound)
}

pub async fn list(
    State(state): State<AppState>,
    CurrentUser(u): CurrentUser,
) -> ApiResult<Json<Vec<ConnectionSummary>>> {
    let rows: Vec<Row> = sqlx::query_as(concat!(
        "SELECT ",
        columns!(),
        " FROM connections c WHERE ?2 OR EXISTS (
            SELECT 1 FROM connection_access a WHERE a.connection_id = c.id AND a.user_id = ?1)
         ORDER BY name COLLATE NOCASE"
    ))
    .bind(u.id)
    .bind(u.is_admin)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| ConnectionSummary {
                id: r.id,
                name: r.name,
                protocol: protocol(&r.protocol),
                can_wake: r.wol_mac.is_some(),
            })
            .collect(),
    ))
}

pub async fn wake(
    State(state): State<AppState>,
    CurrentUser(u): CurrentUser,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    let row = find_allowed(&state.db, u.id, u.is_admin, id).await?;
    let mac = row.wol_mac.as_deref().and_then(wol::parse_mac).ok_or_else(|| bad("WoL non configuré"))?;
    if let Some(host) = &row.wol_ssh_host {
        let password = match &row.wol_ssh_password {
            Some(sealed) => {
                String::from_utf8_lossy(&state.vault.open(&format!("wol-ssh:{}", row.id), sealed)?)
                    .into_owned()
            }
            None => return Err(bad("mot de passe SSH de réveil absent")),
        };
        let fp = wol::ssh_command(
            host,
            row.wol_ssh_user.as_deref().unwrap_or_default(),
            &password,
            row.wol_ssh_command.as_deref().unwrap_or_default(),
            mac,
            row.wol_ssh_hostkey.as_deref(),
        )
        .await
        .map_err(|e| bad(format!("réveil par commande : {e:#}")))?;
        if row.wol_ssh_hostkey.is_none() {
            // Clé SSH épinglée au premier envoi réussi (hôte du réseau interne, via le tunnel chiffré).
            sqlx::query(
                "UPDATE connections SET wol_ssh_hostkey = ? WHERE id = ? AND wol_ssh_hostkey IS NULL",
            )
            .bind(&fp)
            .bind(row.id)
            .execute(&state.db)
            .await?;
        }
        tracing::info!(user = u.username, connection = row.name, ssh = host, "WoL envoyé par commande");
        return Ok(StatusCode::NO_CONTENT);
    }
    let target = wol::parse_target(row.wol_target.as_deref().unwrap_or(wol::DEFAULT_TARGET))
        .ok_or_else(|| bad("adresse WoL invalide"))?;
    wol::send(mac, target).await.map_err(|e| anyhow::anyhow!("envoi WoL vers {target} : {e}"))?;
    tracing::info!(user = u.username, connection = row.name, %target, "paquet WoL envoyé");
    Ok(StatusCode::NO_CONTENT)
}

async fn to_admin(db: &SqlitePool, r: Row) -> ApiResult<ConnectionAdmin> {
    let allowed_users =
        sqlx::query_scalar("SELECT user_id FROM connection_access WHERE connection_id = ? ORDER BY user_id")
            .bind(r.id)
            .fetch_all(db)
            .await?;
    Ok(ConnectionAdmin {
        id: r.id,
        name: r.name,
        protocol: protocol(&r.protocol),
        host: r.host,
        port: r.port as u16,
        username: r.username,
        domain: r.domain,
        has_password: r.password.is_some(),
        wol_mac: r.wol_mac,
        wol_target: r.wol_target,
        allowed_users,
        cert_fingerprint: r.cert_sha256.as_deref().map(hex::encode),
        wol_command: r.wol_ssh_host.clone().map(|host| yawrdp_proto::WolCommandAdmin {
            host,
            user: r.wol_ssh_user.clone().unwrap_or_default(),
            command: r.wol_ssh_command.clone().unwrap_or_default(),
            has_password: r.wol_ssh_password.is_some(),
            hostkey: r.wol_ssh_hostkey.clone(),
        }),
    })
}

pub async fn admin_list(
    State(state): State<AppState>,
    _: AdminUser,
) -> ApiResult<Json<Vec<ConnectionAdmin>>> {
    let rows: Vec<Row> =
        sqlx::query_as(concat!("SELECT ", columns!(), " FROM connections ORDER BY name COLLATE NOCASE"))
            .fetch_all(&state.db)
            .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(to_admin(&state.db, r).await?);
    }
    Ok(Json(out))
}

/// Entrée validée et normalisée.
struct Valid {
    name: String,
    protocol: Protocol,
    host: String,
    port: u16,
    wol_mac: Option<String>,
    wol_target: Option<String>,
}

fn validate(i: &ConnectionInput) -> ApiResult<Valid> {
    let name = i.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(bad("nom requis (100 caractères maximum)"));
    }
    let host = i.host.trim();
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && host.chars().all(|c| c.is_ascii_alphanumeric() || ".-:[]".contains(c));
    if !host_ok {
        return Err(bad("hôte invalide"));
    }
    let protocol = i.protocol.unwrap_or(Protocol::Rdp);
    let port = i.port.unwrap_or(protocol.default_port());
    if port == 0 {
        return Err(bad("port invalide"));
    }
    let wol_mac = match i.wol_mac.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(m) => Some(wol::format_mac(wol::parse_mac(m).ok_or_else(|| bad("adresse MAC invalide"))?)),
        None => None,
    };
    let wol_target = match i.wol_target.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(t) => {
            Some(wol::parse_target(t).ok_or_else(|| bad("cible WoL invalide (ip ou ip:port)"))?.to_string())
        }
        None => None,
    };
    Ok(Valid { name: name.into(), protocol, host: host.into(), port, wol_mac, wol_target })
}

async fn save_access(db: &SqlitePool, id: i64, users: &[i64]) -> ApiResult<()> {
    sqlx::query("DELETE FROM connection_access WHERE connection_id = ?").bind(id).execute(db).await?;
    for u in users {
        sqlx::query(
            "INSERT OR IGNORE INTO connection_access (connection_id, user_id)
                     SELECT ?, id FROM users WHERE id = ?",
        )
        .bind(id)
        .bind(u)
        .execute(db)
        .await?;
    }
    Ok(())
}

async fn save_password(state: &AppState, id: i64, pw: &Option<String>) -> ApiResult<()> {
    let Some(pw) = pw else { return Ok(()) };
    let sealed = (!pw.is_empty()).then(|| state.vault.seal(&format!("connection:{id}"), pw.as_bytes()));
    sqlx::query("UPDATE connections SET password = ? WHERE id = ?")
        .bind(sealed)
        .bind(id)
        .execute(&state.db)
        .await?;
    Ok(())
}

pub async fn create(
    State(state): State<AppState>,
    _: AdminUser,
    Json(i): Json<ConnectionInput>,
) -> ApiResult<(StatusCode, Json<ConnectionAdmin>)> {
    let v = validate(&i)?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO connections (name, protocol, host, port, username, domain, wol_mac, wol_target)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(&v.name)
    .bind(protocol_str(v.protocol))
    .bind(&v.host)
    .bind(v.port as i64)
    .bind(i.username.trim())
    .bind(i.domain.trim())
    .bind(&v.wol_mac)
    .bind(&v.wol_target)
    .fetch_one(&state.db)
    .await?;
    save_password(&state, id, &i.password).await?;
    save_access(&state.db, id, &i.allowed_users).await?;
    save_wol_command(&state, id, &i.wol_command).await?;
    let row = find_allowed(&state.db, 0, true, id).await?;
    Ok((StatusCode::CREATED, Json(to_admin(&state.db, row).await?)))
}

pub async fn update(
    State(state): State<AppState>,
    _: AdminUser,
    Path(id): Path<i64>,
    Json(i): Json<ConnectionInput>,
) -> ApiResult<Json<ConnectionAdmin>> {
    let v = validate(&i)?;
    let r = sqlx::query(
        "UPDATE connections SET name = ?, protocol = ?, host = ?, port = ?, username = ?, domain = ?,
         wol_mac = ?, wol_target = ? WHERE id = ?",
    )
    .bind(&v.name)
    .bind(protocol_str(v.protocol))
    .bind(&v.host)
    .bind(v.port as i64)
    .bind(i.username.trim())
    .bind(i.domain.trim())
    .bind(&v.wol_mac)
    .bind(&v.wol_target)
    .bind(id)
    .execute(&state.db)
    .await?;
    if r.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    save_password(&state, id, &i.password).await?;
    save_access(&state.db, id, &i.allowed_users).await?;
    save_wol_command(&state, id, &i.wol_command).await?;
    if i.forget_certificate {
        sqlx::query("UPDATE connections SET cert_sha256 = NULL WHERE id = ?")
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    let row = find_allowed(&state.db, 0, true, id).await?;
    Ok(Json(to_admin(&state.db, row).await?))
}

pub async fn delete(
    State(state): State<AppState>,
    _: AdminUser,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    let r = sqlx::query("DELETE FROM connections WHERE id = ?").bind(id).execute(&state.db).await?;
    if r.rows_affected() == 0 { Err(AppError::NotFound) } else { Ok(StatusCode::NO_CONTENT) }
}
