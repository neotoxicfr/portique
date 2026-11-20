//! Connexions : liste pour l'utilisateur, CRUD pour l'admin, réveil (WoL).

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use portique_proto::{
    ConnectionAdmin, ConnectionInput, ConnectionSummary, RDP_PORT, SSH_PORT, SshAdmin, SshInput,
};
use sqlx::SqlitePool;

use crate::{
    auth::{AdminUser, CurrentUser},
    state::{ApiResult, AppError, AppState, bad},
    wol,
};

#[derive(sqlx::FromRow)]
pub(crate) struct Row {
    pub(crate) id: i64,
    pub(crate) name: String,
    pub(crate) host: String,
    pub(crate) rdp_enabled: bool,
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
    pub(crate) wol_ssh_hostkey_pending: Option<String>,
    pub(crate) ssh_enabled: bool,
    pub(crate) ssh_port: i64,
    pub(crate) ssh_user: String,
    pub(crate) ssh_password: Option<Vec<u8>>,
    pub(crate) ssh_hostkey: Option<String>,
    pub(crate) ssh_jump_id: Option<i64>,
    pub(crate) ssh_theme: Option<String>,
    pub(crate) wol_via_id: Option<i64>,
}

macro_rules! columns {
    () => {
        "id, name, host, rdp_enabled, port, username, domain, password, wol_mac, wol_target, cert_sha256, \
         wol_ssh_host, wol_ssh_user, wol_ssh_password, wol_ssh_command, wol_ssh_hostkey, wol_ssh_hostkey_pending, \
         ssh_enabled, ssh_port, ssh_user, ssh_password, ssh_hostkey, ssh_jump_id, ssh_theme, wol_via_id"
    };
}

/// Connexion accessible à l'utilisateur ? Les admins voient tout.
async fn save_wol_command(
    state: &AppState,
    id: i64,
    cmd: &Option<portique_proto::WolCommandInput>,
) -> ApiResult<()> {
    let clear = "UPDATE connections SET wol_ssh_host = NULL, wol_ssh_user = NULL, wol_ssh_password = NULL,
         wol_ssh_command = NULL, wol_ssh_hostkey = NULL, wol_ssh_hostkey_pending = NULL, wol_via_id = NULL WHERE id = ?";
    let Some(r) = cmd else {
        sqlx::query(clear).bind(id).execute(&state.db).await?;
        return Ok(());
    };
    if let Some(via) = r.via_id {
        // Par un hôte SSH déclaré : sa clé, son mot de passe, sa clé d'hôte et ses rebonds servent.
        wol::validate_command(r.command.trim()).map_err(bad)?;
        let ssh: Option<bool> = sqlx::query_scalar("SELECT ssh_enabled FROM connections WHERE id = ?")
            .bind(via)
            .fetch_optional(&state.db)
            .await?;
        if via == id || ssh != Some(true) {
            return Err(bad("réveil : choisir un autre hôte, qui a le SSH"));
        }
        sqlx::query(clear).bind(id).execute(&state.db).await?;
        sqlx::query("UPDATE connections SET wol_via_id = ?, wol_ssh_command = ? WHERE id = ?")
            .bind(via)
            .bind(r.command.trim())
            .bind(id)
            .execute(&state.db)
            .await?;
        return Ok(());
    }
    sqlx::query("UPDATE connections SET wol_via_id = NULL WHERE id = ?").bind(id).execute(&state.db).await?;
    let host = r.host.trim();
    let ok = |v: &str, extra: &str| {
        !v.is_empty() && v.len() <= 253 && v.chars().all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
    };
    if !ok(host, ".-:") || r.user.trim().is_empty() {
        return Err(bad("réveil par commande : hôte et utilisateur requis"));
    }
    wol::validate_command(r.command.trim()).map_err(bad)?;
    if let Some(fp) = r.approve_hostkey.as_deref().filter(|f| !f.is_empty()) {
        // Approbation explicite : seulement la clé effectivement présentée par l'hôte.
        let done = sqlx::query(
            "UPDATE connections SET wol_ssh_hostkey = wol_ssh_hostkey_pending, wol_ssh_hostkey_pending = NULL
             WHERE id = ? AND wol_ssh_hostkey_pending = ?",
        )
        .bind(id)
        .bind(fp)
        .execute(&state.db)
        .await?;
        if done.rows_affected() == 0 {
            return Err(bad("clé SSH à approuver introuvable (relance un réveil pour la faire apparaître)"));
        }
    }
    sqlx::query(
        "UPDATE connections SET wol_ssh_host = ?, wol_ssh_user = ?, wol_ssh_command = ?,
         wol_ssh_hostkey = CASE WHEN wol_ssh_host IS ? THEN wol_ssh_hostkey ELSE NULL END,
         wol_ssh_hostkey_pending = CASE WHEN wol_ssh_host IS ? THEN wol_ssh_hostkey_pending ELSE NULL END WHERE id = ?",
    )
    .bind(host)
    .bind(r.user.trim())
    .bind(r.command.trim())
    .bind(host)
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
                rdp: r.rdp_enabled,
                ssh: r.ssh_enabled,
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
    if let (Some(via), Some(template)) = (row.wol_via_id, row.wol_ssh_command.as_deref()) {
        let result = wake_via(&state, via, template, mac).await;
        return match result {
            Ok(name) => {
                tracing::info!(
                    user = u.username,
                    connection = row.name,
                    ssh = name,
                    "WoL envoyé par commande"
                );
                Ok(StatusCode::NO_CONTENT)
            }
            Err(e) => {
                tracing::warn!(user = u.username, connection = row.name, "échec du réveil : {e:#}");
                Err(bad(if u.is_admin {
                    format!("réveil par commande : {e:#}")
                } else {
                    "le réveil a échoué ; un admin trouvera le détail dans le journal".to_owned()
                }))
            }
        };
    }
    if let Some(host) = &row.wol_ssh_host {
        let password = match &row.wol_ssh_password {
            Some(sealed) => Some(
                String::from_utf8_lossy(&state.vault.open(&format!("wol-ssh:{}", row.id), sealed)?)
                    .into_owned(),
            ),
            None => None,
        };
        let key = crate::ssh::service_key(&state).await?;
        let result = wol::ssh_command(
            host,
            row.wol_ssh_user.as_deref().unwrap_or_default(),
            &key,
            password.as_deref(),
            row.wol_ssh_command.as_deref().unwrap_or_default(),
            mac,
            row.wol_ssh_hostkey.as_deref(),
        )
        .await;
        match result {
            Ok(()) => {
                tracing::info!(
                    user = u.username,
                    connection = row.name,
                    ssh = host,
                    "WoL envoyé par commande"
                );
                return Ok(StatusCode::NO_CONTENT);
            }
            Err(e) => {
                if let Some(wol::UnapprovedHostKey(fp)) = e.downcast_ref::<wol::UnapprovedHostKey>() {
                    // Rien n'a été envoyé : on note la clé présentée pour qu'un admin l'approuve.
                    sqlx::query("UPDATE connections SET wol_ssh_hostkey_pending = ? WHERE id = ?")
                        .bind(fp)
                        .bind(row.id)
                        .execute(&state.db)
                        .await?;
                }
                tracing::warn!(
                    user = u.username,
                    connection = row.name,
                    ssh = host,
                    "échec du réveil : {e:#}"
                );
                // Détail (sortie de la commande, empreintes) réservé aux admins.
                return Err(bad(if u.is_admin {
                    format!("réveil par commande : {e:#}")
                } else {
                    "le réveil a échoué ; un admin trouvera le détail dans le journal".to_owned()
                }));
            }
        }
    }
    let target = wol::parse_target(row.wol_target.as_deref().unwrap_or(wol::DEFAULT_TARGET))
        .ok_or_else(|| bad("adresse WoL invalide"))?;
    wol::send(mac, target).await.map_err(|e| anyhow::anyhow!("envoi WoL vers {target} : {e}"))?;
    tracing::info!(user = u.username, connection = row.name, %target, "paquet WoL envoyé");
    Ok(StatusCode::NO_CONTENT)
}

/// Réveil par un hôte SSH déclaré : sa chaîne de rebonds, puis la commande. Renvoie son nom.
async fn wake_via(state: &AppState, via: i64, template: &str, mac: [u8; 6]) -> anyhow::Result<String> {
    let host = find_allowed(&state.db, 0, true, via)
        .await
        .map_err(|_| anyhow::anyhow!("hôte de réveil introuvable"))?;
    let name = host.name.clone();
    let hops = crate::api::ssh::chain(state, host).await.map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let key = crate::ssh::service_key(state).await?;
    let chain = match crate::ssh::connect(&hops, &key, None).await {
        Ok(c) => c,
        Err(crate::ssh::OpenError::Unapproved { name, .. }) => anyhow::bail!(
            "clé d'hôte de « {name} » pas encore approuvée : ouvre une fois son terminal pour l'approuver"
        ),
        Err(crate::ssh::OpenError::Failed(e)) => return Err(e),
    };
    let last = chain.sessions.last().ok_or_else(|| anyhow::anyhow!("aucun hôte"))?;
    wol::run_wake_command(last, template, mac).await?;
    Ok(name)
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
        host: r.host,
        rdp: r.rdp_enabled,
        port: r.port as u16,
        username: r.username,
        domain: r.domain,
        has_password: r.password.is_some(),
        wol_mac: r.wol_mac,
        wol_target: r.wol_target,
        allowed_users,
        cert_fingerprint: r.cert_sha256.as_deref().map(hex::encode),
        wol_command: r.wol_ssh_command.clone().map(|command| portique_proto::WolCommandAdmin {
            via_id: r.wol_via_id,
            host: r.wol_ssh_host.clone().unwrap_or_default(),
            user: r.wol_ssh_user.clone().unwrap_or_default(),
            command,
            has_password: r.wol_ssh_password.is_some(),
            hostkey: r.wol_ssh_hostkey.clone(),
            pending_hostkey: r.wol_ssh_hostkey_pending.clone(),
        }),
        ssh: r.ssh_enabled.then(|| SshAdmin {
            port: r.ssh_port as u16,
            user: r.ssh_user.clone(),
            has_password: r.ssh_password.is_some(),
            hostkey: r.ssh_hostkey.clone(),
            jump_id: r.ssh_jump_id,
            theme: r.ssh_theme.clone(),
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
    if !i.rdp && i.ssh.is_none() {
        return Err(bad("choisir au moins un protocole (RDP ou SSH)"));
    }
    let port = i.port.unwrap_or(RDP_PORT);
    if port == 0 {
        return Err(bad("port invalide"));
    }
    if let Some(ssh) = &i.ssh {
        if ssh.port == Some(0) {
            return Err(bad("port SSH invalide"));
        }
        let user = ssh.user.trim();
        if user.is_empty() || user.len() > 64 || user.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(bad("utilisateur SSH requis (sans espace)"));
        }
        if ssh.theme.as_deref().is_some_and(|t| !portique_proto::TERMINAL_THEMES.contains(&t)) {
            return Err(bad("thème de terminal inconnu"));
        }
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
    Ok(Valid { name: name.into(), host: host.into(), port, wol_mac, wol_target })
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

/// SSH de l'hôte `id`. La clé d'hôte approuvée est oubliée si le port change (l'adresse : dans `update`).
async fn save_ssh(state: &AppState, id: i64, ssh: &Option<SshInput>) -> ApiResult<()> {
    let Some(s) = ssh else {
        sqlx::query("UPDATE connections SET ssh_enabled = 0 WHERE id = ?")
            .bind(id)
            .execute(&state.db)
            .await?;
        return Ok(());
    };
    if let Some(jump) = s.jump_id {
        check_jump(&state.db, id, jump).await?;
    }
    let port = s.port.unwrap_or(SSH_PORT) as i64;
    sqlx::query(
        "UPDATE connections SET ssh_enabled = 1, ssh_user = ?, ssh_jump_id = ?, ssh_theme = ?,
         ssh_hostkey = CASE WHEN ?4 OR ssh_port IS NOT ?5 THEN NULL ELSE ssh_hostkey END,
         ssh_port = ?5 WHERE id = ?6",
    )
    .bind(s.user.trim())
    .bind(s.jump_id)
    .bind(s.theme.as_deref())
    .bind(s.forget_hostkey)
    .bind(port)
    .bind(id)
    .execute(&state.db)
    .await?;
    if let Some(pw) = &s.password {
        let sealed = (!pw.is_empty()).then(|| state.vault.seal(&format!("ssh:{id}"), pw.as_bytes()));
        sqlx::query("UPDATE connections SET ssh_password = ? WHERE id = ?")
            .bind(sealed)
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    Ok(())
}

/// Le rebond doit être un autre hôte SSH, sans boucle (A par B par A).
async fn check_jump(db: &SqlitePool, id: i64, jump: i64) -> ApiResult<()> {
    let mut cur = Some(jump);
    for _ in 0..crate::ssh::MAX_HOPS {
        let Some(c) = cur else { return Ok(()) };
        if c == id {
            return Err(bad("rebond en boucle : un hôte ne peut pas passer par lui-même"));
        }
        let next: Option<(bool, Option<i64>)> =
            sqlx::query_as("SELECT ssh_enabled, ssh_jump_id FROM connections WHERE id = ?")
                .bind(c)
                .fetch_optional(db)
                .await?;
        match next {
            Some((true, j)) => cur = j,
            _ => return Err(bad("le rebond doit être un hôte SSH existant")),
        }
    }
    Err(bad("trop de rebonds enchaînés"))
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
        "INSERT INTO connections (name, rdp_enabled, host, port, username, domain, wol_mac, wol_target)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(&v.name)
    .bind(i.rdp)
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
    save_ssh(&state, id, &i.ssh).await?;
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
        "UPDATE connections SET name = ?1, rdp_enabled = ?2, host = ?3, port = ?4, username = ?5, domain = ?6,
         wol_mac = ?7, wol_target = ?8,
         ssh_hostkey = CASE WHEN host IS NOT ?3 THEN NULL ELSE ssh_hostkey END WHERE id = ?9",
    )
    .bind(&v.name)
    .bind(i.rdp)
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
    save_ssh(&state, id, &i.ssh).await?;
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
