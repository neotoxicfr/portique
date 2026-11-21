//! Connexions : liste pour l'utilisateur, CRUD pour l'admin, réveil (WoL).

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use portique_proto::{
    ConnectionAdmin, ConnectionInput, ConnectionSummary, HopAdmin, HopInput, RDP_PORT, SSH_PORT, SshAdmin,
    SshInput,
};
use sqlx::{SqliteConnection, SqliteExecutor, SqlitePool};

use crate::{
    auth::{AdminUser, CurrentUser},
    crypto::Vault,
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
    pub(crate) wol_ssh_command: Option<String>,
    pub(crate) ssh_enabled: bool,
    pub(crate) ssh_port: i64,
    pub(crate) ssh_user: String,
    pub(crate) ssh_password: Option<Vec<u8>>,
    pub(crate) ssh_hostkey: Option<String>,
    pub(crate) ssh_hostkey_pending: Option<String>,
    pub(crate) ssh_jump_id: Option<i64>,
    pub(crate) ssh_theme: Option<String>,
    pub(crate) wol_via_id: Option<i64>,
    /// Rebond saisi pour cette machine seule : ligne cachée, jamais listée ni ouverte comme cible.
    pub(crate) inline_for: Option<i64>,
}

macro_rules! columns {
    () => {
        "id, name, host, rdp_enabled, port, username, domain, password, wol_mac, wol_target, cert_sha256, \
         wol_ssh_command, ssh_enabled, ssh_port, ssh_user, ssh_password, ssh_hostkey, ssh_hostkey_pending, \
         ssh_jump_id, ssh_theme, wol_via_id, inline_for"
    };
}

/// Maillons saisis d'un emplacement : la ligne cachée `?1` de `?2`, puis les lignes cachées de `?2` par
/// lesquelles elle passe (copies laissées par la suppression d'un hôte connu), `?3` au plus.
macro_rules! links {
    () => {
        "WITH RECURSIVE link(id, n) AS (
             SELECT id, 0 FROM connections WHERE id = ?1 AND inline_for = ?2
             UNION SELECT c.ssh_jump_id, link.n + 1 FROM link JOIN connections c ON c.id = link.id
                 WHERE c.ssh_jump_id IN (SELECT id FROM connections WHERE inline_for = ?2) AND link.n < ?3) "
    };
}

/// Réveil par commande de `id` : SSH par un rebond (hôte connu ou saisi), puis la commande.
async fn save_wol_command(
    vault: &Vault,
    db: &mut SqliteConnection,
    id: i64,
    cmd: &Option<portique_proto::WolCommandInput>,
) -> ApiResult<()> {
    // Ancien réveil par adresse saisie que le démarrage n'a pas pu reprendre : repris ici, ou modification
    // refusée, plutôt que d'effacer ses réglages. L'admin le voyait comme un réveil direct : une commande
    // absente ne le supprime donc pas.
    let converted = convert_legacy_wol_host(vault, db, id).await.map_err(|e| {
        bad(format!("réveil : l'ancien réglage par adresse saisie n'a pas pu être repris ({e:#})"))
    })?;
    // Les colonnes wol_ssh_* autres que la commande ne servent plus (reprises par `convert_legacy_wol_hosts`).
    let clear = "UPDATE connections SET wol_ssh_host = NULL, wol_ssh_user = NULL, wol_ssh_password = NULL,
         wol_ssh_command = NULL, wol_ssh_hostkey = NULL, wol_ssh_hostkey_pending = NULL, wol_via_id = NULL WHERE id = ?";
    let Some(r) = cmd else {
        if !converted {
            sqlx::query(clear).bind(id).execute(&mut *db).await?;
        }
        return Ok(());
    };
    wol::validate_command(r.command.trim()).map_err(bad)?;
    let current: Option<i64> = sqlx::query_scalar("SELECT wol_via_id FROM connections WHERE id = ?")
        .bind(id)
        .fetch_one(&mut *db)
        .await?;
    let via = save_hop(vault, db, id, current, Some(&r.via)).await?;
    sqlx::query(clear).bind(id).execute(&mut *db).await?;
    sqlx::query("UPDATE connections SET wol_via_id = ?, wol_ssh_command = ? WHERE id = ?")
        .bind(via)
        .bind(r.command.trim())
        .bind(id)
        .execute(&mut *db)
        .await?;
    Ok(())
}

/// Connexion accessible à l'utilisateur ? Les admins voient tout. Jamais une ligne cachée.
pub(crate) async fn find_allowed(db: &SqlitePool, user_id: i64, is_admin: bool, id: i64) -> ApiResult<Row> {
    sqlx::query_as(concat!(
        "SELECT ",
        columns!(),
        " FROM connections c WHERE id = ?1 AND c.inline_for IS NULL AND (?3 OR EXISTS (
            SELECT 1 FROM connection_access a WHERE a.connection_id = c.id AND a.user_id = ?2))"
    ))
    .bind(id)
    .bind(user_id)
    .bind(is_admin)
    .fetch_optional(db)
    .await?
    .ok_or(AppError::NotFound)
}

/// Saut d'une chaîne (rebond ou hôte de réveil), ligne cachée comprise : seul l'accès à la cible compte.
pub(crate) async fn find_hop<'e>(db: impl SqliteExecutor<'e>, id: i64) -> ApiResult<Row> {
    sqlx::query_as(concat!("SELECT ", columns!(), " FROM connections WHERE id = ?"))
        .bind(id)
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
        " FROM connections c WHERE c.inline_for IS NULL AND (?2 OR EXISTS (
            SELECT 1 FROM connection_access a WHERE a.connection_id = c.id AND a.user_id = ?1))
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
                alert: r.ssh_enabled && r.ssh_theme.as_deref() == Some("alerte"),
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
    // Pas de double authentification exigée ici, même par l'hôte SSH : la commande est celle de l'admin
    // et la MAC vient de la base. L'utilisateur ne peut que réveiller sa machine, comme par paquet UDP.
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
    if row.wol_ssh_command.is_some() {
        // Réveil par commande dont l'hôte de réveil a été supprimé : pas de repli silencieux sur l'UDP.
        return Err(bad("réveil par commande sans hôte de réveil : un admin doit le reconfigurer"));
    }
    let target = wol::parse_target(row.wol_target.as_deref().unwrap_or(wol::DEFAULT_TARGET))
        .ok_or_else(|| bad("adresse WoL invalide"))?;
    wol::send(mac, target).await.map_err(|e| anyhow::anyhow!("envoi WoL vers {target} : {e}"))?;
    tracing::info!(user = u.username, connection = row.name, %target, "paquet WoL envoyé");
    Ok(StatusCode::NO_CONTENT)
}

/// Réveil par un rebond (hôte connu ou saisi) : sa chaîne de rebonds, puis la commande. Renvoie son nom.
async fn wake_via(state: &AppState, via: i64, template: &str, mac: [u8; 6]) -> anyhow::Result<String> {
    let hops = crate::api::ssh::chain(state, via).await.map_err(|e| match e {
        AppError::NotFound => anyhow::anyhow!("hôte de réveil introuvable"),
        e => anyhow::anyhow!("{e:?}"),
    })?;
    let name = hops.last().map(|h| h.name.clone()).unwrap_or_default();
    let key = crate::ssh::service_key(state).await?;
    let chain = match crate::ssh::connect(&hops, &key, None).await {
        Ok(c) => c,
        Err(crate::ssh::OpenError::Unapproved { id, name, fingerprint, .. }) => {
            // Rien n'a été envoyé. Rebond saisi : la clé présentée attend l'approbation dans l'admin de sa
            // machine, si l'adresse n'a pas changé depuis la lecture (sinon elle serait approuvable pour la
            // nouvelle) et si un terminal ne l'a pas épinglée entre-temps. Hôte connu : son terminal sert à
            // l'approuver.
            if let Some(hop) = hops.iter().find(|h| h.id == id) {
                let owner: Option<i64> = sqlx::query_scalar(
                    "UPDATE connections SET ssh_hostkey_pending = ?
                     WHERE id = ? AND inline_for IS NOT NULL AND ssh_hostkey IS NULL AND host = ? AND ssh_port = ?
                     RETURNING inline_for",
                )
                .bind(&fingerprint)
                .bind(id)
                .bind(&hop.host)
                .bind(i64::from(hop.port))
                .fetch_optional(&state.db)
                .await?;
                if let Some(owner) = owner {
                    let machine: String = sqlx::query_scalar("SELECT name FROM connections WHERE id = ?")
                        .bind(owner)
                        .fetch_one(&state.db)
                        .await?;
                    anyhow::bail!("clé d'hôte de « {name} » à approuver dans l'admin de « {machine} »");
                }
            }
            anyhow::bail!(
                "clé d'hôte de « {name} » pas encore approuvée : ouvre une fois son terminal pour l'approuver"
            )
        }
        Err(crate::ssh::OpenError::Failed(e)) => return Err(e),
    };
    let last = chain.sessions.last().ok_or_else(|| anyhow::anyhow!("aucun hôte"))?;
    wol::run_wake_command(last, template, mac).await?;
    Ok(name)
}

/// Rebond `id` d'un emplacement de `owner`, tel que l'admin le voit : hôte saisi (ligne cachée de `owner`)
/// ou hôte connu.
async fn hop_admin(db: &mut SqliteConnection, owner: i64, id: Option<i64>) -> ApiResult<Option<HopAdmin>> {
    let Some(id) = id else { return Ok(None) };
    let h = find_hop(&mut *db, id).await?;
    if h.inline_for != Some(owner) {
        return Ok(Some(HopAdmin::Known { id }));
    }
    // Clé en attente du premier maillon saisi qui en a une : celui-ci, ou une copie cachée par laquelle il
    // passe, qui n'a pas d'admin à elle.
    let pending: Option<String> = sqlx::query_scalar(concat!(
        links!(),
        "SELECT c.ssh_hostkey_pending FROM link JOIN connections c ON c.id = link.id
         WHERE c.ssh_hostkey_pending IS NOT NULL ORDER BY link.n LIMIT 1"
    ))
    .bind(id)
    .bind(owner)
    .bind(crate::ssh::MAX_HOPS as i64)
    .fetch_optional(&mut *db)
    .await?;
    Ok(Some(HopAdmin::Host {
        host: h.host,
        port: h.ssh_port as u16,
        user: h.ssh_user,
        has_password: h.ssh_password.is_some(),
        via_id: h.ssh_jump_id,
        hostkey: h.ssh_hostkey,
        pending_hostkey: pending,
    }))
}

/// Vue admin de `r`. `db` : la connexion qui a lu `r`, dans la même transaction, pour que les rebonds lus
/// soient ceux qu'elle désigne (une suppression d'hôte convertit les références puis supprime l'hôte).
async fn to_admin(db: &mut SqliteConnection, r: Row) -> ApiResult<ConnectionAdmin> {
    let allowed_users =
        sqlx::query_scalar("SELECT user_id FROM connection_access WHERE connection_id = ? ORDER BY user_id")
            .bind(r.id)
            .fetch_all(&mut *db)
            .await?;
    // Commande sans rebond (hôte de réveil supprimé avant la conversion des dépendants) : rendue comme un
    // réveil direct, le réveil lui-même refuse de partir (voir `wake`).
    let via = hop_admin(&mut *db, r.id, r.wol_via_id).await?;
    let wol_command = r
        .wol_ssh_command
        .clone()
        .zip(via)
        .map(|(command, via)| portique_proto::WolCommandAdmin { via, command });
    let jump = hop_admin(&mut *db, r.id, r.ssh_jump_id).await?;
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
        wol_command,
        ssh: r.ssh_enabled.then(|| SshAdmin {
            port: r.ssh_port as u16,
            user: r.ssh_user.clone(),
            has_password: r.ssh_password.is_some(),
            hostkey: r.ssh_hostkey.clone(),
            jump,
            theme: r.ssh_theme.clone(),
        }),
    })
}

pub async fn admin_list(
    State(state): State<AppState>,
    _: AdminUser,
) -> ApiResult<Json<Vec<ConnectionAdmin>>> {
    // Une transaction de lecture : machines et rebonds vus dans le même instantané.
    let mut tx = state.db.begin().await?;
    let rows: Vec<Row> = sqlx::query_as(concat!(
        "SELECT ",
        columns!(),
        " FROM connections WHERE inline_for IS NULL ORDER BY name COLLATE NOCASE"
    ))
    .fetch_all(&mut *tx)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(to_admin(&mut tx, r).await?);
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

/// Adresse d'un hôte (RDP, SSH, rebond saisi) sous la forme que `connect` utilise telle quelle : nom, IPv4,
/// ou IPv6 sans crochets (ceux d'une saisie `[2001:db8::1]` sont retirés). `None` si elle est invalide.
fn normalize_host(host: &str) -> Option<&str> {
    let host = host.trim();
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if bare.contains(':') {
        return bare.parse::<std::net::Ipv6Addr>().is_ok().then_some(bare);
    }
    let name = !bare.is_empty()
        && bare.len() <= 253
        && bare.chars().all(|c| c.is_ascii_alphanumeric() || ".-".contains(c));
    // Des crochets n'entourent qu'une IPv6.
    (name && bare == host).then_some(bare)
}

fn ssh_user_ok(user: &str) -> bool {
    !user.is_empty() && user.len() <= 64 && !user.chars().any(|c| c.is_control() || c.is_whitespace())
}

fn validate(i: &ConnectionInput) -> ApiResult<Valid> {
    let name = i.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(bad("nom requis (100 caractères maximum)"));
    }
    let host = normalize_host(&i.host).ok_or_else(|| bad("hôte invalide"))?;
    if !i.rdp && i.ssh.is_none() {
        return Err(bad("choisir au moins un protocole (RDP ou SSH)"));
    }
    let port = i.port.unwrap_or(RDP_PORT);
    if port == 0 {
        return Err(bad("port invalide"));
    }
    // Borne du Client Info RDP (MS-RDPBCGR 2.2.1.11.1.1, 512 octets UTF-16 nul compris) : au-delà, le bureau
    // ne s'ouvrirait jamais, autant prévenir l'admin à la saisie.
    if [&i.username, &i.domain].iter().any(|s| s.trim().encode_utf16().count() > 255) {
        return Err(bad("utilisateur et domaine RDP : 255 caractères maximum"));
    }
    if let Some(ssh) = &i.ssh {
        if ssh.port == Some(0) {
            return Err(bad("port SSH invalide"));
        }
        if !ssh_user_ok(ssh.user.trim()) {
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
    // Le réveil par commande remplace {mac} : sans adresse, la commande partirait vide.
    if i.wol_command.is_some() && wol_mac.is_none() {
        return Err(bad("adresse MAC requise pour le réveil par commande"));
    }
    let wol_target = match i.wol_target.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(t) => {
            Some(wol::parse_target(t).ok_or_else(|| bad("cible WoL invalide (ip ou ip:port)"))?.to_string())
        }
        None => None,
    };
    Ok(Valid { name: name.into(), host: host.into(), port, wol_mac, wol_target })
}

async fn save_access(db: &mut SqliteConnection, id: i64, users: &[i64]) -> ApiResult<()> {
    sqlx::query("DELETE FROM connection_access WHERE connection_id = ?").bind(id).execute(&mut *db).await?;
    for u in users {
        sqlx::query(
            "INSERT OR IGNORE INTO connection_access (connection_id, user_id)
                     SELECT ?, id FROM users WHERE id = ?",
        )
        .bind(id)
        .bind(u)
        .execute(&mut *db)
        .await?;
    }
    Ok(())
}

/// SSH de l'hôte `id`. La clé d'hôte approuvée est oubliée si le port change (l'adresse : dans `update`).
async fn save_ssh(
    vault: &Vault,
    db: &mut SqliteConnection,
    id: i64,
    ssh: &Option<SshInput>,
) -> ApiResult<()> {
    let Some(s) = ssh else {
        // SSH coupé : un hôte connu reste noté comme rebond pour une réactivation, un hôte saisi part
        // (purgé par `prune_inline`).
        sqlx::query(
            "UPDATE connections SET ssh_enabled = 0, ssh_jump_id = CASE WHEN ssh_jump_id IN
                 (SELECT id FROM connections WHERE inline_for = ?1) THEN NULL ELSE ssh_jump_id END WHERE id = ?1",
        )
        .bind(id)
        .execute(&mut *db)
        .await?;
        return Ok(());
    };
    let current: Option<i64> = sqlx::query_scalar("SELECT ssh_jump_id FROM connections WHERE id = ?")
        .bind(id)
        .fetch_one(&mut *db)
        .await?;
    let jump = save_hop(vault, db, id, current, s.jump.as_ref()).await?;
    let port = s.port.unwrap_or(SSH_PORT) as i64;
    sqlx::query(
        "UPDATE connections SET ssh_enabled = 1, ssh_user = ?, ssh_jump_id = ?, ssh_theme = ?,
         ssh_hostkey = CASE WHEN ?4 OR ssh_port IS NOT ?5 THEN NULL ELSE ssh_hostkey END,
         ssh_port = ?5 WHERE id = ?6",
    )
    .bind(s.user.trim())
    .bind(jump)
    .bind(s.theme.as_deref())
    .bind(s.forget_hostkey)
    .bind(port)
    .bind(id)
    .execute(&mut *db)
    .await?;
    // Son terminal (la cible compte dans sa chaîne) et ceux des autres qui passent par lui.
    check_through(db, id).await?;
    if let Some(pw) = &s.password {
        let sealed = (!pw.is_empty()).then(|| vault.seal(&format!("ssh:{id}"), pw.as_bytes()));
        sqlx::query("UPDATE connections SET ssh_password = ? WHERE id = ?")
            .bind(sealed)
            .bind(id)
            .execute(&mut *db)
            .await?;
    }
    Ok(())
}

/// Enregistre le rebond d'un emplacement de `owner` (réveil ou terminal) et renvoie l'identifiant à y noter.
/// `current` : rebond actuel de l'emplacement. Un hôte saisi réutilise la ligne cachée de l'emplacement : sa
/// clé d'hôte reste approuvée tant que l'adresse et le port ne changent pas. Une ligne cachée qui ne sert
/// plus est supprimée par `prune_inline`.
async fn save_hop(
    vault: &Vault,
    db: &mut SqliteConnection,
    owner: i64,
    current: Option<i64>,
    hop: Option<&HopInput>,
) -> ApiResult<Option<i64>> {
    let (host, port, user, password, via_id, approve, forget) = match hop {
        None => return Ok(None),
        Some(HopInput::Known { id }) => {
            let listed: Option<i64> =
                sqlx::query_scalar("SELECT id FROM connections WHERE id = ? AND inline_for IS NULL")
                    .bind(id)
                    .fetch_optional(&mut *db)
                    .await?;
            if listed.is_none() {
                return Err(bad("le rebond doit être un hôte SSH existant"));
            }
            check_jump(db, owner, *id).await?;
            return Ok(Some(*id));
        }
        Some(HopInput::Host { host, port, user, password, via_id, approve_hostkey, forget_hostkey }) => (
            host.trim(),
            port.unwrap_or(SSH_PORT),
            user.trim(),
            password,
            *via_id,
            approve_hostkey,
            *forget_hostkey,
        ),
    };
    let host = normalize_host(host).ok_or_else(|| bad("rebond : adresse invalide"))?;
    if port == 0 {
        return Err(bad("rebond : port SSH invalide"));
    }
    if !ssh_user_ok(user) {
        return Err(bad("rebond : utilisateur SSH requis (sans espace)"));
    }
    let mine: Option<(i64, Option<i64>)> = match current {
        Some(c) => {
            sqlx::query_as("SELECT id, ssh_jump_id FROM connections WHERE id = ? AND inline_for = ?")
                .bind(c)
                .bind(owner)
                .fetch_optional(&mut *db)
                .await?
        }
        None => None,
    };
    if let Some(v) = via_id {
        // Par un hôte de la liste, ou par la copie cachée qu'a laissée la suppression de l'hôte d'origine.
        let hidden: Option<Option<i64>> =
            sqlx::query_scalar("SELECT inline_for FROM connections WHERE id = ?")
                .bind(v)
                .fetch_optional(&mut *db)
                .await?;
        let kept = mine.is_some_and(|(_, j)| j == Some(v));
        match hidden {
            Some(None) => {}
            Some(Some(o)) if o == owner && kept => {}
            _ => return Err(bad("le rebond doit être un hôte SSH existant")),
        }
    }
    let id =
        match mine {
            Some((id, _)) => id,
            None => sqlx::query_scalar(
                "INSERT INTO connections (name, host, port, rdp_enabled, ssh_enabled, ssh_port, inline_for)
                 VALUES (?1, ?1, ?2, 0, 1, ?3, ?4) RETURNING id",
            )
            .bind(host)
            .bind(i64::from(RDP_PORT))
            .bind(i64::from(port))
            .bind(owner)
            .fetch_one(&mut *db)
            .await?,
        };
    // Le nom (celui de l'hôte d'origine pour une copie) suit l'adresse quand elle change.
    sqlx::query(
        "UPDATE connections SET ssh_user = ?3, ssh_jump_id = ?4,
         name = CASE WHEN host IS ?1 THEN name ELSE ?1 END,
         ssh_hostkey = CASE WHEN host IS ?1 AND ssh_port IS ?2 AND NOT ?6 THEN ssh_hostkey ELSE NULL END,
         ssh_hostkey_pending = CASE WHEN host IS ?1 AND ssh_port IS ?2 AND NOT ?6 THEN ssh_hostkey_pending ELSE NULL END,
         host = ?1, ssh_port = ?2 WHERE id = ?5",
    )
    .bind(host)
    .bind(i64::from(port))
    .bind(user)
    .bind(via_id)
    .bind(id)
    .bind(forget)
    .execute(&mut *db)
    .await?;
    // Sans boucle par `owner`, et bornée : la ligne cachée compte comme un saut.
    check_jump(db, owner, id).await?;
    if let Some(fp) = approve.as_deref().filter(|f| !f.is_empty()) {
        // Approbation explicite : seulement la clé effectivement présentée, par ce maillon ou une copie
        // cachée de l'emplacement par laquelle il passe.
        let done = sqlx::query(concat!(
            links!(),
            "UPDATE connections SET ssh_hostkey = ssh_hostkey_pending, ssh_hostkey_pending = NULL
             WHERE id IN (SELECT id FROM link) AND ssh_hostkey_pending = ?4"
        ))
        .bind(id)
        .bind(owner)
        .bind(crate::ssh::MAX_HOPS as i64)
        .bind(fp)
        .execute(&mut *db)
        .await?;
        if done.rows_affected() == 0 {
            return Err(bad("clé SSH à approuver introuvable (relance un réveil pour la faire apparaître)"));
        }
    }
    if let Some(pw) = password {
        let sealed = (!pw.is_empty()).then(|| vault.seal(&format!("ssh:{id}"), pw.as_bytes()));
        sqlx::query("UPDATE connections SET ssh_password = ? WHERE id = ?")
            .bind(sealed)
            .bind(id)
            .execute(&mut *db)
            .await?;
    }
    Ok(Some(id))
}

/// Supprime les lignes cachées de `owner` qu'aucun de ses emplacements n'atteint plus (hôte saisi remplacé
/// par un hôte connu, réveil direct, SSH coupé), en suivant les rebonds d'une ligne cachée à l'autre.
async fn prune_inline(db: &mut SqliteConnection, owner: i64) -> ApiResult<()> {
    sqlx::query(
        "WITH RECURSIVE used(id) AS (
             SELECT wol_via_id FROM connections WHERE id = ?1
             UNION SELECT ssh_jump_id FROM connections WHERE id = ?1
             UNION SELECT c.ssh_jump_id FROM connections c JOIN used u ON c.id = u.id WHERE c.inline_for = ?1)
         DELETE FROM connections WHERE inline_for = ?1 AND id NOT IN (SELECT id FROM used WHERE id IS NOT NULL)",
    )
    .bind(owner)
    .execute(&mut *db)
    .await?;
    Ok(())
}

/// Le rebond doit être un autre hôte SSH, sans boucle (A par B par A), et la chaîne qui part de `jump`
/// compter au plus `MAX_HOPS` hôtes : la borne d'un réveil. Celle d'un terminal, qui compte aussi sa
/// cible, est vérifiée par `check_through`.
async fn check_jump(db: &mut SqliteConnection, id: i64, jump: i64) -> ApiResult<()> {
    let mut cur = Some(jump);
    for _ in 0..crate::ssh::MAX_HOPS {
        let Some(c) = cur else { return Ok(()) };
        if c == id {
            return Err(bad("rebond en boucle : un hôte ne peut pas passer par lui-même"));
        }
        let next: Option<(bool, Option<i64>, String)> =
            sqlx::query_as("SELECT ssh_enabled, ssh_jump_id, name FROM connections WHERE id = ?")
                .bind(c)
                .fetch_optional(&mut *db)
                .await?;
        match next {
            Some((true, j, _)) => cur = j,
            Some((false, _, name)) => return Err(bad(format!("le rebond « {name} » n'a pas de SSH"))),
            None => return Err(bad("le rebond doit être un hôte SSH existant")),
        }
    }
    if cur.is_some() {
        return Err(bad("trop de rebonds enchaînés"));
    }
    Ok(())
}

/// Le rebond de `id` vient de changer : les chaînes qui passent par lui (terminal d'un hôte, lui compris, ou
/// réveil d'une machine) doivent rester dans la borne. Refus en nommant la première qui la dépasserait.
async fn check_through(db: &mut SqliteConnection, id: i64) -> ApiResult<()> {
    let max = crate::ssh::MAX_HOPS as i64;
    // `down` : hôtes de la chaîne de `id`, lui compris ; `up` : lignes qui passent par `id`, à n sauts.
    let over: Option<(String, bool)> = sqlx::query_as(
        "WITH RECURSIVE
             down(id, n) AS (
                 SELECT ?1, 1
                 UNION SELECT c.ssh_jump_id, down.n + 1 FROM down JOIN connections c ON c.id = down.id
                     WHERE c.ssh_jump_id IS NOT NULL AND down.n <= ?2),
             up(id, n) AS (
                 SELECT ?1, 0
                 UNION SELECT c.id, up.n + 1 FROM up JOIN connections c ON c.ssh_jump_id = up.id WHERE up.n <= ?2),
             own(n) AS (SELECT max(n) FROM down)
         SELECT c.name, 0 FROM up JOIN connections c ON c.id = up.id
             WHERE c.inline_for IS NULL AND c.ssh_enabled AND up.n + (SELECT n FROM own) > ?2
         UNION ALL
         SELECT w.name, 1 FROM up JOIN connections w ON w.wol_via_id = up.id
             WHERE w.wol_ssh_command IS NOT NULL AND up.n + (SELECT n FROM own) > ?2
         LIMIT 1",
    )
    .bind(id)
    .bind(max)
    .fetch_optional(&mut *db)
    .await?;
    match over {
        Some((name, wake)) => Err(bad(format!(
            "chaîne trop longue pour {} de « {name} » ({max} hôtes SSH au plus)",
            if wake { "le réveil" } else { "le terminal" }
        ))),
        None => Ok(()),
    }
}

async fn save_password(
    vault: &Vault,
    db: &mut SqliteConnection,
    id: i64,
    pw: &Option<String>,
) -> ApiResult<()> {
    let Some(pw) = pw else { return Ok(()) };
    let sealed = (!pw.is_empty()).then(|| vault.seal(&format!("connection:{id}"), pw.as_bytes()));
    sqlx::query("UPDATE connections SET password = ? WHERE id = ?")
        .bind(sealed)
        .bind(id)
        .execute(&mut *db)
        .await?;
    Ok(())
}

pub async fn create(
    State(state): State<AppState>,
    _: AdminUser,
    Json(i): Json<ConnectionInput>,
) -> ApiResult<(StatusCode, Json<ConnectionAdmin>)> {
    let v = validate(&i)?;
    // Une seule transaction : un refus d'un des réglages (rebond invalide…) n'en laisse aucun à moitié écrit.
    let mut tx = state.db.begin().await?;
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
    .fetch_one(&mut *tx)
    .await?;
    save_password(&state.vault, &mut tx, id, &i.password).await?;
    save_access(&mut tx, id, &i.allowed_users).await?;
    save_wol_command(&state.vault, &mut tx, id, &i.wol_command).await?;
    save_ssh(&state.vault, &mut tx, id, &i.ssh).await?;
    prune_inline(&mut tx, id).await?;
    let row = find_hop(&mut *tx, id).await?;
    let view = to_admin(&mut tx, row).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(view)))
}

pub async fn update(
    State(state): State<AppState>,
    _: AdminUser,
    Path(id): Path<i64>,
    Json(i): Json<ConnectionInput>,
) -> ApiResult<Json<ConnectionAdmin>> {
    let v = validate(&i)?;
    let mut tx = state.db.begin().await?;
    let r = sqlx::query(
        "UPDATE connections SET name = ?1, rdp_enabled = ?2, host = ?3, port = ?4, username = ?5, domain = ?6,
         wol_mac = ?7, wol_target = ?8,
         ssh_hostkey = CASE WHEN host IS NOT ?3 THEN NULL ELSE ssh_hostkey END WHERE id = ?9 AND inline_for IS NULL",
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
    .execute(&mut *tx)
    .await?;
    if r.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    save_password(&state.vault, &mut tx, id, &i.password).await?;
    save_access(&mut tx, id, &i.allowed_users).await?;
    save_wol_command(&state.vault, &mut tx, id, &i.wol_command).await?;
    save_ssh(&state.vault, &mut tx, id, &i.ssh).await?;
    prune_inline(&mut tx, id).await?;
    if i.forget_certificate {
        sqlx::query("UPDATE connections SET cert_sha256 = NULL WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    let row = find_hop(&mut *tx, id).await?;
    let view = to_admin(&mut tx, row).await?;
    tx.commit().await?;
    Ok(Json(view))
}

pub async fn delete(
    State(state): State<AppState>,
    _: AdminUser,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    let mut tx = state.db.begin().await?;
    let listed: Option<i64> =
        sqlx::query_scalar("SELECT id FROM connections WHERE id = ? AND inline_for IS NULL")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    if listed.is_none() {
        return Err(AppError::NotFound);
    }
    // Qui passait par cet hôte garde son chemin : à chaque emplacement, une copie cachée (un hôte saisi) le
    // remplace, rebond compris. Ses propres lignes cachées partent avec lui (ON DELETE CASCADE) ; une ligne
    // cachée d'une autre machine qui passait par lui reçoit une copie possédée par cette machine. Le rebond
    // noté d'une machine au SSH coupé n'est pas copié (ni identifiants ni mot de passe) : il s'efface avec
    // l'hôte (ON DELETE SET NULL).
    let users: Vec<(i64, i64, bool, bool)> = sqlx::query_as(
        "SELECT id, coalesce(inline_for, id), wol_via_id IS ?1,
             ssh_jump_id IS ?1 AND (ssh_enabled OR inline_for IS NOT NULL) FROM connections
         WHERE (wol_via_id = ?1 OR ssh_jump_id = ?1) AND inline_for IS NOT ?1",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    for (user, owner, wol_via, jump) in users {
        if wol_via {
            let copy = copy_hop(&state.vault, &mut tx, id, owner).await?;
            sqlx::query("UPDATE connections SET wol_via_id = ? WHERE id = ?")
                .bind(copy)
                .bind(user)
                .execute(&mut *tx)
                .await?;
        }
        if jump {
            let copy = copy_hop(&state.vault, &mut tx, id, owner).await?;
            sqlx::query("UPDATE connections SET ssh_jump_id = ? WHERE id = ?")
                .bind(copy)
                .bind(user)
                .execute(&mut *tx)
                .await?;
        }
    }
    sqlx::query("DELETE FROM connections WHERE id = ?").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Copie cachée, pour `owner`, de l'hôte `gone` sur le point d'être supprimé, avec la suite de sa chaîne :
/// un hôte connu reste désigné, un rebond saisi de `gone` (qui part avec lui) est copié aussi. Chaque mot de
/// passe est rouvert puis rescellé pour sa nouvelle ligne ; un SSH coupé le reste. Renvoie la copie de `gone`.
async fn copy_hop(vault: &Vault, db: &mut SqliteConnection, gone: i64, owner: i64) -> ApiResult<i64> {
    let mut rows = vec![find_hop(&mut *db, gone).await?];
    let mut next = rows[0].ssh_jump_id;
    while let Some(j) = next {
        let r = find_hop(&mut *db, j).await?;
        // Chaîne bornée à l'enregistrement ; la borne ici ne fait que garantir la fin de la boucle.
        if r.inline_for != Some(gone) || rows.len() > crate::ssh::MAX_HOPS {
            break;
        }
        next = r.ssh_jump_id;
        rows.push(r);
    }
    let mut copy = 0;
    for r in rows.into_iter().rev() {
        copy = sqlx::query_scalar(
            "INSERT INTO connections (name, host, port, rdp_enabled, ssh_enabled, ssh_port, ssh_user,
                 ssh_hostkey, ssh_hostkey_pending, ssh_jump_id, inline_for)
             VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
        )
        .bind(&r.name)
        .bind(&r.host)
        .bind(r.port)
        .bind(r.ssh_enabled)
        .bind(r.ssh_port)
        .bind(&r.ssh_user)
        .bind(&r.ssh_hostkey)
        .bind(&r.ssh_hostkey_pending)
        .bind(next)
        .bind(owner)
        .fetch_one(&mut *db)
        .await?;
        if let Some(sealed) = &r.ssh_password {
            let pw = vault.open(&format!("ssh:{}", r.id), sealed)?;
            sqlx::query("UPDATE connections SET ssh_password = ? WHERE id = ?")
                .bind(vault.seal(&format!("ssh:{copy}"), &pw))
                .bind(copy)
                .execute(&mut *db)
                .await?;
        }
        next = Some(copy);
    }
    Ok(copy)
}

/// Reprend l'ancien réveil « par adresse saisie » (colonnes wol_ssh_*) en hôte saisi : une ligne cachée, mot
/// de passe rescellé pour elle, clé d'hôte approuvée ou en attente gardée. Au démarrage ; sans effet une fois
/// fait. Une machine qui échoue est laissée telle quelle et retentée au démarrage suivant.
pub async fn convert_legacy_wol_hosts(state: &AppState) -> anyhow::Result<()> {
    let ids: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM connections WHERE wol_ssh_host IS NOT NULL AND wol_via_id IS NULL",
    )
    .fetch_all(&state.db)
    .await?;
    for id in ids {
        let done = async {
            let mut tx = state.db.begin().await?;
            convert_legacy_wol_host(&state.vault, &mut tx, id).await?;
            tx.commit().await?;
            anyhow::Ok(())
        };
        match done.await {
            Ok(()) => tracing::info!(connection = id, "réveil par adresse saisie repris en hôte saisi"),
            Err(e) => tracing::error!(connection = id, "reprise du réveil par adresse saisie : {e:#}"),
        }
    }
    Ok(())
}

/// Reprise d'une machine dans la transaction `db` ; `false` si elle n'avait rien à reprendre.
async fn convert_legacy_wol_host(vault: &Vault, db: &mut SqliteConnection, id: i64) -> anyhow::Result<bool> {
    type Legacy = (String, Option<String>, Option<Vec<u8>>, Option<String>, Option<String>);
    let legacy: Option<Legacy> = sqlx::query_as(
        "SELECT wol_ssh_host, wol_ssh_user, wol_ssh_password, wol_ssh_hostkey, wol_ssh_hostkey_pending
         FROM connections WHERE id = ? AND wol_ssh_host IS NOT NULL AND wol_via_id IS NULL",
    )
    .bind(id)
    .fetch_optional(&mut *db)
    .await?;
    let Some((host, user, password, hostkey, pending)) = legacy else { return Ok(false) };
    // L'ancien réveil se connectait toujours au port 22.
    let hop: i64 = sqlx::query_scalar(
        "INSERT INTO connections (name, host, port, rdp_enabled, ssh_enabled, ssh_port, ssh_user, ssh_hostkey,
             ssh_hostkey_pending, inline_for)
         VALUES (?1, ?1, ?2, 0, 1, ?3, ?4, ?5, ?6, ?7) RETURNING id",
    )
    .bind(&host)
    .bind(i64::from(RDP_PORT))
    .bind(i64::from(SSH_PORT))
    .bind(user.unwrap_or_default())
    .bind(hostkey)
    .bind(pending)
    .bind(id)
    .fetch_one(&mut *db)
    .await?;
    if let Some(sealed) = password {
        let pw = vault.open(&format!("wol-ssh:{id}"), &sealed)?;
        sqlx::query("UPDATE connections SET ssh_password = ? WHERE id = ?")
            .bind(vault.seal(&format!("ssh:{hop}"), &pw))
            .bind(hop)
            .execute(&mut *db)
            .await?;
    }
    sqlx::query(
        "UPDATE connections SET wol_via_id = ?, wol_ssh_host = NULL, wol_ssh_user = NULL, wol_ssh_password = NULL,
         wol_ssh_hostkey = NULL, wol_ssh_hostkey_pending = NULL WHERE id = ?",
    )
    .bind(hop)
    .bind(id)
    .execute(&mut *db)
    .await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use portique_proto::ConnectionInput;

    fn input(username: &str, domain: &str) -> ConnectionInput {
        serde_json::from_value(serde_json::json!({
            "name": "pc", "host": "192.0.2.10", "port": null, "username": username, "domain": domain,
        }))
        .unwrap()
    }

    #[test]
    fn rdp_username_and_domain_are_bounded() {
        let max = "é".repeat(255);
        assert!(super::validate(&input(&max, &max)).is_ok());
        let long = "a".repeat(256);
        assert!(super::validate(&input(&long, "")).is_err(), "utilisateur");
        assert!(super::validate(&input("alice", &long)).is_err(), "domaine");
        // Hors BMP : deux unités UTF-16 par caractère.
        assert!(super::validate(&input(&"\u{1F600}".repeat(128), "")).is_err());
    }

    // Rebonds : lignes cachées, hôte saisi, reprise de l'ancien réveil, suppression d'un hôte connu.

    use axum::{
        Json,
        extract::{Path, State},
    };
    use portique_proto::{ConnectionAdmin, HopAdmin};
    use serde_json::{Value, json};

    use super::{AppState, admin_list, create, delete, find_allowed, find_hop, list, update, wake};
    use crate::{
        api::ssh::tests::{state, state_on},
        auth::{AdminUser, CurrentUser, UserRow},
        state::AppError,
    };

    async fn admin(s: &AppState) -> UserRow {
        crate::auth::user_by_name(&s.db, "admin").await.unwrap().unwrap()
    }

    /// Création (`id` absent) ou modification, comme le ferait l'admin.
    async fn save(s: &AppState, id: Option<i64>, body: Value) -> Result<ConnectionAdmin, AppError> {
        let i: ConnectionInput = serde_json::from_value(body).unwrap();
        let a = AdminUser(admin(s).await);
        match id {
            None => create(State(s.clone()), a, Json(i)).await.map(|(_, Json(c))| c),
            Some(id) => update(State(s.clone()), a, Path(id), Json(i)).await.map(|Json(c)| c),
        }
    }

    async fn get(s: &AppState, id: i64) -> ConnectionAdmin {
        let Json(all) = admin_list(State(s.clone()), AdminUser(admin(s).await)).await.unwrap();
        all.into_iter().find(|c| c.id == id).expect("listée")
    }

    async fn hidden(s: &AppState) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM connections WHERE inline_for IS NOT NULL")
            .fetch_one(&s.db)
            .await
            .unwrap()
    }

    async fn scalar<T>(s: &AppState, sql: &'static str, id: i64) -> T
    where
        T: for<'r> sqlx::Decode<'r, sqlx::Sqlite> + sqlx::Type<sqlx::Sqlite> + Send + Unpin,
    {
        sqlx::query_scalar(sql).bind(id).fetch_one(&s.db).await.unwrap()
    }

    async fn password(s: &AppState, id: i64) -> String {
        let sealed: Vec<u8> = scalar(s, "SELECT ssh_password FROM connections WHERE id = ?", id).await;
        String::from_utf8(s.vault.open(&format!("ssh:{id}"), &sealed).unwrap()).unwrap()
    }

    /// Hôte SSH déclaré, rebond éventuel.
    async fn known(s: &AppState, name: &str, host: &str, jump: Option<Value>) -> i64 {
        let ssh = json!({"user": "root", "port": 2222, "password": format!("pw-{name}"), "jump": jump});
        save(s, None, json!({"name": name, "host": host, "rdp": false, "ssh": ssh})).await.unwrap().id
    }

    fn host(addr: &str, via: Option<i64>) -> Value {
        json!({"kind": "host", "host": addr, "port": 2201, "user": "admin", "password": "pw-saisi", "via_id": via})
    }

    /// Machine avec réveil par commande (`wol` : rebond) et SSH (`jump` : rebond) ; `None` = sans.
    fn machine(wol: Option<Value>, jump: Option<Option<Value>>) -> Value {
        json!({"name": "PC", "host": "192.0.2.50", "wol_mac": "00:11:22:33:44:55",
            "wol_command": wol.map(|via| json!({"via": via, "command": "wakeonlan {mac}"})),
            "ssh": jump.map(|jump| json!({"user": "alice", "jump": jump}))})
    }

    #[tokio::test]
    async fn inline_rows_are_never_targets() {
        let s = state("builtin").await;
        let a = admin(&s).await;
        let pc = save(&s, None, machine(None, Some(None))).await.unwrap().id;
        // RDP, SSH et réveil configurés : seule `inline_for` la retient.
        let row: i64 = sqlx::query_scalar(
            "INSERT INTO connections (name, host, port, rdp_enabled, ssh_enabled, ssh_user, wol_mac, inline_for)
             VALUES ('cachée', '192.0.2.7', 3389, 1, 1, 'root', '00:11:22:33:44:66', ?) RETURNING id",
        )
        .bind(pc)
        .fetch_one(&s.db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO connection_access (connection_id, user_id) VALUES (?, ?)")
            .bind(row)
            .bind(a.id)
            .execute(&s.db)
            .await
            .unwrap();

        let Json(mine) = list(State(s.clone()), CurrentUser(a.clone())).await.unwrap();
        assert_eq!(mine.iter().map(|c| c.id).collect::<Vec<_>>(), [pc], "liste de l'utilisateur");
        let Json(all) = admin_list(State(s.clone()), AdminUser(a.clone())).await.unwrap();
        assert_eq!(all.iter().map(|c| c.id).collect::<Vec<_>>(), [pc], "liste de l'admin");
        // Bureau, terminal (et leur revalidation) passent par `find_allowed`.
        for (user, is_admin) in [(a.id, true), (a.id, false)] {
            assert!(matches!(find_allowed(&s.db, user, is_admin, row).await, Err(AppError::NotFound)));
        }
        let r = wake(State(s.clone()), CurrentUser(a.clone()), Path(row)).await;
        assert!(matches!(r, Err(AppError::NotFound)), "réveil");
        let r = save(&s, Some(row), json!({"name": "x", "host": "192.0.2.7"})).await;
        assert!(matches!(r, Err(AppError::NotFound)), "modification");
        let name: String = scalar(&s, "SELECT name FROM connections WHERE id = ?", row).await;
        assert_eq!(name, "cachée", "rien de modifié");
        let r = delete(State(s.clone()), AdminUser(a.clone()), Path(row)).await;
        assert!(matches!(r, Err(AppError::NotFound)), "suppression");

        // Elle sert de saut à la machine qui la désigne.
        sqlx::query("UPDATE connections SET ssh_jump_id = ? WHERE id = ?")
            .bind(row)
            .bind(pc)
            .execute(&s.db)
            .await
            .unwrap();
        let hops = crate::api::ssh::chain(&s, pc).await.unwrap();
        assert_eq!(hops.iter().map(|h| h.id).collect::<Vec<_>>(), [row, pc]);
    }

    #[tokio::test]
    async fn wol_via_host_round_trip() {
        let s = state("builtin").await;
        let gw = known(&s, "gw", "192.0.2.1", None).await;
        let pc =
            save(&s, None, machine(Some(host("192.0.2.2", Some(gw))), Some(Some(host("192.0.2.3", None)))))
                .await
                .unwrap();
        let expected = |addr: &str, via, hostkey: Option<&str>| HopAdmin::Host {
            host: addr.into(),
            port: 2201,
            user: "admin".into(),
            has_password: true,
            via_id: via,
            hostkey: hostkey.map(Into::into),
            pending_hostkey: None,
        };
        assert_eq!(pc.wol_command.as_ref().unwrap().via, expected("192.0.2.2", Some(gw), None));
        assert_eq!(pc.ssh.as_ref().unwrap().jump, Some(expected("192.0.2.3", None, None)));
        let pc = pc.id;
        let wol: i64 = scalar(&s, "SELECT wol_via_id FROM connections WHERE id = ?", pc).await;
        let jump: i64 = scalar(&s, "SELECT ssh_jump_id FROM connections WHERE id = ?", pc).await;
        assert_ne!(wol, jump, "une ligne cachée par emplacement");
        assert_eq!(password(&s, wol).await, "pw-saisi", "scellé pour sa propre ligne");

        // Clé approuvée gardée tant que l'adresse et le port restent, mot de passe gardé sans saisie.
        sqlx::query("UPDATE connections SET ssh_hostkey = 'SHA256:ancienne' WHERE id = ?")
            .bind(wol)
            .execute(&s.db)
            .await
            .unwrap();
        let mut same = host("192.0.2.2", Some(gw));
        same["password"] = Value::Null;
        let back = save(&s, Some(pc), machine(Some(same), None)).await.unwrap();
        assert_eq!(back.wol_command.unwrap().via, expected("192.0.2.2", Some(gw), Some("SHA256:ancienne")));
        assert_eq!(scalar::<i64>(&s, "SELECT wol_via_id FROM connections WHERE id = ?", pc).await, wol);
        let mut moved = host("192.0.2.2", Some(gw));
        moved["port"] = json!(2202);
        let back = save(&s, Some(pc), machine(Some(moved.clone()), None)).await.unwrap();
        let HopAdmin::Host { hostkey, .. } = back.wol_command.unwrap().via else { panic!("hôte saisi") };
        assert_eq!(hostkey, None, "port changé : clé oubliée");

        // Approbation : seulement la clé en attente.
        sqlx::query("UPDATE connections SET ssh_hostkey_pending = 'SHA256:presentee' WHERE id = ?")
            .bind(wol)
            .execute(&s.db)
            .await
            .unwrap();
        moved["approve_hostkey"] = json!("SHA256:autre");
        assert!(save(&s, Some(pc), machine(Some(moved.clone()), None)).await.is_err());
        moved["approve_hostkey"] = json!("SHA256:presentee");
        let back = save(&s, Some(pc), machine(Some(moved.clone()), None)).await.unwrap();
        let HopAdmin::Host { hostkey, pending_hostkey, .. } = back.wol_command.unwrap().via else { panic!() };
        assert_eq!((hostkey.as_deref(), pending_hostkey), (Some("SHA256:presentee"), None));
        moved["approve_hostkey"] = Value::Null;
        moved["forget_hostkey"] = json!(true);
        let back = save(&s, Some(pc), machine(Some(moved.clone()), None)).await.unwrap();
        let HopAdmin::Host { hostkey, .. } = back.wol_command.unwrap().via else { panic!() };
        assert_eq!(hostkey, None, "clé oubliée sur demande, adresse et port inchangés");
        moved["forget_hostkey"] = json!(false);
        moved["password"] = json!("");
        let back = save(&s, Some(pc), machine(Some(moved), None)).await.unwrap();
        let HopAdmin::Host { has_password, .. } = back.wol_command.unwrap().via else { panic!() };
        assert!(!has_password, "mot de passe effacé");

        // Hôte connu : rendu tel quel.
        let known_hop = json!({"kind": "known", "id": gw});
        let back = save(&s, Some(pc), machine(Some(known_hop.clone()), Some(Some(known_hop)))).await.unwrap();
        assert_eq!(back.wol_command.unwrap().via, HopAdmin::Known { id: gw });
        assert_eq!(back.ssh.unwrap().jump, Some(HopAdmin::Known { id: gw }));
    }

    #[tokio::test]
    async fn no_orphan_inline_rows() {
        let s = state("builtin").await;
        let gw = known(&s, "gw", "192.0.2.1", None).await;
        let to_gw = || json!({"kind": "known", "id": gw});
        let pc = save(&s, None, machine(Some(host("192.0.2.2", None)), Some(Some(host("192.0.2.3", None)))))
            .await
            .unwrap()
            .id;
        assert_eq!(hidden(&s).await, 2);
        let steps = [
            (machine(Some(to_gw()), Some(Some(host("192.0.2.3", None)))), 1, "réveil : hôte connu"),
            (
                machine(Some(host("192.0.2.2", None)), Some(Some(host("192.0.2.3", None)))),
                2,
                "réveil : saisi",
            ),
            (machine(None, Some(Some(host("192.0.2.3", None)))), 1, "réveil direct"),
            (machine(None, Some(Some(to_gw()))), 0, "SSH : hôte connu"),
            (machine(None, Some(Some(host("192.0.2.3", None)))), 1, "SSH : saisi"),
            (machine(None, Some(None)), 0, "SSH sans rebond"),
            (machine(None, Some(Some(host("192.0.2.3", None)))), 1, "SSH : saisi"),
            (machine(Some(host("192.0.2.2", None)), None), 1, "SSH coupé"),
        ];
        for (body, n, what) in steps {
            save(&s, Some(pc), body).await.unwrap();
            assert_eq!(hidden(&s).await, n, "{what}");
        }
        // Coupé, le SSH garde un hôte connu comme rebond (réactivation) ; rien de caché ne reste derrière.
        save(&s, Some(pc), machine(None, Some(Some(to_gw())))).await.unwrap();
        save(&s, Some(pc), machine(None, None)).await.unwrap();
        assert_eq!(
            scalar::<Option<i64>>(&s, "SELECT ssh_jump_id FROM connections WHERE id = ?", pc).await,
            Some(gw)
        );
        save(&s, Some(pc), machine(Some(host("192.0.2.2", None)), Some(Some(host("192.0.2.3", None)))))
            .await
            .unwrap();
        delete(State(s.clone()), AdminUser(admin(&s).await), Path(pc)).await.unwrap();
        assert_eq!(hidden(&s).await, 0, "parties avec leur machine");
    }

    #[tokio::test]
    async fn inline_via_loop_refused() {
        let s = state("builtin").await;
        let pc = save(&s, None, machine(None, Some(None))).await.unwrap().id;
        // `back` passe par le PC : un hôte saisi du PC ne peut pas passer par lui.
        let back = known(&s, "retour", "192.0.2.4", Some(json!({"kind": "known", "id": pc}))).await;
        let other = save(&s, None, machine(Some(host("192.0.2.5", None)), Some(None))).await.unwrap().id;
        let others: i64 = scalar(&s, "SELECT wol_via_id FROM connections WHERE id = ?", other).await;
        let before = hidden(&s).await;
        for via in [pc, back, others] {
            let r = save(&s, Some(pc), machine(Some(host("192.0.2.2", Some(via))), Some(None))).await;
            assert!(matches!(r, Err(AppError::BadRequest(_))), "réveil par {via}");
            let r = save(&s, Some(pc), machine(None, Some(Some(host("192.0.2.2", Some(via)))))).await;
            assert!(matches!(r, Err(AppError::BadRequest(_))), "rebond par {via}");
        }
        // Ligne cachée d'une autre machine désignée comme hôte connu : refusé aussi.
        let r = save(&s, Some(pc), machine(Some(json!({"kind": "known", "id": others})), Some(None))).await;
        assert!(matches!(r, Err(AppError::BadRequest(_))));
        assert_eq!(hidden(&s).await, before, "un refus n'écrit rien");
    }

    #[tokio::test]
    async fn legacy_wol_host_is_converted() {
        use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
        // Base telle qu'en production avant 0009 : réveil par adresse saisie, mot de passe scellé pour la
        // machine (`wol-ssh:{id}`), clé d'hôte épinglée ; une autre machine attend l'approbation de sa clé.
        let opts = "sqlite::memory:".parse::<SqliteConnectOptions>().unwrap().foreign_keys(true);
        let db = SqlitePoolOptions::new().max_connections(1).connect_with(opts).await.unwrap();
        let migrator = sqlx::migrate!("./migrations");
        migrator.run_to(8, &db).await.unwrap();
        let vault = crate::crypto::Vault::new(&std::array::from_fn(|i| i as u8));
        sqlx::raw_sql(
            "INSERT INTO connections (name, host, port, wol_mac, wol_ssh_host, wol_ssh_user, wol_ssh_command,
                 wol_ssh_hostkey)
             VALUES ('PC', '192.0.2.50', 3389, '00:11:22:33:44:55', '192.0.2.1', 'admin', 'wakeonlan {mac}',
                 'SHA256:epinglee');
             INSERT INTO connections (name, host, port, wol_mac, wol_ssh_host, wol_ssh_user, wol_ssh_command,
                 wol_ssh_hostkey_pending)
             VALUES ('Portable', '192.0.2.51', 3389, '00:11:22:33:44:56', '192.0.2.1', 'root', 'wakeonlan {mac}',
                 'SHA256:attente');
             INSERT INTO connections (name, host, port, wol_mac) VALUES ('Direct', '192.0.2.52', 3389, '00:11:22:33:44:57');",
        )
        .execute(&db)
        .await
        .unwrap();
        sqlx::query("UPDATE connections SET wol_ssh_password = ? WHERE id = 1")
            .bind(vault.seal("wol-ssh:1", b"pw-rebond"))
            .execute(&db)
            .await
            .unwrap();
        migrator.run(&db).await.unwrap();
        let s = state_on("builtin", db).await;

        for pass in 0..2 {
            super::convert_legacy_wol_hosts(&s).await.unwrap();
            assert_eq!(hidden(&s).await, 2, "passage {pass}");
            let hop: i64 = scalar(&s, "SELECT wol_via_id FROM connections WHERE id = ?", 1).await;
            assert_eq!(scalar::<i64>(&s, "SELECT inline_for FROM connections WHERE id = ?", hop).await, 1);
            assert_eq!(password(&s, hop).await, "pw-rebond", "rescellé pour la ligne cachée");
            let pc = get(&s, 1).await.wol_command.unwrap();
            assert_eq!(pc.command, "wakeonlan {mac}");
            let expected =
                |user: &str, password, hostkey: Option<&str>, pending: Option<&str>| HopAdmin::Host {
                    host: "192.0.2.1".into(),
                    port: 22,
                    user: user.into(),
                    has_password: password,
                    via_id: None,
                    hostkey: hostkey.map(Into::into),
                    pending_hostkey: pending.map(Into::into),
                };
            assert_eq!(pc.via, expected("admin", true, Some("SHA256:epinglee"), None));
            let laptop = get(&s, 2).await.wol_command.unwrap().via;
            assert_eq!(laptop, expected("root", false, None, Some("SHA256:attente")));
            assert!(get(&s, 3).await.wol_command.is_none());
            let left: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM connections WHERE coalesce(wol_ssh_host, wol_ssh_user, wol_ssh_password,
                     wol_ssh_hostkey, wol_ssh_hostkey_pending) IS NOT NULL",
            )
            .fetch_one(&s.db)
            .await
            .unwrap();
            assert_eq!(left, 0, "anciennes colonnes vidées");
        }
    }

    /// Faux serveur SSH local : présente sa clé d'hôte, n'accepte personne. Renvoie (port, empreinte).
    /// `pin` : à chaque connexion, avant de répondre, épingle sa clé sur les rebonds saisis qui le visent
    /// (comme un terminal qui l'approuverait pendant un réveil).
    async fn fake_sshd(pin: Option<sqlx::SqlitePool>) -> (u16, String) {
        use russh::keys::{HashAlg, PrivateKey, ssh_key::private::Ed25519Keypair};
        struct Refuse;
        impl russh::server::Handler for Refuse {
            type Error = russh::Error;
        }
        let key = PrivateKey::from(Ed25519Keypair::from_seed(&[9; 32]));
        let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        let config = std::sync::Arc::new(russh::server::Config { keys: vec![key], ..Default::default() });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let fp = fingerprint.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                if let Some(db) = &pin {
                    sqlx::query(
                        "UPDATE connections SET ssh_hostkey = ? WHERE host = '127.0.0.1' AND ssh_port = ?
                         AND inline_for IS NOT NULL",
                    )
                    .bind(&fp)
                    .bind(i64::from(port))
                    .execute(db)
                    .await
                    .unwrap();
                }
                let config = config.clone();
                tokio::spawn(async move {
                    if let Ok(session) = russh::server::run_stream(config, sock, Refuse).await {
                        let _ = session.await;
                    }
                });
            }
        });
        (port, fingerprint)
    }

    #[tokio::test]
    async fn wake_holds_inline_hostkey_for_approval() {
        let s = state("builtin").await;
        let a = admin(&s).await;
        let (port, fingerprint) = fake_sshd(None).await;
        let mut hop = host("127.0.0.1", None);
        hop["port"] = json!(port);
        let pc = save(&s, None, machine(Some(hop.clone()), None)).await.unwrap().id;

        let r = wake(State(s.clone()), CurrentUser(a.clone()), Path(pc)).await;
        let Err(AppError::BadRequest(msg)) = r else { panic!("réveil refusé attendu : {r:?}") };
        assert!(msg.contains("à approuver dans l'admin de « PC »"), "{msg}");
        let HopAdmin::Host { pending_hostkey, hostkey, .. } = get(&s, pc).await.wol_command.unwrap().via
        else {
            panic!("hôte saisi")
        };
        assert_eq!((pending_hostkey.as_deref(), hostkey), (Some(fingerprint.as_str()), None));
        hop["approve_hostkey"] = json!(fingerprint);
        let back = save(&s, Some(pc), machine(Some(hop), None)).await.unwrap();
        let HopAdmin::Host { pending_hostkey, hostkey, .. } = back.wol_command.unwrap().via else { panic!() };
        assert_eq!((hostkey.as_deref(), pending_hostkey), (Some(fingerprint.as_str()), None));

        // Hôte connu : rien n'est mis en attente, son terminal sert à l'approuver.
        let gw = save(
            &s,
            None,
            json!({"name": "gw", "host": "127.0.0.1", "rdp": false,
            "ssh": {"user": "root", "port": port}}),
        )
        .await
        .unwrap()
        .id;
        let other = save(&s, None, machine(Some(json!({"kind": "known", "id": gw})), None)).await.unwrap().id;
        let r = wake(State(s.clone()), CurrentUser(a), Path(other)).await;
        let Err(AppError::BadRequest(msg)) = r else { panic!("réveil refusé attendu : {r:?}") };
        assert!(msg.contains("ouvre une fois son terminal"), "{msg}");
        let pending: Option<String> =
            scalar(&s, "SELECT ssh_hostkey_pending FROM connections WHERE id = ?", gw).await;
        assert_eq!(pending, None);
    }

    #[tokio::test]
    async fn command_without_hop_is_not_sent_by_udp() {
        let s = state("builtin").await;
        let pc = save(&s, None, machine(Some(host("192.0.2.2", None)), None)).await.unwrap().id;
        // Rebond perdu avant la conversion à la suppression (ON DELETE SET NULL d'une version antérieure).
        sqlx::query("UPDATE connections SET wol_via_id = NULL WHERE id = ?")
            .bind(pc)
            .execute(&s.db)
            .await
            .unwrap();
        let r = wake(State(s.clone()), CurrentUser(admin(&s).await), Path(pc)).await;
        let Err(AppError::BadRequest(msg)) = r else { panic!("{r:?}") };
        assert!(msg.contains("sans hôte de réveil"), "{msg}");
    }

    #[tokio::test]
    async fn delete_converts_dependents() {
        let s = state("builtin").await;
        let j = known(&s, "j", "192.0.2.1", None).await;
        let d = known(&s, "d", "192.0.2.2", Some(json!({"kind": "known", "id": j}))).await;
        // `e` passe par un hôte saisi qui part avec lui : la copie garde ce saut.
        let e = known(&s, "e", "192.0.2.3", Some(host("192.0.2.4", Some(j)))).await;
        sqlx::query("UPDATE connections SET ssh_hostkey = 'SHA256:d' WHERE id = ?")
            .bind(d)
            .execute(&s.db)
            .await
            .unwrap();
        let to = |id: i64| json!({"kind": "known", "id": id});
        let pc = save(&s, None, machine(Some(to(d)), Some(Some(to(d))))).await.unwrap().id;
        let laptop = save(&s, None, machine(Some(to(e)), None)).await.unwrap().id;
        let a = AdminUser(admin(&s).await);
        delete(State(s.clone()), a, Path(d)).await.unwrap();
        delete(State(s.clone()), AdminUser(admin(&s).await), Path(e)).await.unwrap();

        let pc_admin = get(&s, pc).await;
        let copy = |via| HopAdmin::Host {
            host: "192.0.2.2".into(),
            port: 2222,
            user: "root".into(),
            has_password: true,
            via_id: via,
            hostkey: Some("SHA256:d".into()),
            pending_hostkey: None,
        };
        assert_eq!(pc_admin.wol_command.unwrap().via, copy(Some(j)), "réveil : copie de d, par j");
        assert_eq!(pc_admin.ssh.unwrap().jump, Some(copy(Some(j))), "rebond : copie de d, par j");
        let wol: i64 = scalar(&s, "SELECT wol_via_id FROM connections WHERE id = ?", pc).await;
        let jump: i64 = scalar(&s, "SELECT ssh_jump_id FROM connections WHERE id = ?", pc).await;
        assert_ne!(wol, jump, "une copie par emplacement");
        for c in [wol, jump] {
            assert_eq!(password(&s, c).await, "pw-d", "rescellé pour la copie");
            assert_eq!(scalar::<String>(&s, "SELECT name FROM connections WHERE id = ?", c).await, "d");
        }
        let hops = crate::api::ssh::chain(&s, pc).await.unwrap();
        assert_eq!(hops.iter().map(|h| h.id).collect::<Vec<_>>(), [j, jump, pc], "chaîne conservée");
        // Renvoyée par l'admin, la copie garde son nom ; une autre adresse le remplace.
        let mut same =
            json!({"kind": "host", "host": "192.0.2.2", "port": 2222, "user": "root", "via_id": j});
        save(&s, Some(pc), machine(Some(same.clone()), None)).await.unwrap();
        assert_eq!(scalar::<String>(&s, "SELECT name FROM connections WHERE id = ?", wol).await, "d");
        same["host"] = json!("192.0.2.20");
        save(&s, Some(pc), machine(Some(same), None)).await.unwrap();
        assert_eq!(
            scalar::<String>(&s, "SELECT name FROM connections WHERE id = ?", wol).await,
            "192.0.2.20"
        );

        // Copie de e, puis copie de son hôte saisi (supprimé avec lui), puis j.
        let ec: i64 = scalar(&s, "SELECT wol_via_id FROM connections WHERE id = ?", laptop).await;
        let hops = crate::api::ssh::chain(&s, ec).await.unwrap();
        assert_eq!(hops.len(), 3, "j, copie du saisi de e, copie de e");
        assert_eq!((hops[0].id, hops[1].host.as_str(), hops[2].host.as_str()), (j, "192.0.2.4", "192.0.2.3"));
        assert_eq!(password(&s, hops[1].id).await, "pw-saisi");
        for h in &hops[1..] {
            assert_eq!(
                scalar::<i64>(&s, "SELECT inline_for FROM connections WHERE id = ?", h.id).await,
                laptop
            );
        }
        let gone: i64 =
            sqlx::query_scalar("SELECT count(*) FROM connections WHERE id IN (?, ?) OR inline_for IN (?, ?)")
                .bind(d)
                .bind(e)
                .bind(d)
                .bind(e)
                .fetch_one(&s.db)
                .await
                .unwrap();
        assert_eq!(gone, 0, "d, e et leurs lignes cachées supprimés");
    }

    #[tokio::test]
    async fn delete_converts_nested() {
        let s = state("builtin").await;
        let j = known(&s, "j", "192.0.2.1", None).await;
        let d = known(&s, "d", "192.0.2.2", Some(json!({"kind": "known", "id": j}))).await;
        // Le réveil de y passe par un hôte saisi r, lui-même par d.
        let y = save(&s, None, machine(Some(host("192.0.2.9", Some(d))), None)).await.unwrap().id;
        let r: i64 = scalar(&s, "SELECT wol_via_id FROM connections WHERE id = ?", y).await;
        delete(State(s.clone()), AdminUser(admin(&s).await), Path(d)).await.unwrap();

        let dc: i64 = scalar(&s, "SELECT ssh_jump_id FROM connections WHERE id = ?", r).await;
        assert_ne!(dc, d);
        assert_eq!(
            scalar::<i64>(&s, "SELECT inline_for FROM connections WHERE id = ?", dc).await,
            y,
            "copie à y"
        );
        assert_eq!(password(&s, dc).await, "pw-d");
        let hops = crate::api::ssh::chain(&s, r).await.unwrap();
        assert_eq!(hops.iter().map(|h| h.id).collect::<Vec<_>>(), [j, dc, r], "chaîne conservée");
        let via = get(&s, y).await.wol_command.unwrap().via;
        let HopAdmin::Host { via_id, .. } = via else { panic!("hôte saisi") };
        assert_eq!(via_id, Some(dc));

        // Renvoyée telle quelle par l'admin, la copie reste ; retirée, elle ne laisse rien derrière.
        save(&s, Some(y), machine(Some(host("192.0.2.9", Some(dc))), None)).await.unwrap();
        assert_eq!(scalar::<i64>(&s, "SELECT ssh_jump_id FROM connections WHERE id = ?", r).await, dc);
        save(&s, Some(y), machine(Some(host("192.0.2.9", None)), None)).await.unwrap();
        assert_eq!(hidden(&s).await, 1, "seul r reste");
    }

    // Revue de la PR 10.

    /// Liste admin et chaîne lisent la machine et ses rebonds dans un même instantané : la suppression d'un
    /// hôte entre deux lectures (références converties, puis hôte supprimé) ne fait pas échouer la lecture.
    #[tokio::test]
    async fn admin_view_and_chain_read_one_snapshot() {
        // Base sur disque (WAL) : une lecture en cours sur une connexion, la suppression sur une autre.
        let path = std::env::temp_dir().join(format!("portique-instantane-{}.db", std::process::id()));
        let db = crate::open_db(&format!("sqlite://{}", path.display())).await.unwrap();
        let s = state_on("builtin", db).await;
        let g = known(&s, "g", "192.0.2.1", None).await;
        let to_g = || json!({"kind": "known", "id": g});
        let m = save(&s, None, machine(Some(to_g()), Some(Some(to_g())))).await.unwrap().id;
        let mut read = s.db.begin().await.unwrap();
        let row = find_hop(&mut *read, m).await.unwrap();
        delete(State(s.clone()), AdminUser(admin(&s).await), Path(g)).await.unwrap();
        assert!(find_hop(&s.db, g).await.is_err(), "hors de l'instantané, g n'existe plus");
        let view = super::to_admin(&mut read, row).await.unwrap();
        assert_eq!(view.ssh.unwrap().jump, Some(HopAdmin::Known { id: g }));
        assert_eq!(view.wol_command.unwrap().via, HopAdmin::Known { id: g });
        let hops = crate::api::ssh::chain_in(&mut read, &s.vault, m).await.unwrap();
        assert_eq!(hops.iter().map(|h| h.id).collect::<Vec<_>>(), [g, m]);
        drop(read);
        s.db.close().await;
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
        }
    }

    /// Cinq hôtes SSH au plus par chaîne : un réveil en compte cinq, un terminal quatre rebonds et sa cible.
    #[tokio::test]
    async fn chain_budgets_for_wake_and_terminal() {
        let s = state("builtin").await;
        // k1 ← k2 ← k3 ← k4 : chaîne de k4 = k4, k3, k2, k1.
        let mut k = known(&s, "k1", "192.0.2.1", None).await;
        let mut ks = vec![k];
        for i in 2..=5 {
            k = known(&s, &format!("k{i}"), &format!("192.0.2.{i}"), Some(json!({"kind": "known", "id": k})))
                .await;
            ks.push(k);
        }
        // Réveil par un hôte saisi derrière k4 : 5 hôtes, accepté ; derrière k5 : 6, refusé.
        assert!(save(&s, None, machine(Some(host("192.0.2.9", Some(ks[3]))), None)).await.is_ok());
        let r = save(&s, None, machine(Some(host("192.0.2.9", Some(ks[4]))), None)).await;
        assert!(matches!(r, Err(AppError::BadRequest(_))), "6 hôtes");
        // Terminal par k4 : cible + 4 rebonds, accepté ; par k5 : refusé.
        assert!(
            save(&s, None, machine(None, Some(Some(json!({"kind": "known", "id": ks[3]}))))).await.is_ok()
        );
        let r = save(&s, None, machine(None, Some(Some(json!({"kind": "known", "id": ks[4]}))))).await;
        assert!(matches!(r, Err(AppError::BadRequest(_))), "cible + 5 rebonds");
    }

    /// Le rebond d'un relais change : les chaînes des autres qui passent par lui restent dans la borne.
    #[tokio::test]
    async fn relay_change_keeps_other_chains_bounded() {
        let s = state("builtin").await;
        let g = known(&s, "g", "192.0.2.1", None).await;
        let d = known(&s, "d", "192.0.2.2", Some(json!({"kind": "known", "id": g}))).await;
        let c = known(&s, "c", "192.0.2.3", Some(json!({"kind": "known", "id": d}))).await;
        let b = known(&s, "b", "192.0.2.4", Some(json!({"kind": "known", "id": c}))).await;
        // Terminal de a : a, b, c, d, g.
        let a = known(&s, "a", "192.0.2.5", Some(json!({"kind": "known", "id": b}))).await;
        let g_jump = |jump: Option<Value>| json!({"name": "g", "host": "192.0.2.1", "rdp": false, "ssh": {"user": "root", "port": 2222, "jump": jump}});
        let r = save(&s, Some(g), g_jump(Some(host("192.0.2.6", None)))).await;
        let Err(AppError::BadRequest(msg)) = r else { panic!("{r:?}") };
        assert!(msg.contains("terminal de « a »"), "{msg}");
        assert_eq!(hidden(&s).await, 0, "rien d'écrit");
        // SSH de a coupé ; réveil de w par un hôte saisi derrière b : r, b, c, d, g.
        save(&s, Some(a), json!({"name": "a", "host": "192.0.2.5", "rdp": true})).await.unwrap();
        let w = save(&s, None, machine(Some(host("192.0.2.9", Some(b))), None)).await.unwrap();
        let r = save(&s, Some(g), g_jump(Some(host("192.0.2.6", None)))).await;
        let Err(AppError::BadRequest(msg)) = r else { panic!("{r:?}") };
        assert!(msg.contains(&format!("réveil de « {} »", w.name)), "{msg}");
        // Réveil direct : plus rien ne passe par g à cette profondeur.
        save(&s, Some(w.id), machine(None, None)).await.unwrap();
        save(&s, Some(g), g_jump(Some(host("192.0.2.6", None)))).await.unwrap();
    }

    /// Réveil par un hôte saisi qui passe par une copie cachée (hôte connu supprimé avant d'avoir sa clé) :
    /// la clé en attente de la copie s'affiche et s'approuve dans l'admin de la machine.
    #[tokio::test]
    async fn nested_copy_hostkey_is_approvable() {
        let s = state("builtin").await;
        let a = admin(&s).await;
        let (port, fingerprint) = fake_sshd(None).await;
        let d = save(
            &s,
            None,
            json!({"name": "d", "host": "127.0.0.1", "rdp": false,
            "ssh": {"user": "root", "port": port}}),
        )
        .await
        .unwrap()
        .id;
        let y = save(&s, None, machine(Some(host("192.0.2.9", Some(d))), None)).await.unwrap().id;
        delete(State(s.clone()), AdminUser(a.clone()), Path(d)).await.unwrap();
        let r = wake(State(s.clone()), CurrentUser(a.clone()), Path(y)).await;
        let Err(AppError::BadRequest(msg)) = r else { panic!("{r:?}") };
        assert!(msg.contains("à approuver dans l'admin de « PC »"), "{msg}");
        let HopAdmin::Host { pending_hostkey, via_id, .. } = get(&s, y).await.wol_command.unwrap().via else {
            panic!("hôte saisi")
        };
        assert_eq!(pending_hostkey.as_deref(), Some(fingerprint.as_str()), "clé de la copie affichée");
        let copy = via_id.unwrap();

        // Une clé en attente hors de la chaîne de y (autre machine) ne s'approuve pas d'ici.
        let z = save(&s, None, machine(Some(host("192.0.2.8", None)), None)).await.unwrap().id;
        sqlx::query("UPDATE connections SET ssh_hostkey_pending = 'SHA256:ailleurs' WHERE inline_for = ?")
            .bind(z)
            .execute(&s.db)
            .await
            .unwrap();
        let mut hop = host("192.0.2.9", Some(copy));
        hop["password"] = Value::Null;
        hop["approve_hostkey"] = json!("SHA256:ailleurs");
        assert!(save(&s, Some(y), machine(Some(hop.clone()), None)).await.is_err());

        hop["approve_hostkey"] = json!(fingerprint);
        save(&s, Some(y), machine(Some(hop), None)).await.unwrap();
        let key: Option<String> = scalar(&s, "SELECT ssh_hostkey FROM connections WHERE id = ?", copy).await;
        assert_eq!(key.as_deref(), Some(fingerprint.as_str()), "approuvée sur la copie");
        let HopAdmin::Host { pending_hostkey, .. } = get(&s, y).await.wol_command.unwrap().via else {
            panic!()
        };
        assert_eq!(pending_hostkey, None);
    }

    /// Un terminal épingle la clé pendant le réveil : le réveil ne la remet pas en attente.
    #[tokio::test]
    async fn wake_does_not_hold_a_key_pinned_meanwhile() {
        let s = state("builtin").await;
        let (port, fingerprint) = fake_sshd(Some(s.db.clone())).await;
        let mut hop = host("127.0.0.1", None);
        hop["port"] = json!(port);
        let pc = save(&s, None, machine(Some(hop), None)).await.unwrap().id;
        let r = wake(State(s.clone()), CurrentUser(admin(&s).await), Path(pc)).await;
        assert!(matches!(r, Err(AppError::BadRequest(_))), "{r:?}");
        let HopAdmin::Host { pending_hostkey, hostkey, .. } = get(&s, pc).await.wol_command.unwrap().via
        else {
            panic!("hôte saisi")
        };
        assert_eq!((hostkey.as_deref(), pending_hostkey), (Some(fingerprint.as_str()), None));
    }

    /// Le rebond noté d'une machine au SSH coupé disparaît avec l'hôte supprimé, sans copie de ses identifiants.
    #[tokio::test]
    async fn delete_drops_inactive_ssh_jump() {
        let s = state("builtin").await;
        let g = known(&s, "g", "192.0.2.1", None).await;
        let to_g = || json!({"kind": "known", "id": g});
        let pc = save(&s, None, machine(Some(to_g()), Some(Some(to_g())))).await.unwrap().id;
        save(&s, Some(pc), machine(Some(to_g()), None)).await.unwrap();
        delete(State(s.clone()), AdminUser(admin(&s).await), Path(g)).await.unwrap();
        let jump: Option<i64> = scalar(&s, "SELECT ssh_jump_id FROM connections WHERE id = ?", pc).await;
        assert_eq!(jump, None);
        assert_eq!(hidden(&s).await, 1, "seul le réveil (actif) est converti");
    }

    /// Une adresse acceptée sert telle quelle à la connexion : IPv6 sans crochets, nom, IPv4.
    #[tokio::test]
    async fn addresses_are_usable_as_is() {
        use super::normalize_host as n;
        assert_eq!(n(" [2001:db8::20] "), Some("2001:db8::20"));
        assert_eq!(n("2001:db8::20"), Some("2001:db8::20"));
        assert_eq!(n("pc-1.example.com"), Some("pc-1.example.com"));
        for bad in ["[192.0.2.1]", "[pc]", "pc:22", "192.0.2.1:22", "[2001:db8::20", "[[::1]]", "", "a b"] {
            assert_eq!(n(bad), None, "{bad:?}");
        }
        let s = state("builtin").await;
        let mut body = machine(Some(host("[2001:db8::21]", None)), Some(Some(host("[2001:db8::22]", None))));
        body["host"] = json!("[2001:db8::20]");
        let pc = save(&s, None, body).await.unwrap();
        assert_eq!(pc.host, "2001:db8::20");
        let HopAdmin::Host { host: wol, .. } = pc.wol_command.unwrap().via else { panic!() };
        let Some(HopAdmin::Host { host: jump, .. }) = pc.ssh.unwrap().jump else { panic!() };
        assert_eq!((wol.as_str(), jump.as_str()), ("2001:db8::21", "2001:db8::22"));
        for (target, hop) in [("[192.0.2.1]", "192.0.2.2"), ("192.0.2.1", "192.0.2.2:22")] {
            let mut body = machine(Some(host(hop, None)), None);
            body["host"] = json!(target);
            assert!(save(&s, None, body).await.is_err(), "{target} / {hop}");
        }
    }

    /// Ancien réveil que le démarrage n'a pas repris : une modification sans rapport ne l'efface pas. Repris
    /// alors si possible ; sinon la modification est refusée et ses réglages restent.
    #[tokio::test]
    async fn unconverted_legacy_wol_survives_an_update() {
        let s = state("builtin").await;
        let pc = save(&s, None, json!({"name": "PC", "host": "192.0.2.50", "wol_mac": "00:11:22:33:44:55"}))
            .await
            .unwrap()
            .id;
        let legacy = |sealed: Vec<u8>| {
            sqlx::query(
                "UPDATE connections SET wol_ssh_host = '192.0.2.1', wol_ssh_user = 'admin', wol_ssh_password = ?,
                 wol_ssh_command = 'wakeonlan {mac}', wol_ssh_hostkey = 'SHA256:epinglee' WHERE id = ?",
            )
            .bind(sealed)
            .bind(pc)
            .execute(&s.db)
        };
        // Illisible (scellé pour une autre ligne) : modification refusée, réglages intacts.
        legacy(s.vault.seal("wol-ssh:0", b"pw-rebond")).await.unwrap();
        let unrelated = json!({"name": "Renommé", "host": "192.0.2.50", "wol_mac": "00:11:22:33:44:55"});
        assert!(matches!(save(&s, Some(pc), unrelated.clone()).await, Err(AppError::BadRequest(_))));
        let kept: Option<String> = scalar(&s, "SELECT wol_ssh_host FROM connections WHERE id = ?", pc).await;
        assert_eq!(kept.as_deref(), Some("192.0.2.1"));
        // Lisible : repris pendant la modification, et gardé bien que l'admin l'ait vu comme un réveil direct.
        legacy(s.vault.seal(&format!("wol-ssh:{pc}"), b"pw-rebond")).await.unwrap();
        let back = save(&s, Some(pc), unrelated).await.unwrap();
        assert_eq!(back.name, "Renommé");
        let wol = back.wol_command.expect("réveil gardé");
        let HopAdmin::Host { host, hostkey, has_password, .. } = wol.via else { panic!("hôte saisi") };
        assert_eq!(
            (host.as_str(), hostkey.as_deref(), has_password),
            ("192.0.2.1", Some("SHA256:epinglee"), true)
        );
        let hop: i64 = scalar(&s, "SELECT wol_via_id FROM connections WHERE id = ?", pc).await;
        assert_eq!(password(&s, hop).await, "pw-rebond");
    }
}
