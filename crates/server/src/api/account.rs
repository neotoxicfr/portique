//! Gestion de son propre compte : mot de passe, TOTP, passkeys (mode intégré seulement).

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use portique_proto::{
    CeremonyChallenge, CeremonyFinish, ChangePassword, PasskeyInfo, ReAuth, TotpConfirm, TotpSetup,
};
use uuid::Uuid;
use webauthn_rs::prelude::{CreationChallengeResponse, RegisterPublicKeyCredential};

use crate::{
    api::auth::load_passkeys,
    auth::{self, ClientIp, CurrentUser, UserRow},
    state::{ApiResult, AppError, AppState, Ceremony, bad},
    totp,
};

fn local(u: &UserRow) -> ApiResult<()> {
    if u.external { Err(bad("compte géré par le proxy d'authentification")) } else { Ok(()) }
}

/// Revérifie le mot de passe (et le TOTP s'il est actif) avant une opération sensible.
/// Les échecs comptent dans la même limitation que la connexion.
async fn reauth(state: &AppState, ip: std::net::IpAddr, u: &UserRow, proof: &ReAuth) -> ApiResult<()> {
    local(u)?;
    if !state.limiter.allowed(ip, &u.username) {
        return Err(AppError::TooManyAttempts);
    }
    let ok = u.password_hash.as_deref().is_some_and(|h| auth::verify_password(&proof.password, h));
    if !ok {
        state.limiter.failed(ip, &u.username);
        return Err(bad("mot de passe actuel incorrect"));
    }
    if let Some(sealed) = &u.totp_secret {
        let secret = state.vault.open(&format!("totp:{}", u.id), sealed)?;
        let last: i64 = sqlx::query_scalar("SELECT totp_last FROM users WHERE id = ?")
            .bind(u.id)
            .fetch_one(&state.db)
            .await?;
        let code = proof.totp.as_deref().unwrap_or_default();
        let Some(step) = totp::verify(&secret, &u.username, code, last)? else {
            state.limiter.failed(ip, &u.username);
            return Err(bad("code TOTP invalide"));
        };
        sqlx::query("UPDATE users SET totp_last = ? WHERE id = ?")
            .bind(step)
            .bind(u.id)
            .execute(&state.db)
            .await?;
    }
    state.limiter.succeeded(ip, &u.username);
    Ok(())
}

pub async fn change_password(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    CurrentUser(u): CurrentUser,
    Json(req): Json<ChangePassword>,
) -> ApiResult<StatusCode> {
    reauth(&state, ip, &u, &req.auth).await?;
    auth::validate_password(&req.new)?;
    sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(auth::hash_password(&req.new)?)
        .bind(u.id)
        .execute(&state.db)
        .await?;
    // Les autres sessions tombent : un mot de passe changé doit couper un intrus.
    sqlx::query("DELETE FROM sessions WHERE user_id = ?").bind(u.id).execute(&state.db).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn totp_setup(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    CurrentUser(u): CurrentUser,
    Json(proof): Json<ReAuth>,
) -> ApiResult<Json<TotpSetup>> {
    // Remplacer une graine existante passe par une désactivation (mot de passe + code).
    if u.totp_secret.is_some() {
        return Err(bad("TOTP déjà actif : désactive-le d'abord"));
    }
    reauth(&state, ip, &u, &proof).await?;
    let secret = totp::new_secret();
    sqlx::query("UPDATE users SET totp_pending = ? WHERE id = ?")
        .bind(state.vault.seal(&format!("totp-pending:{}", u.id), &secret))
        .bind(u.id)
        .execute(&state.db)
        .await?;
    let (secret_base32, otpauth_url) = totp::setup_info(&secret, &u.username)?;
    let qr_svg = totp::qr_svg(&otpauth_url)?;
    Ok(Json(TotpSetup { secret_base32, otpauth_url, qr_svg }))
}

pub async fn totp_confirm(
    State(state): State<AppState>,
    CurrentUser(u): CurrentUser,
    Json(req): Json<TotpConfirm>,
) -> ApiResult<StatusCode> {
    local(&u)?;
    if u.totp_secret.is_some() {
        return Err(bad("TOTP déjà actif"));
    }
    let pending: Option<Vec<u8>> = sqlx::query_scalar("SELECT totp_pending FROM users WHERE id = ?")
        .bind(u.id)
        .fetch_one(&state.db)
        .await?;
    let pending = pending.ok_or_else(|| bad("aucune configuration TOTP en cours"))?;
    let secret = state.vault.open(&format!("totp-pending:{}", u.id), &pending)?;
    let step = totp::verify(&secret, &u.username, &req.code, 0)?
        .ok_or_else(|| bad("code invalide, vérifie l'heure du téléphone"))?;
    sqlx::query("UPDATE users SET totp_secret = ?, totp_pending = NULL, totp_last = ? WHERE id = ?")
        .bind(state.vault.seal(&format!("totp:{}", u.id), &secret))
        .bind(step)
        .bind(u.id)
        .execute(&state.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn totp_disable(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    CurrentUser(u): CurrentUser,
    Json(proof): Json<ReAuth>,
) -> ApiResult<StatusCode> {
    if u.totp_secret.is_none() {
        return Err(bad("TOTP non activé"));
    }
    reauth(&state, ip, &u, &proof).await?;
    sqlx::query("UPDATE users SET totp_secret = NULL, totp_last = 0 WHERE id = ?")
        .bind(u.id)
        .execute(&state.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn passkeys(
    State(state): State<AppState>,
    CurrentUser(u): CurrentUser,
) -> ApiResult<Json<Vec<PasskeyInfo>>> {
    let rows: Vec<(i64, String, String)> =
        sqlx::query_as("SELECT id, name, created_at FROM passkeys WHERE user_id = ? ORDER BY id")
            .bind(u.id)
            .fetch_all(&state.db)
            .await?;
    Ok(Json(rows.into_iter().map(|(id, name, created_at)| PasskeyInfo { id, name, created_at }).collect()))
}

pub async fn passkey_register_start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    CurrentUser(u): CurrentUser,
    Json(proof): Json<ReAuth>,
) -> ApiResult<Json<CeremonyChallenge<CreationChallengeResponse>>> {
    // Une passkey donne un accès durable : on exige la même preuve qu'à la connexion.
    reauth(&state, ip, &u, &proof).await?;
    let existing = load_passkeys(&state, u.id).await?;
    let exclude = existing.iter().map(|(_, k)| k.cred_id().clone()).collect();
    let user_uuid = Uuid::parse_str(&u.webauthn_id).map_err(anyhow::Error::from)?;
    let (options, st) = state
        .webauthn
        .start_passkey_registration(user_uuid, &u.username, &u.username, Some(exclude))
        .map_err(|e| anyhow::anyhow!("webauthn : {e}"))?;
    let ceremony = state.ceremonies.insert(Ceremony::Register { user_id: u.id, state: st });
    Ok(Json(CeremonyChallenge { ceremony, options }))
}

pub async fn passkey_register_finish(
    State(state): State<AppState>,
    CurrentUser(u): CurrentUser,
    Json(req): Json<CeremonyFinish<RegisterPublicKeyCredential>>,
) -> ApiResult<StatusCode> {
    let Some(Ceremony::Register { user_id, state: st }) = state.ceremonies.take(req.ceremony) else {
        return Err(bad("défi expiré, recommence"));
    };
    if user_id != u.id {
        return Err(AppError::Forbidden);
    }
    let key = state
        .webauthn
        .finish_passkey_registration(&req.credential, &st)
        .map_err(|e| bad(format!("passkey refusée : {e}")))?;
    let name = req
        .name
        .map(|n| n.trim().chars().take(64).collect::<String>())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "Passkey".into());
    sqlx::query("INSERT INTO passkeys (user_id, name, credential) VALUES (?, ?, ?)")
        .bind(u.id)
        .bind(name)
        .bind(serde_json::to_string(&key).map_err(anyhow::Error::from)?)
        .execute(&state.db)
        .await?;
    Ok(StatusCode::CREATED)
}

pub async fn passkey_delete(
    State(state): State<AppState>,
    CurrentUser(u): CurrentUser,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    let r = sqlx::query("DELETE FROM passkeys WHERE id = ? AND user_id = ?")
        .bind(id)
        .bind(u.id)
        .execute(&state.db)
        .await?;
    if r.rows_affected() == 0 { Err(AppError::NotFound) } else { Ok(StatusCode::NO_CONTENT) }
}
