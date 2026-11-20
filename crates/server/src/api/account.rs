//! Gestion de son propre compte : mot de passe, TOTP, passkeys (mode intégré seulement).

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use axum_extra::extract::CookieJar;
use portique_proto::{
    CeremonyChallenge, CeremonyFinish, ChangePassword, Combo, DEFAULT_COMBOS, PasskeyInfo, ReAuth,
    TERMINAL_THEMES, TerminalPrefs, TotpConfirm, TotpSetup,
};
use uuid::Uuid;
use webauthn_rs::prelude::{CreationChallengeResponse, RegisterPublicKeyCredential};

use crate::{
    api::auth::load_passkeys,
    auth::{self, ClientIp, CurrentUser, UserRow},
    state::{ApiResult, AppError, AppState, Ceremony, bad},
    totp,
};

/// Un compte qui a déjà un second facteur n'en ajoute ni n'en retire un que depuis une session ouverte avec lui.
/// Sinon, un compte à passkey seule (connexion au mot de passe encore possible) se ferait enrôler un
/// facteur par quiconque a son mot de passe, et le SSH s'ouvrirait.
pub(crate) async fn second_factor_gate(state: &AppState, u: &UserRow, jar: &CookieJar) -> ApiResult<()> {
    let passkey: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM passkeys WHERE user_id = ?)")
        .bind(u.id)
        .fetch_one(&state.db)
        .await?;
    let token = jar.get(auth::SESSION_COOKIE).map(|c| crate::crypto::token_hash(c.value()));
    if (passkey || u.totp_secret.is_some())
        && !crate::api::ssh::session_has_mfa(state, u, token.as_deref()).await?
    {
        return Err(bad("reconnecte-toi avec ta passkey ou ton TOTP pour ajouter un facteur"));
    }
    Ok(())
}

fn local(u: &UserRow) -> ApiResult<()> {
    if u.external { Err(bad("compte géré par le proxy d'authentification")) } else { Ok(()) }
}

/// Revérifie le mot de passe (et le TOTP s'il est actif) avant une opération sensible.
/// Les tentatives comptent dans la même limitation que la connexion.
async fn reauth(state: &AppState, ip: std::net::IpAddr, u: &UserRow, proof: &ReAuth) -> ApiResult<()> {
    local(u)?;
    let Some(ticket) = state.limiter.reserve(ip, &u.username) else {
        return Err(AppError::TooManyAttempts);
    };
    let ok = match u.password_hash.as_deref() {
        Some(h) => auth::verify_password(&proof.password, h).await,
        None => false,
    };
    if !ok {
        return Err(bad("mot de passe actuel incorrect"));
    }
    if let Some(sealed) = &u.totp_secret {
        let code = proof.totp.as_deref().unwrap_or_default();
        if !auth::consume_totp(state, u, sealed, code).await? {
            return Err(bad("code TOTP invalide"));
        }
    }
    state.limiter.succeeded(ip, &u.username, ticket);
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
    // N'écrit que sur le hash que `reauth` vient de vérifier : un mot de passe remis par un admin pendant
    // le hachage (sessions coupées) ne doit pas être écrasé par l'ancien détenteur du compte.
    let r = sqlx::query("UPDATE users SET password_hash = ? WHERE id = ? AND password_hash = ?")
        .bind(auth::hash_password(&req.new).await?)
        .bind(u.id)
        .bind(u.password_hash.as_deref())
        .execute(&state.db)
        .await?;
    if r.rows_affected() == 0 {
        return Err(AppError::Unauthorized);
    }
    // Les autres sessions tombent : un mot de passe changé doit couper un intrus.
    sqlx::query("DELETE FROM sessions WHERE user_id = ?").bind(u.id).execute(&state.db).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn totp_setup(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    CurrentUser(u): CurrentUser,
    jar: CookieJar,
    Json(proof): Json<ReAuth>,
) -> ApiResult<Json<TotpSetup>> {
    // Remplacer une graine existante passe par une désactivation (mot de passe + code).
    if u.totp_secret.is_some() {
        return Err(bad("TOTP déjà actif : désactive-le d'abord"));
    }
    reauth(&state, ip, &u, &proof).await?;
    second_factor_gate(&state, &u, &jar).await?;
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
    jar: CookieJar,
    Json(req): Json<TotpConfirm>,
) -> ApiResult<StatusCode> {
    local(&u)?;
    if u.totp_secret.is_some() {
        return Err(bad("TOTP déjà actif"));
    }
    second_factor_gate(&state, &u, &jar).await?;
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
    jar: CookieJar,
    Json(proof): Json<ReAuth>,
) -> ApiResult<StatusCode> {
    if u.totp_secret.is_none() {
        return Err(bad("TOTP non activé"));
    }
    reauth(&state, ip, &u, &proof).await?;
    second_factor_gate(&state, &u, &jar).await?;
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
    jar: CookieJar,
    Json(proof): Json<ReAuth>,
) -> ApiResult<Json<CeremonyChallenge<CreationChallengeResponse>>> {
    // Une passkey donne un accès durable : on exige la même preuve qu'à la connexion.
    reauth(&state, ip, &u, &proof).await?;
    second_factor_gate(&state, &u, &jar).await?;
    let existing = load_passkeys(&state, u.id).await?;
    let exclude = existing.iter().map(|(_, k)| k.cred_id().clone()).collect();
    let user_uuid = Uuid::parse_str(&u.webauthn_id).map_err(anyhow::Error::from)?;
    let (options, st) = state
        .webauthn
        .start_passkey_registration(user_uuid, &u.username, &u.username, Some(exclude))
        .map_err(|e| anyhow::anyhow!("webauthn : {e}"))?;
    let ceremony = state.ceremonies.insert(Ceremony::Register { user_id: u.id, state: st })?;
    Ok(Json(CeremonyChallenge { ceremony, options }))
}

pub async fn passkey_register_finish(
    State(state): State<AppState>,
    CurrentUser(u): CurrentUser,
    jar: CookieJar,
    Json(req): Json<CeremonyFinish<RegisterPublicKeyCredential>>,
) -> ApiResult<StatusCode> {
    // Un facteur a pu apparaître depuis le début de la cérémonie.
    second_factor_gate(&state, &u, &jar).await?;
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
    jar: CookieJar,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    // Retirer la dernière passkey rendrait le compte « sans facteur », donc libre d'enrôlement.
    second_factor_gate(&state, &u, &jar).await?;
    let r = sqlx::query("DELETE FROM passkeys WHERE id = ? AND user_id = ?")
        .bind(id)
        .bind(u.id)
        .execute(&state.db)
        .await?;
    if r.rows_affected() == 0 { Err(AppError::NotFound) } else { Ok(StatusCode::NO_CONTENT) }
}

/// Préférences de terminal du compte, valeurs par défaut comprises.
pub(crate) async fn terminal_prefs(db: &sqlx::SqlitePool, user_id: i64) -> ApiResult<TerminalPrefs> {
    let (theme, combos): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT terminal_theme, key_combos FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_one(db)
            .await?;
    Ok(TerminalPrefs {
        theme: theme.unwrap_or_else(|| TERMINAL_THEMES[0].into()),
        combos: combos
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or_else(|| DEFAULT_COMBOS.iter().map(|c| (*c).into()).collect()),
    })
}

pub async fn terminal_get(
    State(state): State<AppState>,
    CurrentUser(u): CurrentUser,
) -> ApiResult<Json<TerminalPrefs>> {
    Ok(Json(terminal_prefs(&state.db, u.id).await?))
}

/// Préférences de terminal : réglables aussi par un compte géré par le proxy (rien de sensible).
pub async fn terminal_set(
    State(state): State<AppState>,
    CurrentUser(u): CurrentUser,
    Json(p): Json<TerminalPrefs>,
) -> ApiResult<Json<TerminalPrefs>> {
    if !TERMINAL_THEMES.contains(&p.theme.as_str()) {
        return Err(bad("thème de terminal inconnu"));
    }
    if p.combos.len() > 12 {
        return Err(bad("12 combinaisons au plus"));
    }
    let combos: Vec<String> = p.combos.iter().map(|c| c.trim().to_owned()).collect();
    if let Some(c) = combos.iter().find(|c| Combo::parse(c).is_none()) {
        return Err(bad(format!("combinaison invalide : « {c} » (ex. Ctrl+C, Alt+B, Ctrl+Alt+D)")));
    }
    sqlx::query("UPDATE users SET terminal_theme = ?, key_combos = ? WHERE id = ?")
        .bind(&p.theme)
        .bind(serde_json::to_string(&combos).map_err(anyhow::Error::from)?)
        .bind(u.id)
        .execute(&state.db)
        .await?;
    Ok(Json(TerminalPrefs { theme: p.theme, combos }))
}

#[cfg(test)]
mod tests {
    use axum::{Json, extract::State};
    use portique_proto::{ChangePassword, ReAuth};

    use crate::{
        auth::{self, ClientIp, CurrentUser, user_by_name},
        state::AppError,
    };

    /// Un admin remet le mot de passe pendant que l'ancien détenteur change le sien (requête déjà
    /// authentifiée, hash vérifié) : l'écriture de ce dernier ne passe plus, celle de l'admin reste.
    #[tokio::test]
    async fn password_reset_meanwhile_is_not_overwritten() {
        let s = crate::api::ssh::tests::state("builtin").await;
        let stale = user_by_name(&s.db, "admin").await.unwrap().unwrap();
        sqlx::query("UPDATE users SET password_hash = 'remis' WHERE id = ?")
            .bind(stale.id)
            .execute(&s.db)
            .await
            .unwrap();
        let req = || ChangePassword {
            auth: ReAuth { password: "admin-password-123".into(), totp: None },
            new: "nouveau-mot-de-passe".into(),
        };
        let ip = ClientIp("192.0.2.1".parse().unwrap());
        let r = super::change_password(State(s.clone()), ip, CurrentUser(stale.clone()), Json(req())).await;
        assert!(matches!(r, Err(AppError::Unauthorized)));
        let now = user_by_name(&s.db, "admin").await.unwrap().unwrap();
        assert_eq!(now.password_hash.as_deref(), Some("remis"));

        // Sans écriture concurrente, le changement passe.
        sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(stale.password_hash.as_deref())
            .bind(stale.id)
            .execute(&s.db)
            .await
            .unwrap();
        let ip = ClientIp("192.0.2.1".parse().unwrap());
        assert!(super::change_password(State(s.clone()), ip, CurrentUser(stale), Json(req())).await.is_ok());
        let now = user_by_name(&s.db, "admin").await.unwrap().unwrap();
        assert!(auth::verify_password("nouveau-mot-de-passe", now.password_hash.as_deref().unwrap()).await);
    }
}
