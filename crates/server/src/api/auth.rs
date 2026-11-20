//! Connexion / déconnexion (mode intégré) et identité courante.

use axum::{Json, extract::State};
use axum_extra::extract::CookieJar;
use portique_proto::{
    AuthMode, CeremonyChallenge, CeremonyFinish, LoginRequest, LoginResponse, Me, PasskeyLoginStart,
    ServerInfo,
};
use webauthn_rs::prelude::{Passkey, PublicKeyCredential, RequestChallengeResponse};

use crate::{
    auth::{self, ClientIp, CurrentUser},
    state::{ApiResult, AppError, AppState, Ceremony},
};

pub async fn info(State(state): State<AppState>) -> Json<ServerInfo> {
    Json(ServerInfo { auth_mode: state.cfg.auth_mode, version: env!("CARGO_PKG_VERSION").into() })
}

pub async fn me(CurrentUser(u): CurrentUser) -> Json<Me> {
    Json(u.me())
}

fn require_builtin(state: &AppState) -> ApiResult<()> {
    match state.cfg.auth_mode {
        AuthMode::Builtin => Ok(()),
        AuthMode::Proxy => Err(AppError::NotFound),
    }
}

pub async fn login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> ApiResult<(CookieJar, Json<LoginResponse>)> {
    require_builtin(&state)?;
    let name = req.username.trim();
    if !state.limiter.reserve(ip, name) {
        return Err(AppError::TooManyAttempts);
    }
    let user = auth::user_by_name(&state.db, name).await?;
    let ok = match user.as_ref().and_then(|u| u.password_hash.as_deref()) {
        Some(hash) => auth::verify_password(&req.password, hash).await,
        None => {
            auth::dummy_verify(&req.password).await;
            false
        }
    };
    let Some(user) = user.filter(|_| ok) else {
        tracing::info!(%ip, user = name, "échec de connexion");
        return Err(AppError::Unauthorized);
    };

    if let Some(sealed) = &user.totp_secret {
        let Some(code) = req.totp.as_deref().filter(|c| !c.is_empty()) else {
            // Mot de passe bon : on demande le code, sans compter d'échec.
            state.limiter.release(ip, name);
            return Ok((jar, Json(LoginResponse::TotpRequired)));
        };
        if !auth::consume_totp(&state, &user, sealed, code).await? {
            return Err(AppError::BadRequest("code TOTP invalide".into()));
        }
    }

    state.limiter.succeeded(ip, name);
    tracing::info!(%ip, user = user.username, "connexion");
    // Mot de passe + TOTP vérifié ci-dessus : second facteur.
    let proof = auth::Proof::Password {
        hash: user.password_hash.as_deref().unwrap_or_default(),
        totp: user.totp_secret.as_deref(),
    };
    let jar = auth::open_session(&state, jar, user.id, proof).await?;
    Ok((jar, Json(LoginResponse::Ok { me: user.me() })))
}

pub async fn logout(State(state): State<AppState>, jar: CookieJar) -> ApiResult<CookieJar> {
    auth::close_session(&state, jar).await
}

pub async fn load_passkeys(state: &AppState, user_id: i64) -> ApiResult<Vec<(i64, Passkey)>> {
    let rows: Vec<(i64, String)> = sqlx::query_as("SELECT id, credential FROM passkeys WHERE user_id = ?")
        .bind(user_id)
        .fetch_all(&state.db)
        .await?;
    rows.into_iter()
        .map(|(id, json)| Ok((id, serde_json::from_str(&json).map_err(anyhow::Error::from)?)))
        .collect()
}

/// Début de connexion par passkey : l'identifiant d'abord, puis le défi pour ses passkeys.
pub async fn passkey_start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<PasskeyLoginStart>,
) -> ApiResult<Json<CeremonyChallenge<RequestChallengeResponse>>> {
    require_builtin(&state)?;
    let name = req.username.trim();
    // Chaque démarrage compte comme une tentative, rendue si la connexion aboutit : sinon des démarrages
    // sans fin pour un compte valide rempliraient la table des défis.
    if !state.limiter.reserve(ip, name) {
        return Err(AppError::TooManyAttempts);
    }
    let user = auth::user_by_name(&state.db, name).await?;
    let keys = match &user {
        Some(u) => load_passkeys(&state, u.id).await?,
        None => vec![],
    };
    let (Some(user), false) = (user, keys.is_empty()) else {
        return Err(AppError::BadRequest("aucune passkey pour ce compte".into()));
    };
    let creds: Vec<Passkey> = keys.into_iter().map(|(_, k)| k).collect();
    let (options, st) =
        state.webauthn.start_passkey_authentication(&creds).map_err(|e| anyhow::anyhow!("webauthn : {e}"))?;
    let ceremony = state.ceremonies.insert(Ceremony::Login { user_id: user.id, state: st })?;
    Ok(Json(CeremonyChallenge { ceremony, options }))
}

pub async fn passkey_finish(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    jar: CookieJar,
    Json(req): Json<CeremonyFinish<PublicKeyCredential>>,
) -> ApiResult<(CookieJar, Json<LoginResponse>)> {
    require_builtin(&state)?;
    let Some(Ceremony::Login { user_id, state: st }) = state.ceremonies.take(req.ceremony) else {
        return Err(AppError::BadRequest("défi expiré, recommence".into()));
    };
    let user = auth::user_by_id(&state.db, user_id).await?.ok_or(AppError::Unauthorized)?;
    // L'échec reste compté : le démarrage a réservé la tentative.
    let result = match state.webauthn.finish_passkey_authentication(&req.credential, &st) {
        Ok(r) => r,
        Err(e) => {
            tracing::info!(%ip, user = user.username, "échec passkey : {e}");
            return Err(AppError::Unauthorized);
        }
    };

    // La passkey doit toujours être enregistrée : le défi a pu être émis avant sa suppression.
    let Some((id, mut key)) =
        load_passkeys(&state, user_id).await?.into_iter().find(|(_, k)| k.cred_id() == result.cred_id())
    else {
        tracing::info!(%ip, user = user.username, "passkey retirée pendant la connexion");
        return Err(AppError::Unauthorized);
    };
    // Met à jour son compteur de signature.
    if key.update_credential(&result) == Some(true) {
        sqlx::query("UPDATE passkeys SET credential = ? WHERE id = ?")
            .bind(serde_json::to_string(&key).map_err(anyhow::Error::from)?)
            .bind(id)
            .execute(&state.db)
            .await?;
    }

    state.limiter.succeeded(ip, &user.username);
    tracing::info!(%ip, user = user.username, "connexion par passkey");
    let jar = auth::open_session(&state, jar, user.id, auth::Proof::Passkey(id)).await?;
    Ok((jar, Json(LoginResponse::Ok { me: user.me() })))
}
