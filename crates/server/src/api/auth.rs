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
    let Some(ticket) = state.limiter.reserve(ip, name) else {
        return Err(AppError::TooManyAttempts);
    };
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

    // Le pas TOTP se consomme dans la même transaction que la création de la session : un échec de celle-ci
    // laisse le code utilisable, une connexion aboutie en bloque toujours le rejeu.
    // Code manquant : demandé avant d'ouvrir la transaction, qui n'a rien à faire dans ce cas.
    let code = req.totp.as_deref().filter(|c| !c.is_empty());
    if user.totp_secret.is_some() && code.is_none() {
        // Mot de passe bon : on demande le code, sans compter d'échec.
        ticket.release();
        return Ok((jar, Json(LoginResponse::TotpRequired)));
    }
    let mut tx = state.db.begin().await?;
    if let (Some(sealed), Some(code)) = (&user.totp_secret, code)
        && !auth::consume_totp(&state, &mut *tx, &user, sealed, code).await?
    {
        return Err(AppError::BadRequest("code TOTP invalide".into()));
    }

    // Mot de passe + TOTP vérifié ci-dessus : second facteur.
    let proof = auth::Proof::Password {
        hash: user.password_hash.as_deref().unwrap_or_default(),
        totp: user.totp_secret.as_deref(),
    };
    // Succès noté une fois la session née : une preuve révoquée entre-temps reste un échec compté.
    let jar = auth::open_session(&state, &mut tx, jar, user.id, proof).await?;
    tx.commit().await?;
    ticket.succeeded();
    tracing::info!(%ip, user = user.username, "connexion");
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
    let Some(ticket) = state.limiter.reserve(ip, name) else {
        return Err(AppError::TooManyAttempts);
    };
    let user = auth::user_by_name(&state.db, name).await?;
    let keys = match &user {
        Some(u) => load_passkeys(&state, u.id).await?,
        None => vec![],
    };
    let (Some(user), false) = (user, keys.is_empty()) else {
        return Err(AppError::BadRequest("aucune passkey pour ce compte".into()));
    };
    let (passkeys, creds): (Vec<i64>, Vec<Passkey>) = keys.into_iter().unzip();
    let (options, st) =
        state.webauthn.start_passkey_authentication(&creds).map_err(|e| anyhow::anyhow!("webauthn : {e}"))?;
    let ceremony = state.ceremonies.insert(Ceremony::Login { user_id: user.id, state: st, ticket, passkeys });
    Ok(Json(CeremonyChallenge { ceremony, options }))
}

pub async fn passkey_finish(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    jar: CookieJar,
    Json(req): Json<CeremonyFinish<PublicKeyCredential>>,
) -> ApiResult<(CookieJar, Json<LoginResponse>)> {
    require_builtin(&state)?;
    let Some(Ceremony::Login { user_id, state: st, ticket, passkeys }) = state.ceremonies.take(req.ceremony)
    else {
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

    // La passkey doit toujours être enregistrée : le défi a pu être émis avant sa suppression. Et ce doit être
    // la ligne dont la clé a vérifié la signature, chargée au démarrage : une autre passkey du même
    // `cred_id` inscrite depuis (identifiants jamais réattribués, 0007) n'ouvre pas de session à sa place.
    // Son compteur de signature ne s'écrit que sur la version lue : deux connexions simultanées ne le font
    // pas reculer, la perdante repart de ce que l'autre a écrit.
    let id = loop {
        // Texte stocké gardé tel quel pour l'écriture conditionnelle : une resérialisation ne lui serait pas
        // forcément identique (passkey écrite par une autre version de webauthn-rs).
        let rows: Vec<(i64, String)> =
            sqlx::query_as("SELECT id, credential FROM passkeys WHERE user_id = ?")
                .bind(user_id)
                .fetch_all(&state.db)
                .await?;
        let mut found = None;
        for (id, read) in rows.into_iter().filter(|(id, _)| passkeys.contains(id)) {
            let key: Passkey = serde_json::from_str(&read).map_err(anyhow::Error::from)?;
            if key.cred_id() == result.cred_id() {
                found = Some((id, read, key));
                break;
            }
        }
        let Some((id, read, mut key)) = found else {
            tracing::info!(%ip, user = user.username, "passkey retirée pendant la connexion");
            return Err(AppError::Unauthorized);
        };
        if key.update_credential(&result) != Some(true) {
            break id;
        }
        let r = sqlx::query("UPDATE passkeys SET credential = ? WHERE id = ? AND credential = ?")
            .bind(serde_json::to_string(&key).map_err(anyhow::Error::from)?)
            .bind(id)
            .bind(&read)
            .execute(&state.db)
            .await?;
        if r.rows_affected() == 1 {
            break id;
        }
    };

    let jar =
        auth::open_session(&state, &mut *state.db.acquire().await?, jar, user.id, auth::Proof::Passkey(id))
            .await?;
    // Rendue aux clés du démarrage (le ticket les porte) : l'adresse de la fin peut différer (réseau
    // mobile, double pile).
    ticket.succeeded();
    tracing::info!(%ip, user = user.username, "connexion par passkey");
    Ok((jar, Json(LoginResponse::Ok { me: user.me() })))
}

#[cfg(test)]
mod tests {
    use axum::{Json, extract::State};
    use axum_extra::extract::CookieJar;
    use portique_proto::LoginRequest;

    use crate::auth::{ClientIp, user_by_name};

    /// La session ne peut pas être créée : le code TOTP n'est pas consommé, le même code sert au nouvel essai.
    #[tokio::test]
    async fn totp_code_still_usable_when_session_fails() {
        let s = crate::api::ssh::tests::state("builtin").await;
        let u = user_by_name(&s.db, "admin").await.unwrap().unwrap();
        let secret = crate::totp::new_secret();
        sqlx::query("UPDATE users SET totp_secret = ? WHERE id = ?")
            .bind(s.vault.seal(&format!("totp:{}", u.id), &secret))
            .bind(u.id)
            .execute(&s.db)
            .await
            .unwrap();
        let code = crate::totp::build(&secret, &u.username).unwrap().generate_current().to_string();
        let login = || {
            let req = LoginRequest {
                username: "admin".into(),
                password: "admin-password-123".into(),
                totp: Some(code.clone()),
            };
            super::login(
                State(s.clone()),
                ClientIp("192.0.2.1".parse().unwrap()),
                CookieJar::new(),
                Json(req),
            )
        };
        sqlx::raw_sql(
            "CREATE TRIGGER panne BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT, 'panne'); END",
        )
        .execute(&s.db)
        .await
        .unwrap();
        assert!(login().await.is_err());
        sqlx::raw_sql("DROP TRIGGER panne").execute(&s.db).await.unwrap();
        assert!(login().await.is_ok(), "code consommé par la connexion qui a échoué");
        assert!(login().await.is_err(), "code rejoué après une connexion aboutie");
    }
}
