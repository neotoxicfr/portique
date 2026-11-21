//! Gestion de son propre compte : mot de passe, TOTP, passkeys (mode intégré seulement).

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use axum_extra::extract::CookieJar;
use portique_proto::{
    AuthMode, CeremonyChallenge, CeremonyFinish, ChangePassword, Combo, DEFAULT_COMBOS, PasskeyInfo, ReAuth,
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
        if !auth::consume_totp(state, &state.db, u, sealed, code).await? {
            return Err(bad("code TOTP invalide"));
        }
    }
    ticket.succeeded();
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
    // N'écrit que sur le hash et la graine TOTP que `reauth` vient de vérifier : un mot de passe remis par
    // un admin pendant le hachage (sessions coupées) ne doit pas être écrasé par l'ancien détenteur du
    // compte, ni un TOTP activé entre-temps contourné par une preuve au mot de passe seul.
    let hash = auth::hash_password(&req.new).await?;
    // Nouveau mot de passe et coupure des sessions (un mot de passe changé doit couper un intrus) dans la
    // même transaction : l'un ne s'enregistre pas sans l'autre, et une connexion au nouveau mot de passe,
    // qui attend la fin de la transaction, garde sa session.
    let mut tx = state.db.begin().await?;
    let r = sqlx::query(
        "UPDATE users SET password_hash = ? WHERE id = ? AND password_hash = ? AND totp_secret IS ?",
    )
    .bind(hash)
    .bind(u.id)
    .bind(u.password_hash.as_deref())
    .bind(u.totp_secret.as_deref())
    .execute(&mut *tx)
    .await?;
    if r.rows_affected() == 0 {
        return Err(AppError::Unauthorized);
    }
    sqlx::query("DELETE FROM sessions WHERE user_id = ?").bind(u.id).execute(&mut *tx).await?;
    tx.commit().await?;
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
    // N'active que la graine vérifiée : effacée entre-temps (remise à zéro de la 2FA par un admin) ou
    // remplacée par une autre configuration, elle ne doit pas revenir. La session doit exister encore : un
    // mot de passe changé l'a coupée, la graine qu'un intrus y a préparée ne s'active pas après coup. Une
    // passkey ajoutée depuis le contrôle exige en plus une session ouverte avec un second facteur.
    let token = jar.get(auth::SESSION_COOKIE).map(|c| crate::crypto::token_hash(c.value()));
    let r = sqlx::query(
        "UPDATE users SET totp_secret = ?1, totp_pending = NULL, totp_last = ?2
         WHERE id = ?3 AND totp_secret IS NULL AND totp_pending = ?4
           AND (?5 OR EXISTS (SELECT 1 FROM sessions s
                              WHERE s.token_hash = ?6 AND s.user_id = ?3 AND s.expires_at >= unixepoch()
                                AND (s.mfa OR NOT EXISTS (SELECT 1 FROM passkeys WHERE user_id = ?3))))",
    )
    .bind(state.vault.seal(&format!("totp:{}", u.id), &secret))
    .bind(step)
    .bind(u.id)
    .bind(&pending)
    .bind(state.cfg.auth_mode == AuthMode::Proxy)
    .bind(token.as_deref())
    .execute(&state.db)
    .await?;
    if r.rows_affected() == 0 {
        // Dire pourquoi : passkey apparue entre-temps, session coupée, ou graine changée.
        second_factor_gate(&state, &u, &jar).await?;
        let alive: bool = sqlx::query_scalar(
            "SELECT ?1 OR EXISTS (SELECT 1 FROM sessions
                                  WHERE token_hash = ?2 AND user_id = ?3 AND expires_at >= unixepoch())",
        )
        .bind(state.cfg.auth_mode == AuthMode::Proxy)
        .bind(token.as_deref())
        .bind(u.id)
        .fetch_one(&state.db)
        .await?;
        return Err(if alive { bad("aucune configuration TOTP en cours") } else { AppError::Unauthorized });
    }
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
    // La session à second facteur qui a passé le contrôle doit exister encore : coupée entre-temps (mot de
    // passe changé, 2FA remise à zéro), elle ne retire plus rien.
    let token = jar.get(auth::SESSION_COOKIE).map(|c| crate::crypto::token_hash(c.value()));
    let r = sqlx::query(
        "UPDATE users SET totp_secret = NULL, totp_last = 0
         WHERE id = ?1 AND (?2 OR EXISTS (SELECT 1 FROM sessions WHERE token_hash = ?3 AND user_id = ?1
                                          AND mfa AND expires_at >= unixepoch()))",
    )
    .bind(u.id)
    .bind(state.cfg.auth_mode == AuthMode::Proxy)
    .bind(token)
    .execute(&state.db)
    .await?;
    if r.rows_affected() == 0 {
        return Err(AppError::Unauthorized);
    }
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
    let ceremony = state.ceremonies.insert(Ceremony::Register { user_id: u.id, state: st });
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
    let token = jar.get(auth::SESSION_COOKIE).map(|c| crate::crypto::token_hash(c.value()));
    let credential = serde_json::to_string(&key).map_err(anyhow::Error::from)?;
    if !store_passkey(&state, u.id, &name, &credential, token.as_deref()).await? {
        return Err(AppError::Unauthorized);
    }
    Ok(StatusCode::CREATED)
}

/// Enregistre la passkey si la session qui a passé les contrôles existe encore et n'a pas expiré (une remise
/// à zéro de la 2FA ou un mot de passe changé par un admin l'a supprimée : la passkey ne doit pas survivre à
/// ce ménage), et si elle a été ouverte avec un second facteur dès que le compte en a un au moment de
/// l'écriture : un TOTP ou une passkey ajoutés pendant la cérémonie comptent.
async fn store_passkey(
    state: &AppState,
    user_id: i64,
    name: &str,
    credential: &str,
    token: Option<&[u8]>,
) -> ApiResult<bool> {
    let r = sqlx::query(
        "INSERT INTO passkeys (user_id, name, credential) SELECT ?1, ?2, ?3
         WHERE ?4 OR EXISTS (SELECT 1 FROM sessions s
                             WHERE s.token_hash = ?5 AND s.user_id = ?1 AND s.expires_at >= unixepoch()
                               AND (s.mfa OR NOT (EXISTS (SELECT 1 FROM passkeys WHERE user_id = ?1)
                                    OR EXISTS (SELECT 1 FROM users WHERE id = ?1 AND totp_secret IS NOT NULL))))",
    )
    .bind(user_id)
    .bind(name)
    .bind(credential)
    .bind(state.cfg.auth_mode == AuthMode::Proxy)
    .bind(token)
    .execute(&state.db)
    .await?;
    Ok(r.rows_affected() == 1)
}

pub async fn passkey_delete(
    State(state): State<AppState>,
    CurrentUser(u): CurrentUser,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    // Retirer la dernière passkey rendrait le compte « sans facteur », donc libre d'enrôlement.
    second_factor_gate(&state, &u, &jar).await?;
    // Le compte a un facteur (cette passkey) : session à second facteur, encore ouverte au moment d'écrire.
    let token = jar.get(auth::SESSION_COOKIE).map(|c| crate::crypto::token_hash(c.value()));
    let r = sqlx::query(
        "DELETE FROM passkeys WHERE id = ?1 AND user_id = ?2
           AND (?3 OR EXISTS (SELECT 1 FROM sessions WHERE token_hash = ?4 AND user_id = ?2
                              AND mfa AND expires_at >= unixepoch()))",
    )
    .bind(id)
    .bind(u.id)
    .bind(state.cfg.auth_mode == AuthMode::Proxy)
    .bind(token.as_deref())
    .execute(&state.db)
    .await?;
    if r.rows_affected() == 1 {
        Ok(StatusCode::NO_CONTENT)
    } else if crate::api::ssh::session_has_mfa(&state, &u, token.as_deref()).await? {
        Err(AppError::NotFound)
    } else {
        Err(AppError::Unauthorized)
    }
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
    // Doublon = même séquence envoyée (Ctrl+C et ctrl+c), pas même texte : Alt+B et Alt+b diffèrent.
    let mut seen = std::collections::HashSet::new();
    if let Some(c) = combos.iter().find(|c| !seen.insert(Combo::parse(c).map(|k| k.bytes()))) {
        return Err(bad(format!("combinaison en double : « {c} »")));
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
    use axum::{
        Json,
        extract::{Path, State},
    };
    use axum_extra::extract::{CookieJar, cookie::Cookie};
    use portique_proto::{ChangePassword, ReAuth, TotpConfirm};

    use crate::{
        auth::{self, ClientIp, CurrentUser, user_by_name},
        state::{AppError, AppState},
    };

    /// Session ouverte pour `user_id`, avec ou sans second facteur, et le cookie qui la porte.
    async fn session(s: &AppState, user_id: i64, token: &'static str, mfa: bool) -> CookieJar {
        sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, expires_at, mfa) VALUES (?, ?, unixepoch() + 60, ?)",
        )
        .bind(crate::crypto::token_hash(token))
        .bind(user_id)
        .bind(mfa)
        .execute(&s.db)
        .await
        .unwrap();
        CookieJar::new().add(Cookie::new(auth::SESSION_COOKIE, token))
    }

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

    /// Sessions impossibles à couper : le nouveau mot de passe n'est pas enregistré non plus.
    #[tokio::test]
    async fn password_kept_when_sessions_cannot_be_cut() {
        let s = crate::api::ssh::tests::state("builtin").await;
        let u = user_by_name(&s.db, "admin").await.unwrap().unwrap();
        sqlx::raw_sql(
            "INSERT INTO sessions (token_hash, user_id, expires_at, mfa) VALUES (x'01', 1, unixepoch() + 60, 0);
             CREATE TRIGGER panne BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT, 'panne'); END;",
        )
        .execute(&s.db)
        .await
        .unwrap();
        let req = ChangePassword {
            auth: ReAuth { password: "admin-password-123".into(), totp: None },
            new: "nouveau-mot-de-passe".into(),
        };
        let ip = ClientIp("192.0.2.1".parse().unwrap());
        assert!(
            super::change_password(State(s.clone()), ip, CurrentUser(u.clone()), Json(req)).await.is_err()
        );
        let now = user_by_name(&s.db, "admin").await.unwrap().unwrap();
        assert_eq!(now.password_hash, u.password_hash, "mot de passe changé, sessions restées ouvertes");
    }

    /// Un TOTP activé depuis un autre appareil pendant le hachage : la requête vérifiée au mot de passe
    /// seul ne change plus le mot de passe.
    #[tokio::test]
    async fn totp_enabled_meanwhile_blocks_password_only_change() {
        let s = crate::api::ssh::tests::state("builtin").await;
        let stale = user_by_name(&s.db, "admin").await.unwrap().unwrap();
        assert!(stale.totp_secret.is_none());
        sqlx::query("UPDATE users SET totp_secret = x'01' WHERE id = ?")
            .bind(stale.id)
            .execute(&s.db)
            .await
            .unwrap();
        let req = ChangePassword {
            auth: ReAuth { password: "admin-password-123".into(), totp: None },
            new: "nouveau-mot-de-passe".into(),
        };
        let ip = ClientIp("192.0.2.1".parse().unwrap());
        let r = super::change_password(State(s.clone()), ip, CurrentUser(stale.clone()), Json(req)).await;
        assert!(matches!(r, Err(AppError::Unauthorized)));
        let now = user_by_name(&s.db, "admin").await.unwrap().unwrap();
        assert_eq!(now.password_hash, stale.password_hash);
    }

    /// Un admin remet la 2FA à zéro, puis une nouvelle configuration démarre, pendant qu'une confirmation
    /// TOTP est en vol (graine lue, code vérifié) : la graine lue n'est pas activée. Base sur disque : la
    /// remise à zéro tient le verrou d'écriture pendant que la confirmation lit la graine, puis attend ce
    /// verrou pour écrire. Seul le refus dit quand la graine a été lue : après le commit, c'est la nouvelle et
    /// le code est refusé (on recommence en attendant plus longtemps) ; avant, seule l'écriture conditionnelle
    /// arrête la confirmation.
    #[tokio::test]
    async fn totp_confirm_does_not_revive_a_reset_seed() {
        let path = std::env::temp_dir().join(format!("portique-totp-{}.db", std::process::id()));
        let db = crate::open_db(&format!("sqlite://{}", path.display())).await.unwrap();
        let s = crate::state::AppState { db, ..crate::api::ssh::tests::state("builtin").await };
        crate::bootstrap_admin(&s).await.unwrap();
        let u = user_by_name(&s.db, "admin").await.unwrap().unwrap();
        let seal = |secret: &[u8]| s.vault.seal(&format!("totp-pending:{}", u.id), secret);
        let jar = session(&s, u.id, "t", false).await;
        let mut verdict = None;
        for wait in [100, 400, 1600] {
            let read = crate::totp::new_secret();
            sqlx::query("UPDATE users SET totp_pending = ? WHERE id = ?")
                .bind(seal(&read))
                .bind(u.id)
                .execute(&s.db)
                .await
                .unwrap();
            let code = crate::totp::build(&read, &u.username).unwrap().generate_current().to_string();

            let mut reset = s.db.begin().await.unwrap();
            sqlx::query("UPDATE users SET totp_secret = NULL, totp_pending = ?, totp_last = 0 WHERE id = ?")
                .bind(seal(&crate::totp::new_secret()))
                .bind(u.id)
                .execute(&mut *reset)
                .await
                .unwrap();
            let confirm = tokio::spawn(super::totp_confirm(
                State(s.clone()),
                CurrentUser(u.clone()),
                jar.clone(),
                Json(TotpConfirm { code }),
            ));
            tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
            reset.commit().await.unwrap();
            match confirm.await.unwrap() {
                Err(AppError::BadRequest(m)) if m.starts_with("code invalide") => continue,
                r => {
                    verdict = Some(r);
                    break;
                }
            }
        }
        let now = user_by_name(&s.db, "admin").await.unwrap().unwrap();
        s.db.close().await;
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
        }
        let verdict = verdict.expect("la confirmation n'a jamais lu la graine avant la remise à zéro");
        assert!(
            matches!(&verdict, Err(AppError::BadRequest(m)) if m == "aucune configuration TOTP en cours"),
            "{verdict:?}"
        );
        assert!(now.totp_secret.is_none(), "graine réactivée après la remise à zéro");
    }

    /// Un facteur apparu pendant la cérémonie (TOTP activé, autre passkey) : l'écriture de la passkey exige
    /// alors une session ouverte avec un second facteur ; un compte toujours sans facteur garde l'inscription.
    #[tokio::test]
    async fn passkey_needs_mfa_session_once_account_has_a_factor() {
        let s = crate::api::ssh::tests::state("builtin").await;
        let u = user_by_name(&s.db, "admin").await.unwrap().unwrap();
        sqlx::raw_sql(
            "INSERT INTO sessions (token_hash, user_id, expires_at, mfa) VALUES
               (x'01', 1, unixepoch() + 60, 0), (x'02', 1, unixepoch() + 60, 1);",
        )
        .execute(&s.db)
        .await
        .unwrap();
        let store = |token: &'static [u8]| super::store_passkey(&s, u.id, "Passkey", "{}", Some(token));
        assert!(store(b"\x01").await.unwrap(), "compte sans facteur : session au mot de passe seul acceptée");
        assert!(!store(b"\x01").await.unwrap(), "passkey apparue : session sans facteur refusée");
        assert!(store(b"\x02").await.unwrap());
        sqlx::query("DELETE FROM passkeys").execute(&s.db).await.unwrap();
        sqlx::query("UPDATE users SET totp_secret = x'01' WHERE id = ?")
            .bind(u.id)
            .execute(&s.db)
            .await
            .unwrap();
        assert!(!store(b"\x01").await.unwrap(), "TOTP apparu : session sans facteur refusée");
        assert!(store(b"\x02").await.unwrap());
    }

    /// Une passkey enregistrée pendant qu'une confirmation TOTP est en vol (contrôle passé) : la confirmation
    /// d'une session sans facteur n'active pas le TOTP. Base sur disque : l'inscription tient le verrou
    /// d'écriture, invisible du contrôle, puis valide pendant que la confirmation attend ce verrou. Machine
    /// trop lente (contrôle après la validation) : le test passe sans rien prouver, il n'échoue pas à tort.
    #[tokio::test]
    async fn passkey_added_meanwhile_blocks_password_only_totp_confirm() {
        let path = std::env::temp_dir().join(format!("portique-totp-pk-{}.db", std::process::id()));
        let db = crate::open_db(&format!("sqlite://{}", path.display())).await.unwrap();
        let s = crate::state::AppState { db, ..crate::api::ssh::tests::state("builtin").await };
        crate::bootstrap_admin(&s).await.unwrap();
        let u = user_by_name(&s.db, "admin").await.unwrap().unwrap();
        let secret = crate::totp::new_secret();
        sqlx::query("UPDATE users SET totp_pending = ? WHERE id = ?")
            .bind(s.vault.seal(&format!("totp-pending:{}", u.id), &secret))
            .bind(u.id)
            .execute(&s.db)
            .await
            .unwrap();
        let code = crate::totp::build(&secret, &u.username).unwrap().generate_current().to_string();
        let jar = session(&s, u.id, "t", false).await;
        let mut register = s.db.begin().await.unwrap();
        sqlx::query("INSERT INTO passkeys (user_id, name, credential) VALUES (?, 'Passkey', '{}')")
            .bind(u.id)
            .execute(&mut *register)
            .await
            .unwrap();
        let confirm = tokio::spawn(super::totp_confirm(
            State(s.clone()),
            CurrentUser(u.clone()),
            jar,
            Json(TotpConfirm { code }),
        ));
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        register.commit().await.unwrap();
        let verdict = confirm.await.unwrap();
        let now = user_by_name(&s.db, "admin").await.unwrap().unwrap();
        s.db.close().await;
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
        }
        assert!(
            matches!(&verdict, Err(AppError::BadRequest(m)) if m.starts_with("reconnecte-toi")),
            "{verdict:?}"
        );
        assert!(now.totp_secret.is_none(), "TOTP activé par une session sans facteur");
    }

    /// Un intrus prépare une graine depuis sa session, puis le titulaire change son mot de passe (sessions
    /// coupées) : la confirmation n'active plus cette graine. Session ouverte sans facteur : la première
    /// activation passe toujours.
    #[tokio::test]
    async fn totp_confirm_needs_a_live_session() {
        let s = crate::api::ssh::tests::state("builtin").await;
        let u = user_by_name(&s.db, "admin").await.unwrap().unwrap();
        let secret = crate::totp::new_secret();
        sqlx::query("UPDATE users SET totp_pending = ? WHERE id = ?")
            .bind(s.vault.seal(&format!("totp-pending:{}", u.id), &secret))
            .bind(u.id)
            .execute(&s.db)
            .await
            .unwrap();
        let code = crate::totp::build(&secret, &u.username).unwrap().generate_current().to_string();
        let confirm = |jar: CookieJar| {
            super::totp_confirm(
                State(s.clone()),
                CurrentUser(u.clone()),
                jar,
                Json(TotpConfirm { code: code.clone() }),
            )
        };
        let intruder = session(&s, u.id, "intrus", false).await;
        sqlx::query("DELETE FROM sessions").execute(&s.db).await.unwrap();
        let r = confirm(intruder).await;
        assert!(matches!(r, Err(AppError::Unauthorized)), "{r:?}");
        assert!(
            user_by_name(&s.db, "admin").await.unwrap().unwrap().totp_secret.is_none(),
            "graine de l'intrus activée"
        );
        let r = confirm(session(&s, u.id, "titulaire", false).await).await;
        assert!(r.is_ok(), "première activation refusée : {r:?}");
        assert!(user_by_name(&s.db, "admin").await.unwrap().unwrap().totp_secret.is_some());
    }

    /// Session à second facteur coupée entre le contrôle et la suppression d'une passkey : la passkey reste.
    /// Base sur disque : la coupure tient le verrou d'écriture, invisible du contrôle, puis valide pendant
    /// que la suppression attend ce verrou. Contrôle trop tardif (il voit déjà la coupure) : on recommence en
    /// attendant plus longtemps.
    #[tokio::test]
    async fn passkey_delete_needs_the_session_still_open() {
        let path = std::env::temp_dir().join(format!("portique-pk-del-{}.db", std::process::id()));
        let db = crate::open_db(&format!("sqlite://{}", path.display())).await.unwrap();
        let s = crate::state::AppState { db, ..crate::api::ssh::tests::state("builtin").await };
        crate::bootstrap_admin(&s).await.unwrap();
        let u = user_by_name(&s.db, "admin").await.unwrap().unwrap();
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO passkeys (user_id, name, credential) VALUES (?, 'Passkey', '{}') RETURNING id",
        )
        .bind(u.id)
        .fetch_one(&s.db)
        .await
        .unwrap();
        let mut verdict = None;
        for wait in [100, 400, 1600] {
            let jar = session(&s, u.id, "t", true).await;
            let mut cut = s.db.begin().await.unwrap();
            sqlx::query("DELETE FROM sessions").execute(&mut *cut).await.unwrap();
            let delete =
                tokio::spawn(super::passkey_delete(State(s.clone()), CurrentUser(u.clone()), jar, Path(id)));
            tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
            cut.commit().await.unwrap();
            match delete.await.unwrap() {
                Err(AppError::BadRequest(m)) if m.starts_with("reconnecte-toi") => continue,
                r => {
                    verdict = Some(r);
                    break;
                }
            }
        }
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM passkeys").fetch_one(&s.db).await.unwrap();
        s.db.close().await;
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
        }
        let verdict = verdict.expect("le contrôle n'a jamais précédé la coupure");
        assert!(matches!(verdict, Err(AppError::Unauthorized)), "{verdict:?}");
        assert_eq!(left, 1, "passkey supprimée par une session coupée");
    }
}
