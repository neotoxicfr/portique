//! Gestion des comptes par l'admin.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use yawrdp_proto::{AuthMode, UserAdmin, UserInput};

use crate::{
    auth::{self, AdminUser},
    state::{ApiResult, AppError, AppState, bad},
};

pub async fn list(State(state): State<AppState>, _: AdminUser) -> ApiResult<Json<Vec<UserAdmin>>> {
    let rows: Vec<(i64, String, bool, bool, bool, i64)> = sqlx::query_as(
        "SELECT u.id, u.username, u.is_admin, u.totp_secret IS NOT NULL, u.external,
                (SELECT count(*) FROM passkeys p WHERE p.user_id = u.id)
         FROM users u ORDER BY u.username",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(id, username, is_admin, totp_enabled, external, passkeys)| UserAdmin {
                id,
                username,
                is_admin,
                totp_enabled,
                passkeys: passkeys as u32,
                external,
            })
            .collect(),
    ))
}

pub async fn create(
    State(state): State<AppState>,
    _: AdminUser,
    Json(i): Json<UserInput>,
) -> ApiResult<StatusCode> {
    if state.cfg.auth_mode == AuthMode::Proxy {
        return Err(bad("en mode proxy, les comptes sont créés par le proxy"));
    }
    let name = i.username.trim();
    auth::validate_username(name)?;
    let pw = i.password.as_deref().ok_or_else(|| bad("mot de passe requis"))?;
    auth::validate_password(pw)?;
    let r =
        sqlx::query("INSERT INTO users (username, password_hash, is_admin, webauthn_id) VALUES (?, ?, ?, ?)")
            .bind(name)
            .bind(auth::hash_password(pw)?)
            .bind(i.is_admin)
            .bind(uuid::Uuid::new_v4().to_string())
            .execute(&state.db)
            .await;
    match r {
        Ok(_) => Ok(StatusCode::CREATED),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            Err(AppError::Conflict("identifiant déjà pris".into()))
        }
        Err(e) => Err(e.into()),
    }
}

pub async fn update(
    State(state): State<AppState>,
    AdminUser(me): AdminUser,
    Path(id): Path<i64>,
    Json(i): Json<UserInput>,
) -> ApiResult<StatusCode> {
    let target = auth::user_by_id(&state.db, id).await?.ok_or(AppError::NotFound)?;
    if id == me.id && !i.is_admin {
        return Err(bad("impossible de te retirer tes propres droits admin"));
    }
    if target.external && (i.password.is_some() || i.is_admin != target.is_admin) {
        return Err(bad("compte géré par le proxy : droits et mot de passe viennent du proxy"));
    }
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE users SET is_admin = ? WHERE id = ?")
        .bind(i.is_admin)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    if let Some(pw) = i.password.as_deref() {
        auth::validate_password(pw)?;
        sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(auth::hash_password(pw)?)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM sessions WHERE user_id = ?").bind(id).execute(&mut *tx).await?;
    }
    if i.reset_2fa {
        sqlx::query("UPDATE users SET totp_secret = NULL, totp_pending = NULL, totp_last = 0 WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM passkeys WHERE user_id = ?").bind(id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete(
    State(state): State<AppState>,
    AdminUser(me): AdminUser,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    if id == me.id {
        return Err(bad("impossible de supprimer ton propre compte"));
    }
    let r = sqlx::query("DELETE FROM users WHERE id = ?").bind(id).execute(&state.db).await?;
    if r.rows_affected() == 0 { Err(AppError::NotFound) } else { Ok(StatusCode::NO_CONTENT) }
}
