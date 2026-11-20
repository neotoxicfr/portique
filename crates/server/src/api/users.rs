//! Gestion des comptes par l'admin.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use portique_proto::{AuthMode, UserAdmin, UserInput};

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
            .bind(auth::hash_password(pw).await?)
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
    let hash = match i.password.as_deref() {
        Some(pw) => {
            auth::validate_password(pw)?;
            Some(auth::hash_password(pw).await?)
        }
        None => None,
    };
    let mut tx = state.db.begin().await?;
    // L'auteur doit être encore admin au moment de l'écriture : deux admins qui se rétrogradent l'un
    // l'autre en même temps ne laissent pas la base sans admin (le second trouve l'auteur rétrogradé).
    let r = sqlx::query(
        "UPDATE users SET is_admin = ? WHERE id = ? AND EXISTS (SELECT 1 FROM users WHERE id = ? AND is_admin)",
    )
    .bind(i.is_admin)
    .bind(id)
    .bind(me.id)
    .execute(&mut *tx)
    .await?;
    if r.rows_affected() == 0 {
        drop(tx);
        let still_admin = auth::user_by_id(&state.db, me.id).await?.is_some_and(|u| u.is_admin);
        return Err(if still_admin { AppError::NotFound } else { AppError::Forbidden });
    }
    if let Some(hash) = hash {
        sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(hash)
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
        // Facteur perdu ou volé : les sessions ouvertes avec lui ne doivent plus ouvrir le SSH.
        sqlx::query("DELETE FROM sessions WHERE user_id = ?").bind(id).execute(&mut *tx).await?;
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
    // Même garde que pour la rétrogradation : l'auteur doit être encore admin au moment de l'écriture.
    let r = sqlx::query(
        "DELETE FROM users WHERE id = ? AND EXISTS (SELECT 1 FROM users WHERE id = ? AND is_admin)",
    )
    .bind(id)
    .bind(me.id)
    .execute(&state.db)
    .await?;
    if r.rows_affected() > 0 {
        return Ok(StatusCode::NO_CONTENT);
    }
    let still_admin = auth::user_by_id(&state.db, me.id).await?.is_some_and(|u| u.is_admin);
    Err(if still_admin { AppError::NotFound } else { AppError::Forbidden })
}

#[cfg(test)]
mod tests {
    use axum::{
        Json,
        extract::{Path, State},
    };
    use portique_proto::UserInput;

    use crate::{
        auth::{AdminUser, user_by_name},
        state::AppError,
    };

    /// Deux admins se rétrogradent l'un l'autre en même temps : les deux requêtes ont passé `AdminUser`,
    /// la seconde à écrire trouve son auteur déjà rétrogradé et ne laisse pas la base sans admin.
    #[tokio::test]
    async fn an_admin_demoted_meanwhile_cannot_demote_or_delete() {
        let s = crate::api::ssh::tests::state("builtin").await;
        sqlx::query("INSERT INTO users (username, is_admin, webauthn_id) VALUES ('bob', 1, 'b')")
            .execute(&s.db)
            .await
            .unwrap();
        let admin = user_by_name(&s.db, "admin").await.unwrap().unwrap();
        let bob = user_by_name(&s.db, "bob").await.unwrap().unwrap();
        // bob est passé le premier : admin n'est plus admin, mais sa requête a déjà son `AdminUser`.
        sqlx::query("UPDATE users SET is_admin = 0 WHERE id = ?")
            .bind(admin.id)
            .execute(&s.db)
            .await
            .unwrap();
        let input = UserInput { username: "bob".into(), password: None, is_admin: false, reset_2fa: false };
        let r = super::update(State(s.clone()), AdminUser(admin.clone()), Path(bob.id), Json(input)).await;
        assert!(matches!(r, Err(AppError::Forbidden)), "rétrogradation");
        let r = super::delete(State(s.clone()), AdminUser(admin.clone()), Path(bob.id)).await;
        assert!(matches!(r, Err(AppError::Forbidden)), "suppression");
        assert!(user_by_name(&s.db, "bob").await.unwrap().unwrap().is_admin);
    }
}
