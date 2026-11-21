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
    AdminUser(me): AdminUser,
    Json(i): Json<UserInput>,
) -> ApiResult<StatusCode> {
    if state.cfg.auth_mode == AuthMode::Proxy {
        return Err(bad("en mode proxy, les comptes sont créés par le proxy"));
    }
    let name = i.username.trim();
    auth::validate_username(name)?;
    let pw = i.password.as_deref().ok_or_else(|| bad("mot de passe requis"))?;
    auth::validate_password(pw)?;
    // Même garde que `update` : l'auteur, rétrogradé pendant le hachage, ne crée plus de compte (admin compris).
    let r = sqlx::query(
        "INSERT INTO users (username, password_hash, is_admin, webauthn_id)
         SELECT ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM users WHERE id = ? AND is_admin)",
    )
    .bind(name)
    .bind(auth::hash_password(pw).await?)
    .bind(i.is_admin)
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(me.id)
    .execute(&state.db)
    .await;
    match r {
        Ok(r) if r.rows_affected() == 0 => Err(AppError::Forbidden),
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
        return Err(not_written(&state, me.id).await?);
    }
    if let Some(hash) = hash {
        sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(hash)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM sessions WHERE user_id = ?").bind(id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Supprime le TOTP et les passkeys d'un compte (facteur perdu ou volé). Opération à part de `update` :
/// elle ne réécrit pas le rôle, qu'un autre admin a pu changer depuis que la liste a été lue.
pub async fn reset_2fa(
    State(state): State<AppState>,
    AdminUser(me): AdminUser,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    let mut tx = state.db.begin().await?;
    let r = sqlx::query(
        "UPDATE users SET totp_secret = NULL, totp_pending = NULL, totp_last = 0
         WHERE id = ? AND EXISTS (SELECT 1 FROM users WHERE id = ? AND is_admin)",
    )
    .bind(id)
    .bind(me.id)
    .execute(&mut *tx)
    .await?;
    if r.rows_affected() == 0 {
        drop(tx);
        return Err(not_written(&state, me.id).await?);
    }
    sqlx::query("DELETE FROM passkeys WHERE user_id = ?").bind(id).execute(&mut *tx).await?;
    // Les sessions ouvertes avec le facteur perdu ne doivent plus ouvrir le SSH.
    sqlx::query("DELETE FROM sessions WHERE user_id = ?").bind(id).execute(&mut *tx).await?;
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
    Err(not_written(&state, me.id).await?)
}

/// Écriture gardée qui n'a touché aucune ligne : compte cible absent, ou auteur rétrogradé entre-temps.
async fn not_written(state: &AppState, me: i64) -> ApiResult<AppError> {
    let still_admin = auth::user_by_id(&state.db, me).await?.is_some_and(|u| u.is_admin);
    Ok(if still_admin { AppError::NotFound } else { AppError::Forbidden })
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
    /// la seconde à écrire trouve son auteur déjà rétrogradé et ne laisse pas la base sans admin. Un admin
    /// rétrogradé pendant le hachage ne crée pas non plus de compte.
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
        let input = UserInput { username: "bob".into(), password: None, is_admin: false };
        let r = super::update(State(s.clone()), AdminUser(admin.clone()), Path(bob.id), Json(input)).await;
        assert!(matches!(r, Err(AppError::Forbidden)), "rétrogradation");
        let r = super::delete(State(s.clone()), AdminUser(admin.clone()), Path(bob.id)).await;
        assert!(matches!(r, Err(AppError::Forbidden)), "suppression");
        sqlx::query("UPDATE users SET totp_secret = x'01' WHERE id = ?")
            .bind(bob.id)
            .execute(&s.db)
            .await
            .unwrap();
        let r = super::reset_2fa(State(s.clone()), AdminUser(admin.clone()), Path(bob.id)).await;
        assert!(matches!(r, Err(AppError::Forbidden)), "remise à zéro 2FA");
        let bob = user_by_name(&s.db, "bob").await.unwrap().unwrap();
        assert!(bob.is_admin && bob.totp_secret.is_some());
        let input = UserInput {
            username: "carol".into(),
            password: Some("mot-de-passe-long".into()),
            is_admin: true,
        };
        let r = super::create(State(s.clone()), AdminUser(admin.clone()), Json(input)).await;
        assert!(matches!(r, Err(AppError::Forbidden)), "création");
        assert!(user_by_name(&s.db, "carol").await.unwrap().is_none());
    }

    /// Un admin réinitialise la 2FA de bob pendant qu'un autre le rétrograde : la remise à zéro ne
    /// lui rend pas ses droits (elle ne touche qu'aux facteurs et aux sessions).
    #[tokio::test]
    async fn reset_2fa_keeps_role_and_password() {
        let s = crate::api::ssh::tests::state("builtin").await;
        sqlx::query(
            "INSERT INTO users (username, password_hash, is_admin, totp_secret, totp_pending, totp_last, webauthn_id)
             VALUES ('bob', 'hash', 0, x'01', x'02', 7, 'b')",
        )
        .execute(&s.db)
        .await
        .unwrap();
        let admin = user_by_name(&s.db, "admin").await.unwrap().unwrap();
        let bob = user_by_name(&s.db, "bob").await.unwrap().unwrap();
        sqlx::query("INSERT INTO passkeys (user_id, name, credential) VALUES (?, 'clé', '{}')")
            .bind(bob.id)
            .execute(&s.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO sessions (token_hash, user_id, expires_at, mfa) VALUES (x'aa', ?, 0, 1)")
            .bind(bob.id)
            .execute(&s.db)
            .await
            .unwrap();

        let r = super::reset_2fa(State(s.clone()), AdminUser(admin.clone()), Path(bob.id)).await;
        assert!(r.is_ok());
        let after = user_by_name(&s.db, "bob").await.unwrap().unwrap();
        assert!(!after.is_admin, "rôle inchangé");
        assert_eq!(after.password_hash.as_deref(), Some("hash"), "mot de passe inchangé");
        assert!(after.totp_secret.is_none());
        let (pending, last): (Option<Vec<u8>>, i64) =
            sqlx::query_as("SELECT totp_pending, totp_last FROM users WHERE id = ?")
                .bind(bob.id)
                .fetch_one(&s.db)
                .await
                .unwrap();
        assert!(pending.is_none() && last == 0);
        let left: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM passkeys WHERE user_id = ?1), (SELECT count(*) FROM sessions WHERE user_id = ?1)",
        )
        .bind(bob.id)
        .fetch_one(&s.db)
        .await
        .unwrap();
        assert_eq!(left, (0, 0), "passkeys et sessions supprimées");

        let r = super::reset_2fa(State(s.clone()), AdminUser(admin), Path(9999)).await;
        assert!(matches!(r, Err(AppError::NotFound)));
    }
}
