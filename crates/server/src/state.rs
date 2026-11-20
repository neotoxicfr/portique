use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use portique_proto::ApiError;
use sqlx::SqlitePool;
use uuid::Uuid;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration, Webauthn};

use crate::{config::Config, crypto::Vault, ratelimit::LoginLimiter};

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub cfg: Arc<Config>,
    pub vault: Vault,
    pub webauthn: Arc<Webauthn>,
    pub limiter: Arc<LoginLimiter>,
    pub ceremonies: Arc<Ceremonies>,
}

pub enum Ceremony {
    Register { user_id: i64, state: PasskeyRegistration },
    Login { user_id: i64, state: PasskeyAuthentication },
}

/// Cérémonies WebAuthn en cours (défi en attente de réponse), 5 minutes maximum.
#[derive(Default)]
pub struct Ceremonies {
    pending: Mutex<HashMap<Uuid, (Instant, Ceremony)>>,
}

const CEREMONY_TTL: Duration = Duration::from_secs(300);

impl Ceremonies {
    pub fn insert(&self, c: Ceremony) -> Uuid {
        let id = Uuid::new_v4();
        let mut map = self.pending.lock().unwrap();
        map.retain(|_, (t, _)| t.elapsed() < CEREMONY_TTL);
        map.insert(id, (Instant::now(), c));
        id
    }

    /// Retire la cérémonie : un défi ne sert qu'une fois, même en cas d'échec.
    pub fn take(&self, id: Uuid) -> Option<Ceremony> {
        let (t, c) = self.pending.lock().unwrap().remove(&id)?;
        (t.elapsed() < CEREMONY_TTL).then_some(c)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("non authentifié")]
    Unauthorized,
    #[error("accès refusé")]
    Forbidden,
    #[error("introuvable")]
    NotFound,
    #[error("trop de tentatives, réessaie plus tard")]
    TooManyAttempts,
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Conflict(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::Internal(e.into())
    }
}

/// Message à montrer à l'utilisateur pour un refus transmis autrement qu'en HTTP (WebSocket) ; une
/// erreur interne est journalisée et reste générique.
pub fn user_message(e: AppError) -> String {
    match e {
        AppError::NotFound => "connexion introuvable, ou plus autorisée pour ce compte".into(),
        AppError::Forbidden => "action réservée aux admins".into(),
        AppError::Internal(e) => {
            tracing::error!("{e:#}");
            "erreur interne du serveur (détail dans son journal)".into()
        }
        other => other.to_string(),
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Forbidden => StatusCode::FORBIDDEN,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::TooManyAttempts => StatusCode::TOO_MANY_REQUESTS,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::Internal(e) => {
                tracing::error!("{e:#}");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        let error = match &self {
            AppError::Internal(_) => "erreur interne".to_owned(),
            other => other.to_string(),
        };
        (status, Json(ApiError { error })).into_response()
    }
}

pub type ApiResult<T> = Result<T, AppError>;

pub fn bad(msg: impl Into<String>) -> AppError {
    AppError::BadRequest(msg.into())
}
