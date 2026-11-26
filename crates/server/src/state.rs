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

use crate::{
    config::Config,
    crypto::Vault,
    ratelimit::{LoginLimiter, Ticket},
};

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub cfg: Arc<Config>,
    pub vault: Vault,
    pub webauthn: Arc<Webauthn>,
    pub limiter: Arc<LoginLimiter>,
    pub ceremonies: Arc<Ceremonies>,
    pub live: Arc<LiveSessions>,
}

/// Sessions ouvertes par machine (bureau, terminal), en mémoire : ce que lit un tableau de bord.
#[derive(Default)]
pub struct LiveSessions(Mutex<HashMap<i64, [u32; 2]>>);

#[derive(Clone, Copy)]
pub enum Live {
    Rdp = 0,
    Ssh = 1,
}

/// Compte une session tant qu'il vit.
pub struct LiveGuard {
    set: Arc<LiveSessions>,
    id: i64,
    kind: Live,
}

impl LiveSessions {
    pub fn enter(self: &Arc<Self>, id: i64, kind: Live) -> LiveGuard {
        self.0.lock().unwrap().entry(id).or_default()[kind as usize] += 1;
        LiveGuard { set: self.clone(), id, kind }
    }

    /// Bureaux et terminaux ouverts sur la machine `id`.
    pub fn count(&self, id: i64) -> [u32; 2] {
        self.0.lock().unwrap().get(&id).copied().unwrap_or_default()
    }
}

impl Drop for LiveGuard {
    fn drop(&mut self) {
        let mut map = self.set.0.lock().unwrap();
        if let Some(n) = map.get_mut(&self.id) {
            n[self.kind as usize] = n[self.kind as usize].saturating_sub(1);
            if *n == [0, 0] {
                map.remove(&self.id);
            }
        }
    }
}

pub enum Ceremony {
    Register {
        user_id: i64,
        state: PasskeyRegistration,
    },
    /// `passkeys` : lignes des passkeys proposées au défi, seules à pouvoir ouvrir la session.
    Login {
        user_id: i64,
        state: PasskeyAuthentication,
        ticket: Ticket,
        passkeys: Vec<i64>,
    },
}

/// Cérémonies WebAuthn en cours (défi en attente de réponse), 5 minutes maximum.
#[derive(Default)]
pub struct Ceremonies {
    pending: Mutex<HashMap<Uuid, (Instant, Ceremony)>>,
}

const CEREMONY_TTL: Duration = Duration::from_secs(300);
/// Plafonds des défis en attente : une rafale de démarrages ne fait pas grossir la mémoire sans fin. Un
/// plafond par sorte : les connexions (sans compte) n'évincent jamais une inscription (authentifiée).
const MAX_LOGINS: usize = 1000;
const MAX_REGISTRATIONS: usize = 100;

impl Ceremonies {
    pub fn insert(&self, c: Ceremony) -> Uuid {
        let id = Uuid::new_v4();
        let mut map = self.pending.lock().unwrap();
        map.retain(|_, (t, _)| t.elapsed() < CEREMONY_TTL);
        // Plein : on évince le plus ancien de la même sorte plutôt que de refuser. Refuser laisserait une
        // rafale de démarrages (sans compte) bloquer les passkeys de tout le monde pendant cinq minutes.
        let login = |c: &Ceremony| matches!(c, Ceremony::Login { .. });
        let kind = login(&c);
        let max = if kind { MAX_LOGINS } else { MAX_REGISTRATIONS };
        let same = || map.iter().filter(|(_, (_, o))| login(o) == kind);
        if same().count() >= max
            && let Some(oldest) = same().min_by_key(|(_, (t, _))| *t).map(|(k, _)| *k)
        {
            map.remove(&oldest);
        }
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

#[cfg(test)]
mod tests {
    use webauthn_rs::prelude::Passkey;

    use super::*;

    /// Une session compte tant que sa garde vit ; la machine disparaît du compte à la dernière.
    #[test]
    fn live_sessions_follow_their_guards() {
        let live = Arc::new(LiveSessions::default());
        let a = live.enter(7, Live::Rdp);
        let b = live.enter(7, Live::Ssh);
        let c = live.enter(7, Live::Ssh);
        assert_eq!((live.count(7), live.count(8)), ([1, 2], [0, 0]));
        drop((a, b));
        assert_eq!(live.count(7), [0, 1]);
        drop(c);
        assert!(live.0.lock().unwrap().is_empty());
    }

    /// Passkey ES256 factice (clé publique de l'exemple de webauthn-rs-core).
    const PASSKEY: &str = r#"{"cred":{"cred_id":"uZcVDBVS68E_MtAgeQpElJxldF_6cY9sSvbWqx_qRh8wiu42lyRBRmh5yFeD_r9k130dMbFHBHI9RTFgdJQIzQ","cred":{"type_":"ES256","key":{"EC_EC2":{"curve":"SECP256R1","x":[194,126,127,109,252,23,131,21,252,6,223,99,44,254,140,27,230,17,94,5,133,28,104,41,144,69,171,149,161,26,200,243],"y":[143,123,183,156,24,178,21,248,117,159,162,69,171,52,188,252,26,59,6,47,103,92,19,58,117,103,249,0,219,8,95,196]}}},"counter":2,"user_verified":false,"backup_eligible":false,"backup_state":false,"registration_policy":"preferred","extensions":{"cred_protect":"NotRequested","hmac_create_secret":"NotRequested"},"attestation":{"data":"None","metadata":"None"},"attestation_format":"None"}}"#;

    /// Une rafale de démarrages de connexion n'évince pas une inscription en cours ; chaque sorte évince
    /// d'abord son plus ancien défi.
    #[tokio::test]
    async fn logins_never_evict_registrations() {
        let s = crate::api::ssh::tests::state("builtin").await;
        let keys = [serde_json::from_str::<Passkey>(PASSKEY).unwrap()];
        let register = || {
            let (_, state) =
                s.webauthn.start_passkey_registration(Uuid::new_v4(), "alice", "alice", None).unwrap();
            Ceremony::Register { user_id: 1, state }
        };
        let login = || {
            let (_, state) = s.webauthn.start_passkey_authentication(&keys).unwrap();
            let ticket = Arc::new(LoginLimiter::default()).reserve("192.0.2.1".parse().unwrap(), "").unwrap();
            Ceremony::Login { user_id: 1, state, ticket, passkeys: vec![] }
        };
        let c = Ceremonies::default();
        let reg = c.insert(register());
        let first_login = c.insert(login());
        for _ in 1..MAX_LOGINS + 10 {
            c.insert(login());
        }
        assert_eq!(c.pending.lock().unwrap().len(), MAX_LOGINS + 1);
        assert!(c.take(first_login).is_none(), "plus ancienne connexion évincée");
        assert!(matches!(c.take(reg), Some(Ceremony::Register { .. })), "inscription évincée");
    }
}
