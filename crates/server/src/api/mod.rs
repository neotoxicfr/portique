pub mod account;
pub mod auth;
pub mod connections;
pub mod session;
pub mod ssh;
pub mod users;

use axum::{
    Router,
    routing::{delete, get, post, put},
};

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/info", get(auth::info))
        .route("/me", get(auth::me))
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/passkey/start", post(auth::passkey_start))
        .route("/auth/passkey/finish", post(auth::passkey_finish))
        .route("/account/password", post(account::change_password))
        .route("/account/totp/setup", post(account::totp_setup))
        .route("/account/totp/confirm", post(account::totp_confirm))
        .route("/account/totp/disable", post(account::totp_disable))
        .route("/account/passkeys", get(account::passkeys))
        .route("/account/passkeys/{id}", delete(account::passkey_delete))
        .route("/account/passkeys/register/start", post(account::passkey_register_start))
        .route("/account/passkeys/register/finish", post(account::passkey_register_finish))
        .route("/account/terminal", get(account::terminal_get).put(account::terminal_set))
        .route("/connections", get(connections::list))
        .route("/connections/{id}/wake", post(connections::wake))
        .route("/connections/{id}/session", get(session::open))
        .route("/connections/{id}/ssh", get(ssh::open))
        .route("/admin/ssh-key", get(ssh::service_key))
        .route("/admin/connections", get(connections::admin_list).post(connections::create))
        .route("/admin/connections/{id}", put(connections::update).delete(connections::delete))
        .route("/admin/users", get(users::list).post(users::create))
        .route("/admin/users/{id}", put(users::update).delete(users::delete))
        .route("/admin/users/{id}/reset-2fa", post(users::reset_2fa))
}
