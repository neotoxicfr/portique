//! Appels à l'API du serveur. Toute requête porte l'en-tête anti-CSRF attendu par le serveur.

use gloo_net::http::{Request, RequestBuilder, Response};
use serde::{Serialize, de::DeserializeOwned};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use webauthn_rs_proto::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse,
};
use yawrdp_proto::{ApiError, CeremonyChallenge, CeremonyFinish};

const CSRF: (&str, &str) = ("x-yawrdp", "1");

#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    Unauthorized,
    Message(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unauthorized => f.write_str("session expirée, reconnecte-toi"),
            Error::Message(m) => f.write_str(m),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

fn net(e: impl std::fmt::Display) -> Error {
    Error::Message(format!("réseau : {e}"))
}

async fn check(res: Response) -> Result<Response> {
    if res.ok() {
        return Ok(res);
    }
    if res.status() == 401 {
        return Err(Error::Unauthorized);
    }
    let msg = res
        .json::<ApiError>()
        .await
        .map(|e| e.error)
        .unwrap_or_else(|_| format!("erreur HTTP {}", res.status()));
    Err(Error::Message(msg))
}

fn builder(method: &str, url: &str) -> RequestBuilder {
    let b = match method {
        "POST" => Request::post(url),
        "PUT" => Request::put(url),
        "DELETE" => Request::delete(url),
        _ => Request::get(url),
    };
    b.header(CSRF.0, CSRF.1)
}

pub async fn get<T: DeserializeOwned>(url: &str) -> Result<T> {
    let res = builder("GET", url).send().await.map_err(net)?;
    check(res).await?.json().await.map_err(net)
}

/// Requête avec corps JSON, réponse JSON.
pub async fn send<B: Serialize, T: DeserializeOwned>(method: &str, url: &str, body: &B) -> Result<T> {
    let res = builder(method, url).json(body).map_err(net)?.send().await.map_err(net)?;
    check(res).await?.json().await.map_err(net)
}

/// Requête dont la réponse n'a pas de corps utile.
pub async fn send_empty<B: Serialize>(method: &str, url: &str, body: Option<&B>) -> Result<()> {
    let b = builder(method, url);
    let res = match body {
        Some(body) => b.json(body).map_err(net)?.send().await,
        None => b.send().await,
    }
    .map_err(net)?;
    check(res).await.map(|_| ())
}

fn credentials() -> Result<web_sys::CredentialsContainer> {
    let w = web_sys::window().ok_or_else(|| Error::Message("pas de fenêtre".into()))?;
    Ok(w.navigator().credentials())
}

fn js_err(e: wasm_bindgen::JsValue) -> Error {
    let msg = e
        .dyn_ref::<js_sys::Error>()
        .map(|e| String::from(e.message()))
        .unwrap_or_else(|| "opération annulée".into());
    Error::Message(format!("passkey : {msg}"))
}

/// Connexion par passkey : défi du serveur, signature par l'authentificateur, vérification.
pub async fn passkey_login(username: &str) -> Result<yawrdp_proto::LoginResponse> {
    let start: CeremonyChallenge<RequestChallengeResponse> = send(
        "POST",
        "/api/auth/passkey/start",
        &yawrdp_proto::PasskeyLoginStart { username: username.into() },
    )
    .await?;
    let opts: web_sys::CredentialRequestOptions = start.options.into();
    let promise = credentials()?.get_with_options(&opts).map_err(js_err)?;
    let cred: web_sys::PublicKeyCredential = JsFuture::from(promise).await.map_err(js_err)?.unchecked_into();
    let finish =
        CeremonyFinish { ceremony: start.ceremony, credential: PublicKeyCredential::from(cred), name: None };
    send("POST", "/api/auth/passkey/finish", &finish).await
}

pub async fn passkey_register(name: String, proof: yawrdp_proto::ReAuth) -> Result<()> {
    let start: CeremonyChallenge<CreationChallengeResponse> =
        send("POST", "/api/account/passkeys/register/start", &proof).await?;
    let opts: web_sys::CredentialCreationOptions = start.options.into();
    let promise = credentials()?.create_with_options(&opts).map_err(js_err)?;
    let cred: web_sys::PublicKeyCredential = JsFuture::from(promise).await.map_err(js_err)?.unchecked_into();
    let finish = CeremonyFinish {
        ceremony: start.ceremony,
        credential: RegisterPublicKeyCredential::from(cred),
        name: Some(name),
    };
    send_empty("POST", "/api/account/passkeys/register/finish", Some(&finish)).await
}
