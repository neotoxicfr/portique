//! Types de l'API JSON partagés entre `yawrdp-server` et `yawrdp-web`.
//!
//! Les secrets (mots de passe Windows, graine TOTP) ne sortent jamais du serveur :
//! aucun type de lecture ne les contient, seuls les types d'écriture les acceptent.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Mode d'authentification du serveur.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// Comptes locaux : mot de passe, TOTP, passkeys.
    Builtin,
    /// Un proxy d'authentification (Authelia...) fournit `Remote-User` ; le login intégré est désactivé.
    Proxy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub auth_mode: AuthMode,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub totp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LoginResponse {
    Ok { me: Me },
    TotpRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyLoginStart {
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyChallenge<T> {
    pub ceremony: Uuid,
    pub options: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyFinish<T> {
    pub ceremony: Uuid,
    pub credential: T,
    /// Nom donné à la passkey lors de l'enregistrement (ignoré à la connexion).
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Me {
    pub id: i64,
    pub username: String,
    pub is_admin: bool,
    pub totp_enabled: bool,
    /// Vrai si le compte vient du proxy : pas de mot de passe ni de 2FA locale à gérer.
    pub external: bool,
}

/// Preuve d'identité exigée pour toute opération sensible sur le compte : une session
/// volée ne suffit pas à changer le mot de passe ni à toucher à la 2FA.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReAuth {
    pub password: String,
    /// Obligatoire si le TOTP est actif.
    #[serde(default)]
    pub totp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePassword {
    pub auth: ReAuth,
    pub new: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpSetup {
    pub secret_base32: String,
    pub otpauth_url: String,
    /// QR code en SVG prêt à insérer.
    pub qr_svg: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfirm {
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PasskeyInfo {
    pub id: i64,
    pub name: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Rdp,
    Ssh,
}

impl Protocol {
    pub fn default_port(self) -> u16 {
        match self {
            Protocol::Rdp => 3389,
            Protocol::Ssh => 22,
        }
    }
}

/// Connexion vue par un utilisateur : rien de secret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectionSummary {
    pub id: i64,
    pub name: String,
    pub protocol: Protocol,
    pub can_wake: bool,
}

/// Connexion vue par l'admin : tout sauf le mot de passe.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectionAdmin {
    pub id: i64,
    pub name: String,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub domain: String,
    pub has_password: bool,
    pub wol_mac: Option<String>,
    pub wol_target: Option<String>,
    pub allowed_users: Vec<i64>,
    /// Empreinte SHA-256 (hexa) du certificat épinglé, si déjà vu.
    pub cert_fingerprint: Option<String>,
    /// Réveil « par commande » (SSH) ; `None` = paquet UDP direct.
    pub wol_command: Option<WolCommandAdmin>,
}

/// Réveil par commande : SSH vers `host` puis `command`, où `{mac}` est remplacé par l'adresse
/// MAC (ex. routeur MikroTik : `/tool wol interface=ether1 mac={mac}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WolCommandAdmin {
    pub host: String,
    pub user: String,
    pub command: String,
    pub has_password: bool,
    /// Empreinte de la clé d'hôte SSH épinglée.
    pub hostkey: Option<String>,
}

/// `password: None` garde l'ancien.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WolCommandInput {
    pub host: String,
    pub user: String,
    pub command: String,
    #[serde(default)]
    pub password: Option<String>,
}

/// Création ou modification d'une connexion. `password: None` garde l'ancien,
/// `Some("")` l'efface.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionInput {
    pub name: String,
    pub protocol: Option<Protocol>,
    pub host: String,
    pub port: Option<u16>,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub wol_mac: Option<String>,
    /// Adresse `ip[:port]` où envoyer le paquet magique (broadcast ou dirigée).
    #[serde(default)]
    pub wol_target: Option<String>,
    #[serde(default)]
    pub allowed_users: Vec<i64>,
    /// Oublie le certificat épinglé (PC réinstallé, certificat renouvelé).
    #[serde(default)]
    pub forget_certificate: bool,
    /// Réveil par commande SSH ; `None` = paquet UDP direct.
    #[serde(default)]
    pub wol_command: Option<WolCommandInput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserAdmin {
    pub id: i64,
    pub username: String,
    pub is_admin: bool,
    pub totp_enabled: bool,
    pub passkeys: u32,
    pub external: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInput {
    pub username: String,
    /// Obligatoire à la création, `None` pour ne pas le changer.
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub is_admin: bool,
    /// Supprime le TOTP et les passkeys (compte perdu).
    #[serde(default)]
    pub reset_2fa: bool,
}

/// Messages texte du WebSocket de session (`/api/connections/{id}/session`) ; les messages
/// binaires portent les octets RDP bruts dans les deux sens.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionMessage {
    /// Premier contact : l'empreinte du certificat du PC doit être approuvée par un admin
    /// (à comparer avec celle qu'affiche le script de préparation sur le PC).
    UntrustedCertificate {
        fingerprint: String,
        can_approve: bool,
    },
    /// Le serveur a fait TLS + NLA : le navigateur reprend à MCS Connect Initial.
    Ready {
        selected_protocol: u32,
        negotiation_flags: u8,
        username: String,
        domain: String,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}
