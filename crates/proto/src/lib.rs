//! Types de l'API JSON partagés entre `portique-server` et `portique-web`.
//!
//! Les secrets (mots de passe Windows, graine TOTP) ne sortent jamais du serveur :
//! aucun type de lecture ne les contient, seuls les types d'écriture les acceptent.
//! Seule exception : `TotpSetup`, réponse d'enrôlement qui montre la graine une fois.

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

/// Réponse d'enrôlement TOTP : contient la graine (en clair, dans l'URL et dans le QR code), à traiter
/// comme un secret.
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

pub const RDP_PORT: u16 = 3389;
pub const SSH_PORT: u16 = 22;

/// Hôte vu par un utilisateur : rien de secret. Un hôte offre le RDP, le SSH ou les deux.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectionSummary {
    pub id: i64,
    pub name: String,
    pub rdp: bool,
    pub ssh: bool,
    pub can_wake: bool,
    /// Hôte marqué sensible (thème de terminal « alerte ») : l'accueil le signale en rouge.
    #[serde(default)]
    pub alert: bool,
}

/// Hôte vu par l'admin : tout sauf les mots de passe. `port`, `username`, `domain` et
/// `has_password` sont ceux du RDP.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectionAdmin {
    pub id: i64,
    pub name: String,
    pub host: String,
    pub rdp: bool,
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
    /// SSH sur cet hôte ; `None` = pas de SSH.
    pub ssh: Option<SshAdmin>,
}

/// SSH d'un hôte. Le service s'authentifie avec sa clé, puis avec `password` s'il y en a un.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SshAdmin {
    pub port: u16,
    pub user: String,
    pub has_password: bool,
    /// Empreinte SHA-256 de la clé d'hôte approuvée (format OpenSSH).
    pub hostkey: Option<String>,
    /// Rebond (ProxyJump) : hôte connu ou hôte saisi ; `None` = connexion directe.
    pub jump: Option<HopAdmin>,
    /// Thème propre à cet hôte ; `None` = thème du compte.
    pub theme: Option<String>,
}

/// `password: None` garde l'ancien, `Some("")` l'efface.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SshInput {
    #[serde(default)]
    pub port: Option<u16>,
    pub user: String,
    #[serde(default)]
    pub password: Option<String>,
    /// Rebond ; `None` = connexion directe.
    #[serde(default)]
    pub jump: Option<HopInput>,
    #[serde(default)]
    pub theme: Option<String>,
    /// Oublie la clé d'hôte approuvée (machine réinstallée).
    #[serde(default)]
    pub forget_hostkey: bool,
}

/// Rebond SSH (WoL ou terminal) : un hôte connu de la liste, ou un hôte saisi pour cette machine seule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HopAdmin {
    Known {
        id: i64,
    },
    Host {
        host: String,
        port: u16,
        user: String,
        has_password: bool,
        /// Hôte connu par lequel passe cet hôte saisi.
        via_id: Option<i64>,
        /// Empreinte SHA-256 de la clé d'hôte approuvée (format OpenSSH).
        hostkey: Option<String>,
        /// Clé présentée lors d'un essai, en attente d'approbation (aucun mot de passe n'est envoyé avant).
        pending_hostkey: Option<String>,
    },
}

/// Rebond à enregistrer. Pour un hôte saisi, `password: None` garde l'ancien, `Some("")` l'efface.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HopInput {
    Known {
        id: i64,
    },
    Host {
        host: String,
        #[serde(default)]
        port: Option<u16>,
        user: String,
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        via_id: Option<i64>,
        /// Approuve la clé en attente (doit être identique à `pending_hostkey`).
        #[serde(default)]
        approve_hostkey: Option<String>,
        /// Oublie la clé approuvée (hôte réinstallé) : la prochaine connexion la présentera à approuver.
        #[serde(default)]
        forget_hostkey: bool,
    },
}

/// Réveil par commande : SSH vers `host` puis `command`, où `{mac}` est remplacé par l'adresse
/// MAC (par exemple `wakeonlan {mac}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WolCommandAdmin {
    /// Hôte SSH par lequel passe la commande.
    pub via: HopAdmin,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolCommandInput {
    /// Hôte SSH par lequel passer la commande.
    pub via: HopInput,
    pub command: String,
}

/// Création ou modification d'une connexion. `password: None` garde l'ancien,
/// `Some("")` l'efface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInput {
    pub name: String,
    pub host: String,
    /// RDP sur cet hôte (`port`, `username`, `domain`, `password` le concernent).
    #[serde(default = "yes")]
    pub rdp: bool,
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
    /// SSH sur cet hôte ; `None` = pas de SSH.
    #[serde(default)]
    pub ssh: Option<SshInput>,
}

fn yes() -> bool {
    true
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
}

/// Messages texte du WebSocket de session (`/api/connections/{id}/session`) ; les messages
/// binaires portent les octets RDP bruts dans les deux sens.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionMessage {
    /// Premier contact : l'empreinte du certificat du PC doit être approuvée par un admin
    /// (à comparer avec celle qu'affiche le script de préparation sur le PC).
    UntrustedCertificate { fingerprint: String, can_approve: bool },
    /// Le serveur a fait TLS + NLA : le navigateur reprend à MCS Connect Initial.
    Ready { selected_protocol: u32, negotiation_flags: u8, username: String, domain: String },
    Error {
        message: String,
        /// Refus durable (accès, configuration, identifiants, certificat changé) : ne pas reconnecter.
        /// Faux pour un échec passager (PC qui redémarre, réseau) : la reconnexion automatique reprend.
        #[serde(default)]
        lasting: bool,
    },
}

/// Thèmes du terminal proposés (couleurs définies par le front). Le premier est le défaut.
pub const TERMINAL_THEMES: &[&str] = &["sombre", "clair", "solarise", "dracula", "nord", "alerte"];

/// Combinaisons de la barre de touches tant que le compte n'en a pas choisi.
pub const DEFAULT_COMBOS: &[&str] = &["Ctrl+C", "Ctrl+D", "Ctrl+Z", "Ctrl+R", "Ctrl+L"];

/// Préférences de terminal d'un compte.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TerminalPrefs {
    pub theme: String,
    pub combos: Vec<String>,
}

/// Combinaison de la barre de touches : `Ctrl+X`, `Alt+X` ou `Ctrl+Alt+X`, X un caractère ASCII visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Combo {
    pub ctrl: bool,
    pub alt: bool,
    pub key: char,
}

impl Combo {
    pub fn parse(s: &str) -> Option<Self> {
        let mut c = Combo { ctrl: false, alt: false, key: ' ' };
        // La touche peut être « + » elle-même : « Alt++ ».
        let (mods, key) = match s.strip_suffix("++") {
            Some(m) => (m, "+"),
            None => s.rsplit_once('+')?,
        };
        for m in mods.split('+') {
            match m.trim().to_ascii_lowercase().as_str() {
                "ctrl" if !c.ctrl => c.ctrl = true,
                "alt" if !c.alt => c.alt = true,
                _ => return None,
            }
        }
        let mut chars = key.chars();
        c.key = chars.next().filter(|k| k.is_ascii_graphic())?;
        (chars.next().is_none() && (c.ctrl || c.alt)).then_some(c)
    }

    /// Octets envoyés au terminal (Ctrl : code de contrôle ; Alt : préfixe Échap).
    pub fn bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(2);
        if self.alt {
            b.push(0x1b);
        }
        b.push(if self.ctrl { ctrl_code(self.key) } else { self.key as u8 });
        b
    }
}

/// Code de contrôle d'une touche (Ctrl+A = 0x01…, Ctrl+[ = Échap, Ctrl+? = Suppr).
pub fn ctrl_code(key: char) -> u8 {
    match key.to_ascii_uppercase() {
        k @ '@'..='_' => k as u8 - b'@',
        ' ' => 0,
        '?' => 0x7f,
        k => k as u8,
    }
}

/// Clé SSH publique du service, à poser dans `authorized_keys` des hôtes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceKey {
    /// Ligne OpenSSH : `ssh-ed25519 AAAA… portique`.
    pub public: String,
}

/// Messages texte du WebSocket SSH (`/api/connections/{id}/ssh`) du serveur au navigateur ; les
/// messages binaires portent les octets du terminal dans les deux sens.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SshMessage {
    /// Clé d'hôte inconnue sur un saut (cible ou rebond) : à approuver par un admin.
    UntrustedHostKey {
        connection_id: i64,
        name: String,
        fingerprint: String,
        can_approve: bool,
    },
    /// Shell ouvert : thème et combinaisons à appliquer.
    Ready {
        /// Nom de l'hôte, pour la barre de titre.
        name: String,
        theme: String,
        combos: Vec<String>,
    },
    Error {
        message: String,
    },
}

/// Messages texte du navigateur au serveur sur le WebSocket SSH.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SshControl {
    Resize { cols: u16, rows: u16 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combos() {
        assert_eq!(Combo::parse("Ctrl+C").unwrap().bytes(), [0x03]);
        assert_eq!(Combo::parse("ctrl+r").unwrap().bytes(), [0x12]);
        assert_eq!(Combo::parse("Alt+b").unwrap().bytes(), [0x1b, b'b']);
        assert_eq!(Combo::parse("Ctrl+Alt+d").unwrap().bytes(), [0x1b, 0x04]);
        assert_eq!(Combo::parse("Ctrl+[").unwrap().bytes(), [0x1b]);
        assert_eq!(Combo::parse("Alt++").unwrap().bytes(), [0x1b, b'+']);
        assert_eq!(Combo::parse("Ctrl+Alt++").unwrap().bytes(), [0x1b, b'+']);
        for bad in ["C", "+", "++", "Ctrl+", "Alt+", "Alt+++", "Ctrl+CC", "Shift+C", "Ctrl+Ctrl+C", "Ctrl+é"]
        {
            assert!(Combo::parse(bad).is_none(), "{bad}");
        }
        assert!(DEFAULT_COMBOS.iter().all(|c| Combo::parse(c).is_some()));
    }
}
