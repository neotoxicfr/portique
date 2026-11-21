-- no-transaction
-- Identifiants de comptes et d'hôtes jamais réattribués, comme ceux des passkeys (0007). Sans AUTOINCREMENT,
-- SQLite redonne l'identifiant de la dernière ligne supprimée : une action lancée depuis une liste restée
-- ouverte (remise à zéro de la 2FA, suppression, modification, ouverture de session) viserait le compte ou
-- l'hôte créé ensuite.
-- Tables parentes : sans couper les clés étrangères, le DROP supprimerait en cascade sessions, passkeys et
-- droits d'accès. PRAGMA foreign_keys est sans effet dans une transaction, d'où « no-transaction » et une
-- transaction explicite. Rejouée après une coupure avant son enregistrement, elle recopie les lignes telles quelles.
PRAGMA foreign_keys = OFF;
BEGIN;

CREATE TABLE users_new (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    -- NULL pour les comptes créés par le proxy (pas de login local).
    password_hash TEXT,
    -- Graine TOTP chiffrée (clé maîtresse) ; NULL = pas de TOTP.
    totp_secret   BLOB,
    -- Graine en attente de confirmation par un premier code.
    totp_pending  BLOB,
    -- Dernier pas TOTP accepté : un même code ne sert qu'une fois.
    totp_last     INTEGER NOT NULL DEFAULT 0,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    external      INTEGER NOT NULL DEFAULT 0,
    webauthn_id   TEXT NOT NULL UNIQUE,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    -- Préférences de terminal : thème par défaut, combinaisons de la barre de touches (JSON).
    terminal_theme TEXT,
    key_combos    TEXT
);
INSERT INTO users_new (id, username, password_hash, totp_secret, totp_pending, totp_last, is_admin, external,
                       webauthn_id, created_at, terminal_theme, key_combos)
    SELECT id, username, password_hash, totp_secret, totp_pending, totp_last, is_admin, external,
           webauthn_id, created_at, terminal_theme, key_combos FROM users;
DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

CREATE TABLE connections_new (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    host        TEXT NOT NULL,
    port        INTEGER NOT NULL,
    username    TEXT NOT NULL DEFAULT '',
    domain      TEXT NOT NULL DEFAULT '',
    -- Mot de passe chiffré (XChaCha20-Poly1305, clé maîtresse).
    password    BLOB,
    wol_mac     TEXT,
    wol_target  TEXT,
    -- Empreinte SHA-256 du certificat TLS du PC, épinglée à la première connexion réussie.
    cert_sha256 BLOB,
    -- Réveil par commande SSH (0003) ; clé d'hôte approuvée et clé en attente d'approbation.
    wol_ssh_host TEXT,
    wol_ssh_user TEXT,
    wol_ssh_password BLOB,
    wol_ssh_command TEXT,
    wol_ssh_hostkey TEXT,
    wol_ssh_hostkey_pending TEXT,
    rdp_enabled INTEGER NOT NULL DEFAULT 1,
    ssh_enabled INTEGER NOT NULL DEFAULT 0,
    ssh_port    INTEGER NOT NULL DEFAULT 22,
    ssh_user    TEXT NOT NULL DEFAULT '',
    -- Mot de passe SSH facultatif, chiffré comme celui du RDP.
    ssh_password BLOB,
    -- Empreinte SHA-256 (format OpenSSH) de la clé d'hôte approuvée par un admin.
    ssh_hostkey TEXT,
    -- Rebond : autre hôte SSH par lequel passer (ProxyJump), chaînable.
    ssh_jump_id INTEGER REFERENCES connections(id) ON DELETE SET NULL,
    -- Thème du terminal propre à cet hôte ; NULL = thème du compte.
    ssh_theme   TEXT,
    -- Réveil par commande passant par un hôte SSH déclaré.
    wol_via_id  INTEGER REFERENCES connections(id) ON DELETE SET NULL
);
INSERT INTO connections_new (id, name, host, port, username, domain, password, wol_mac, wol_target, cert_sha256,
                             wol_ssh_host, wol_ssh_user, wol_ssh_password, wol_ssh_command, wol_ssh_hostkey,
                             wol_ssh_hostkey_pending, rdp_enabled, ssh_enabled, ssh_port, ssh_user, ssh_password,
                             ssh_hostkey, ssh_jump_id, ssh_theme, wol_via_id)
    SELECT id, name, host, port, username, domain, password, wol_mac, wol_target, cert_sha256,
           wol_ssh_host, wol_ssh_user, wol_ssh_password, wol_ssh_command, wol_ssh_hostkey,
           wol_ssh_hostkey_pending, rdp_enabled, ssh_enabled, ssh_port, ssh_user, ssh_password,
           ssh_hostkey, ssh_jump_id, ssh_theme, wol_via_id FROM connections;
DROP TABLE connections;
ALTER TABLE connections_new RENAME TO connections;

COMMIT;
PRAGMA foreign_keys = ON;
