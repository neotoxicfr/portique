CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
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
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE passkeys (
    id          INTEGER PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    -- Passkey sérialisée par webauthn-rs (clé publique + compteur), pas un secret.
    credential  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE sessions (
    -- SHA-256 du jeton du cookie : une fuite de la base ne donne pas de session.
    token_hash  BLOB PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  INTEGER NOT NULL
);

CREATE TABLE connections (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    protocol    TEXT NOT NULL CHECK (protocol IN ('rdp', 'ssh')),
    host        TEXT NOT NULL,
    port        INTEGER NOT NULL,
    username    TEXT NOT NULL DEFAULT '',
    domain      TEXT NOT NULL DEFAULT '',
    -- Mot de passe chiffré (XChaCha20-Poly1305, clé maîtresse).
    password    BLOB,
    wol_mac     TEXT,
    wol_target  TEXT
);

CREATE TABLE connection_access (
    connection_id INTEGER NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (connection_id, user_id)
);
