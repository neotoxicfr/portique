-- Identifiants de passkeys jamais réattribués. Sans AUTOINCREMENT, SQLite peut redonner l'identifiant de la
-- dernière ligne supprimée : une connexion par une passkey retirée pendant la cérémonie passerait alors la
-- vérification « cette passkey existe toujours » sur la clé suivante du même compte.
CREATE TABLE passkeys_new (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    -- Passkey sérialisée par webauthn-rs (clé publique + compteur), pas un secret.
    credential  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
INSERT INTO passkeys_new (id, user_id, name, credential, created_at)
    SELECT id, user_id, name, credential, created_at FROM passkeys;
DROP TABLE passkeys;
ALTER TABLE passkeys_new RENAME TO passkeys;
