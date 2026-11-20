-- Une connexion devient un hôte : RDP et/ou SSH (une seule tuile, le clic propose le choix si les deux).
ALTER TABLE connections ADD COLUMN rdp_enabled INTEGER NOT NULL DEFAULT 1;
ALTER TABLE connections ADD COLUMN ssh_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE connections ADD COLUMN ssh_port INTEGER NOT NULL DEFAULT 22;
ALTER TABLE connections ADD COLUMN ssh_user TEXT NOT NULL DEFAULT '';
-- Mot de passe SSH facultatif (la clé du service est essayée d'abord), chiffré comme celui du RDP.
ALTER TABLE connections ADD COLUMN ssh_password BLOB;
-- Empreinte SHA-256 (format OpenSSH) de la clé d'hôte approuvée par un admin.
ALTER TABLE connections ADD COLUMN ssh_hostkey TEXT;
-- Rebond : autre hôte SSH par lequel passer (ProxyJump), chaînable.
ALTER TABLE connections ADD COLUMN ssh_jump_id INTEGER REFERENCES connections(id) ON DELETE SET NULL;
-- Thème du terminal propre à cet hôte ; NULL = thème du compte.
ALTER TABLE connections ADD COLUMN ssh_theme TEXT;
UPDATE connections SET rdp_enabled = (protocol = 'rdp'), ssh_enabled = (protocol = 'ssh');
ALTER TABLE connections DROP COLUMN protocol;

-- Préférences de terminal du compte : thème par défaut, combinaisons de la barre de touches (JSON).
ALTER TABLE users ADD COLUMN terminal_theme TEXT;
ALTER TABLE users ADD COLUMN key_combos TEXT;

-- Réglages du service ; `ssh_key` : clé privée ed25519 du service, chiffrée par la clé maîtresse.
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
