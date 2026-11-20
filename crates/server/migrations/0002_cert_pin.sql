-- Empreinte SHA-256 du certificat TLS du PC, épinglée à la première connexion réussie.
ALTER TABLE connections ADD COLUMN cert_sha256 BLOB;
