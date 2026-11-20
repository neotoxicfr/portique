-- La session a-t-elle été ouverte avec un second facteur (TOTP ou passkey) ? Le SSH l'exige : la clé du
-- service ouvre toutes les machines, une session ouverte par mot de passe seul ne doit pas y donner accès.
ALTER TABLE sessions ADD COLUMN mfa INTEGER NOT NULL DEFAULT 0;
