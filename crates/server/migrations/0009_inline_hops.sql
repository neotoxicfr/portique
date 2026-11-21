-- Rebond saisi pour une seule machine (réveil ou terminal) : une ligne cachée, jamais listée ni ouverte comme
-- cible, supprimée avec sa machine. Elle sert de saut comme un hôte déclaré (clé d'hôte, mot de passe
-- scellé `ssh:{id}`, rebonds).
ALTER TABLE connections ADD COLUMN inline_for INTEGER REFERENCES connections(id) ON DELETE CASCADE;
-- Clé présentée par un rebond saisi lors d'un réveil, en attente d'approbation dans l'admin de la machine.
ALTER TABLE connections ADD COLUMN ssh_hostkey_pending TEXT;
-- Les colonnes wol_ssh_* (sauf wol_ssh_command) ne servent plus : reprises au démarrage en lignes cachées.
