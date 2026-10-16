-- Wake-on-LAN « par commande » : SSH vers un hôte du réseau du PC (routeur MikroTik…) puis
-- commande configurable où {mac} est remplacé. Un paquet magique en broadcast ne traverse pas un
-- tunnel IP (WireGuard) ; l'autre mode reste le paquet UDP direct.
ALTER TABLE connections ADD COLUMN wol_ssh_host TEXT;
ALTER TABLE connections ADD COLUMN wol_ssh_user TEXT;
ALTER TABLE connections ADD COLUMN wol_ssh_password BLOB;
ALTER TABLE connections ADD COLUMN wol_ssh_command TEXT;
-- Empreinte SHA-256 de la clé d'hôte SSH approuvée par un admin ; sans elle, aucun mot de passe
-- n'est envoyé : la clé présentée est seulement notée « en attente » pour approbation.
ALTER TABLE connections ADD COLUMN wol_ssh_hostkey TEXT;
ALTER TABLE connections ADD COLUMN wol_ssh_hostkey_pending TEXT;
