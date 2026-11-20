-- Réveil par commande : la commande peut passer par un hôte SSH déclaré (sa clé, son mot de passe, sa clé
-- d'hôte approuvée, ses rebonds) au lieu d'une adresse saisie à part.
ALTER TABLE connections ADD COLUMN wol_via_id INTEGER REFERENCES connections(id) ON DELETE SET NULL;
