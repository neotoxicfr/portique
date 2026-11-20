# Journal des versions

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), versions : [SemVer](https://semver.org/lang/fr/).

## [v0.3.0] - 2026-11-20

### Ajouté

- **SSH.** Une machine offre le RDP, le SSH ou les deux (une seule tuile, le choix au clic quand il y a
  les deux). Le serveur ouvre la session avec un terminal et suit le redimensionnement ; le navigateur
  affiche xterm.js, servi par Portique (aucun CDN).
- **Clé SSH du service** : ed25519, créée au premier besoin et chiffrée en base. La page admin donne la
  ligne `authorized_keys`, avec `from=` facultatif. Le mot de passe de l'hôte, s'il y en a un, sert de
  second essai.
- **Rebonds** : un hôte SSH peut passer par un autre, en chaîne ; une boucle est refusée. La clé d'hôte de
  chaque saut est approuvée par un admin, puis épinglée.
- **Barre de touches** sur écran tactile, au-dessus du clavier virtuel : Échap, Tab, Ctrl et Alt collants,
  flèches et combinaisons du compte (page « Mon compte »).
- **Thèmes du terminal** : sombre, clair, solarisé, Dracula, Nord, alerte ; par compte, remplaçable par hôte.
- Le réveil par commande SSH essaie aussi la clé du service : le mot de passe devient facultatif.

### Sécurité

- Ouvrir un terminal exige la double authentification en mode intégré (TOTP ou passkey) : la clé du
  service ouvre toutes les machines où elle est posée.

### Modifié

- Les connexions deviennent des hôtes : le champ `protocol` de l'API est remplacé par `rdp` et `ssh`. La
  migration garde le RDP des connexions existantes.

## [v0.2.0] - 2026-11-20

### Modifié

- **yawrdp devient Portique.** Le projet ne se limitera plus au RDP (le SSH arrive) : nouveau nom, nouveau
  dépôt (`neotoxicfr/portique`) et nouvelle image (`ghcr.io/neotoxicfr/portique`).
- **Changements à reporter dans un déploiement existant** :
  - variables `YAWRDP_*` renommées `PORTIQUE_*` ;
  - binaire `portique` (healthcheck : `portique healthcheck`) ;
  - base `portique.db` : renommer `yawrdp.db` (et ses fichiers `-wal`/`-shm`) dans le dossier de données ;
  - scripts de préparation du PC : `portique.reg`, `portique.cmd`, `portique.ps1` ;
  - le cookie de session et l'en-tête anti-CSRF changent de nom : les sessions ouvertes sont à refaire.

### Ajouté

- Image **multi-architecture** : amd64 et arm64 sous le même tag. L'arm64 est construite en natif sur une
  machine ARM, sans émulation (`scripts/build-image.sh`). La release publie aussi une archive aarch64.

### Dépendances

- `webauthn-rs` 0.6.2 : les passkeys déjà enregistrées restent valides (même format stocké).
- `leptos` 0.8.23, `openssl` 0.10.82, `uuid` 1.29.2, image de build Rust 1.100.

## [v0.1.5] - 2026-11-04

### Sécurité

- `tokio` 1.54.1 (RUSTSEC-2026-0384, condition de course dans `time::Interval`), `rustls-webpki` 0.103.16
  (RUSTSEC-2026-0382, intermédiaires retirés de la confiance), `crypto-bigint` 0.7.10 (RUSTSEC-2026-0387)
  et `ctutils` 0.4.8 (RUSTSEC-2026-0385), deux correctifs de temps constant.
- `russh` 0.65.1 (Wake-on-LAN par SSH) : allocations sans limite via EXT_INFO d'un serveur malveillant
  (GHSA-4p9f-7p9m-5vfg), canal bloqué par une taille de paquet nulle (GHSA-fw5c-8223-6h42), `kex_done`
  appelé avant la vérification de la clé d'hôte (GHSA-9264-jvgf-6w2f).
- `cargo audit` fait partie de `scripts/ci.sh` ; seule exception : `rsa` (RUSTSEC-2023-0071, sans
  correctif), non atteignable, justifiée dans `.cargo/audit.toml`.

## [v0.1.4] - 2026-10-21

### Corrigé

- Le navigateur pouvait garder indéfiniment une ancienne version de la page, et donc de l'appli :
  aucun en-tête de cache n'était envoyé. La page, le service worker, le manifeste et les scripts de
  préparation sont désormais revalidés à chaque chargement (`no-cache`). Les fichiers empreintés par
  trunk sont mis en cache un an (`immutable`). Le service worker change de cache, ce qui purge l'ancienne
  coquille.

## [v0.1.3] - 2026-10-21

### Corrigé

- Écran noir quand le décodeur H.264 du navigateur garde les images en tampon (vu avec Firefox sous
  Windows) : portique attendait chaque image sans limite et l'affichage se figeait. Au-delà de 1,5 s sans
  image (ou sans copie de l'image), le H.264 est désactivé pour ce navigateur et la session se rouvre
  sans lui.
- Le lien « Préparer un PC » du pied de page ne menait nulle part : le routeur du front l'interceptait.

## [v0.1.2] - 2026-10-21

### Modifié

- Firefox garde le H.264 (toujours encodé en NVENC par le PC). Son décodeur ne rend que du RGB : il
  affiche la sous-image principale du flux 4:4:4, qui est une image 4:2:0 complète, tandis que Chrome et
  Edge gardent le 4:4:4. L'espace BT.709 pleine plage est imposé au décodeur pour que le navigateur
  convertisse les couleurs comme Windows les a encodées. Le repli sans H.264 de la v0.1.1 ne sert plus
  qu'en cas d'échec réel du décodeur.

## [v0.1.1] - 2026-10-21

### Corrigé

- Écran noir dans Firefox. Son décodeur WebCodecs ne rend que des images RGB, alors que le H.264 4:4:4
  de RDP a besoin des plans YUV. À la première image inexploitable, le navigateur est noté inapte (par
  version) et la session se rouvre seule sans H.264 (RemoteFX Progressive / ClearCodec).

## [v0.1.0] - 2026-10-20

Première version.

### Ajouté

- **Pile RDP maison** à partir des spécifications Microsoft : X.224, MCS/GCC, slow-path et fast-path,
  canaux statiques et dynamiques.
- **Authentification** : NLA avec CredSSP v5+ et NTLMv2 lié au canal TLS ; certificat du PC épinglé après
  approbation.
- **Affichage EGFX** : ZGFX, Planar, ClearCodec, NSCodec, RemoteFX Progressive, H.264 AVC420 et AVC444 v1/v2
  décodés par WebCodecs.
- **Presse-papier** : texte, HTML et images, dans les deux sens.
- **Affichage** : résolution dynamique, multi-écran, plein écran avec capture du clavier, Ctrl+Alt+Suppr,
  reconnexion automatique, PWA.
- **Wake-on-LAN** : UDP direct ou commande SSH, avec clé d'hôte approuvée par un admin.
- **Comptes** : Argon2id, TOTP, passkeys, rôles ; mode proxy (Authelia…).
- **Scripts de préparation** du PC Windows (`/setup/`).
- **Image Docker** : utilisateur non root, secrets `_FILE`, healthcheck.
