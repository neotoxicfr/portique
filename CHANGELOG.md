# Journal des versions

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), versions : [SemVer](https://semver.org/lang/fr/).

## [v0.5.0] - 2026-11-21

### Ajouté

- Réveil en mode « Direct » (paquet UDP, sans hôte SSH) ou « Rebond ». En mode Rebond comme pour le terminal SSH,
  la machine passe par un hôte connu de la liste ou par un « Hôte » saisi pour elle seule (adresse, port, compte,
  mot de passe facultatif, clé d'hôte à approuver ou à oublier) ; « Accès à l'hôte » permet de joindre cet hôte
  saisi par un hôte connu.
- Supprimer un hôte connu ne coupe plus les machines qui passaient par lui : chacune reçoit un hôte saisi qui en
  reprend l'adresse, le compte, le mot de passe et la clé, et l'accès par son propre rebond. Un rebond SSH inactif
  (SSH coupé sur la machine) n'est pas copié : sa référence est retirée.
- `publish-dev.sh` redéploie aussi les autres déploiements qui suivent `:dev` (`DEPLOY_OTHERS`).
- Admin en mode proxy : la colonne de double authentification des comptes montre une information bleue (elle se
  règle dans le proxy, que Portique ne voit pas) au lieu d'une alerte orange.
- RDP sur écran tactile : bouton clavier déplaçable (position retenue par appareil) avec un bouton de déconnexion,
  et barre de touches au-dessus du clavier système (Échap, Tab, Ctrl/Alt/Win collants, flèches, Suppr, Début/Fin,
  pages, F1-F12, Impr. écran, Ctrl+Alt+Suppr).
- Menu de session : chemin d'image réellement utilisé (H.264 4:4:4, 4:2:0, sans H.264, format du décodeur) et
  option « Netteté maximale » (sans H.264 sur cet appareil).
- H.264 4:4:4 recomposé quand le navigateur ne livre que des images RGB et que sa conversion s'inverse (texte et
  icônes sans franges de couleur) ; sinon la vue principale reste affichée.

### Modifié

- API d'administration : `wol_command.via` et `ssh.jump` (hôte connu `{"kind":"known","id"}` ou hôte saisi
  `{"kind":"host",…}`) remplacent `via_id`, `host`, `user`, `password`, `approve_hostkey` et `jump_id`.
- Le réveil par adresse saisie des versions précédentes est repris au démarrage en hôte saisi (mot de passe et clé
  d'hôte gardés). Migration 0009 : sauvegarder `/data` avant la mise à jour.
- Admin sur téléphone : l'éditeur d'une machine s'ouvre sous la ligne touchée.
- Page « Préparer un PC » retouchée, avec un retour vers Portique.
- Dépendances à jour (gloo-net 0.8, qrcode 0.15, sqlx 0.9.1…), crate `openssl` inutilisé retiré, Rust 1.100.

### Corrigé

- Saisie SSH : `TCP_NODELAY` sur la connexion SSH et sur le serveur web ; sur un lien lointain les frappes ne
  partent plus par paquets (écho médian mesuré : 241-276 ms avant, 160 ms après, pour 160 ms de délai réseau).
- Terminal SSH : la dernière ligne ne dépasse plus du bas de l'écran.
- Anneaux de focus : plus rognés par les coins arrondis des groupes.

## [v0.4.0] - 2026-11-21

### Ajouté

- **Nouvelle interface** dans l'esprit des apps système d'Apple : couleurs système, fonds groupés, barres
  translucides, pastilles façon icône d'app, interrupteurs ; clair et sombre selon l'appareil.
- **Accueil** : une carte de taille fixe par machine, trois emplacements d'icônes fixes (Terminal, Bureau,
  Réveil) ; une fonction absente laisse un rond vide. Hôtes au thème « alerte » en rouge. Recherche.
- **RDP sur iPhone et iPad** : bouton clavier (texte, Retour arrière, Entrée, Suppr, coller, saisie IME),
  gestes (toucher = clic, appui long = clic droit, glisser, deux doigts = molette, pincer = zoom local).
- **Admin** en vue partagée (liste et éditeur côte à côte) ; route dédiée de remise à zéro de la 2FA
  (`POST /api/admin/users/{id}/reset-2fa`) qui ne touche jamais au rôle.
- CI et releases sur GitHub Actions (images amd64 et arm64 construites en natif), tests natifs du front en CI.

### Modifié

- Navigation en contrôle segmenté sur ordinateur, barre d'onglets en bas sur téléphone ; déconnexion en icône ;
  plus aucun texte de remplissage.
- Compte et admin en groupes façon Réglages ; terminal avec barre fine, barre de touches et alerte de clé
  d'hôte façon iOS.
- PWA : zones sûres respectées, couleur de barre claire et sombre, nouvelle icône (variante adaptative plein
  cadre), page hors ligne dès le premier lancement.
- L'API des connexions expose `alert` ; le champ `reset_2fa` de la mise à jour d'un compte est retiré.
- Les scripts « Préparer un PC » contrôlent chaque étape et gardent des fins de ligne Windows.
- Réveil par commande SSH : plus de commande proposée par défaut, et seul le code de sortie de l'hôte décide de
  l'échec (la sortie n'est plus lue). Une commande qui échoue en répondant 0 passe désormais pour réussie.

### Sécurité

- Un compte qui a déjà un second facteur n'en ajoute ni n'en retire un (TOTP ou passkey) que depuis une
  session ouverte avec lui. Un compte à passkey seule se connecte encore au mot de passe, et ce mot de passe
  suffisait à enrôler un nouveau facteur, puis à ouvrir le SSH.
- La remise à zéro de la double authentification par un admin coupe les sessions du compte.
- Pas TOTP consommé de façon atomique et lié à la graine vérifiée ; preuve de connexion revérifiée à la
  création de la session ; un changement de mot de passe ne peut plus écraser une remise à zéro simultanée ;
  un admin rétrogradé ne peut plus finir de créer ou promouvoir un compte.
- Limitation des tentatives réservée avant tout travail coûteux, IPv6 comptée par /64, défis passkey plafonnés
  sans bloquer tout le monde, identifiants de passkeys, de comptes et de machines jamais réattribués
  (migrations 0007 et 0008 : sauvegarder `/data` avant la mise à jour).
- Une confirmation TOTP ou une passkey inscrite pendant une remise à zéro de la 2FA ne la réactive plus ; le
  compteur de signature d'une passkey ne recule plus ; les identifiants comptent sans casse pour la limitation.
- Activer ou couper le TOTP et supprimer une passkey exigent une session encore ouverte au moment de l'écriture :
  déconnecter tout le monde (changement de mot de passe) arrête aussi une configuration TOTP lancée par un tiers.
  Une preuve de connexion révoquée en cours de route répond 409 avec son propre message, plus « mauvais mot de passe ».
- NTLM exige 128 bits, signature et chiffrement ; Argon2 hors des workers de requêtes ; attentes SSH et WoL
  bornées.

### Corrigé

- Revue complète du code par CodeRabbit : trames RDP malformées refusées (X.224, fast-path, MCS, licence,
  capacités, canaux virtuels, tuiles progressives), presse-papier fiabilisé dans les deux sens (accusé par
  annonce, réponses tardives jetées, repli DIB), redirection de ferme et identifiants trop longs signalés
  clairement, relais RDP vidé après chaque écriture.
- Session : refus durable (accès, identifiants, certificat changé) sans reconnexion en boucle, échec passager
  toujours reconnecté ; boutons relâchés à l'annulation d'un geste et suivis par fenêtre ; dispositions
  multi-écran validées avant d'ouvrir les fenêtres, extension annulée si Windows ne la confirme pas ; bureau,
  clavier et menu inactifs derrière une alerte, de même pour le terminal SSH ; trafic des canaux retenu pendant
  une suspension (SUSPEND/RESUME) ; le bureau suit encore la fenêtre quand le PC ignore des demandes de taille.
- PWA : ouvrir un fichier (icône…) ne remplace plus la page hors ligne. Préparation du PC : un nouvel essai après
  une annulation ratée ne touche plus au réveil d'une autre carte réseau.

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

### Performances

- Ouverture d'une session RDP plus rapide sur un lien lointain : les jointures de canaux MCS sont sautées quand
  Windows le permet (mesuré sur un aller-retour de 162 ms : première image à 1,94 s au lieu de 2,59 s).
- Le front est servi compressé (gzip ou brotli) : le wasm passe de 1,3 Mo à 0,5 Mo même sans proxy compressant.
- Le journal du serveur détaille les phases d'ouverture RDP ; la console du navigateur les résume.

### Corrigé

- Une session refusée (double authentification manquante, hôte sans SSH, accès retiré) affiche la raison au
  lieu de « session terminée ».
- Terminal : caractères accentués perdus sur un serveur en locale C (LC_CTYPE=C.UTF-8 demandé, comme OpenSSH).
- Administration utilisable sur téléphone (tableaux en cartes), clé du service lisible en entier, indicateur et
  bouton « Retour » pendant les connexions, barre de titre du terminal qui ne masque plus le texte.

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
