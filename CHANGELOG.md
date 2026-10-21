# Journal des versions

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), versions : [SemVer](https://semver.org/lang/fr/).

## [v0.1.3] - 2026-10-21

### Corrigé

- Écran noir quand le décodeur H.264 du navigateur garde les images en tampon (vu avec Firefox sous
  Windows) : yawrdp attendait chaque image sans limite et l'affichage se figeait. Au-delà de 1,5 s sans
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
