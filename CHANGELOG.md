# Journal des versions

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), versions : [SemVer](https://semver.org/lang/fr/).

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
