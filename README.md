# yawrdp

Client RDP web auto-hébergé, en Rust de bout en bout : serveur axum et front Leptos (wasm). La pile RDP est
écrite maison à partir des spécifications Microsoft (MS-RDPBCGR, -RDPEGFX, -RDPECLIP, -RDPEDISP, -CSSP,
-NLMP) ; aucune crate RDP tierce. Il remplace Apache Guacamole : plus de Java ni de guacd, le serveur ne fait
que la connexion authentifiée puis relaie les octets, le navigateur décode l'image.

## Fonctions (V1)

- Connexion NLA (CredSSP/NTLMv2 lié au canal TLS) faite par le serveur : les identifiants Windows ne
  quittent jamais le serveur. Certificat du PC approuvé par un admin au premier contact (empreinte à
  comparer avec celle du script de préparation), puis épinglé.
- Affichage EGFX : ClearCodec, Planar, RemoteFX Progressive, H.264 AVC420 et AVC444 (v1/v2) décodé par
  WebCodecs (matériel quand le navigateur le peut), conversion BT.709 pleine plage faite dans le wasm.
- Presse-papier texte, HTML et images dans les deux sens.
- Résolution dynamique (la session suit la fenêtre), multi-écran (une fenêtre par écran), plein écran
  avec capture du clavier (Alt+Tab, Win…), Ctrl+Alt+Suppr, reconnexion automatique, PWA installable.
- Wake-on-LAN : paquet UDP direct, ou commande SSH sur un hôte du réseau du PC (routeur MikroTik :
  `/tool wol interface=ether1 mac={mac}`), indispensable à travers un VPN.
- Comptes : mot de passe Argon2id, TOTP, passkeys ; ou mode proxy (Authelia…) avec `Remote-User`.
- Page `/setup/` : scripts Windows (.reg + .cmd, ou .ps1) qui règlent tout le nécessaire RDP, H.264 4:4:4
  et encodage matériel compris, sans rien installer.

## Architecture

| Crate | Rôle |
|---|---|
| `rdp-pdu` | PDU RDP sans I/O : X.224, MCS/GCC, slow-path, fast-path, canaux statiques et dynamiques |
| `rdp-auth` | NTLMv2 et CredSSP (crypto RustCrypto, rien de maison) |
| `rdp-connect` | côté serveur : TCP, négociation, TLS épinglé, NLA |
| `rdp-session` | machine à états de la session (wasm et natif) |
| `rdp-gfx` | pipeline EGFX : surfaces, cache, codecs, composition, AVC444 |
| `rdp-codecs` | ZGFX, Planar, ClearCodec, NSCodec, RemoteFX Progressive |
| `rdp-clip` | presse-papier MS-RDPECLIP |
| `server` | API, comptes, relais WebSocket, Wake-on-LAN |
| `web` | front Leptos (wasm) : pages, moteur de session, WebCodecs |
| `rdp-probe` | sonde de diagnostic contre un vrai serveur (capture PNG, enregistrement EGFX, `gfx-replay`) |

Voir `docs/rdp-connexion.md` pour la séquence de connexion et les comportements mesurés sur Windows.

## Configuration

Chaque secret accepte `VAR` ou `VAR_FILE` (Docker secrets). Les deux à la fois sont refusés.

| Variable | Défaut | Rôle |
|---|---|---|
| `YAWRDP_PUBLIC_URL` | — (requis) | URL publique : origine des passkeys et du WebSocket |
| `YAWRDP_MASTER_KEY(_FILE)` | — (requis) | 32 octets en base64 (`openssl rand -base64 32`), chiffre les secrets en base |
| `YAWRDP_ADMIN_PASSWORD(_FILE)` | — | crée le compte `admin` au premier démarrage (mode intégré, 12 caractères minimum) |
| `YAWRDP_AUTH_MODE` | `builtin` | `builtin` (mot de passe + TOTP + passkeys) ou `proxy` |
| `YAWRDP_TRUSTED_PROXIES` | — | IP, CIDR ou nom (ex. `traefik`, résolu toutes les 10 s, valable 60 s) des proxys de confiance |
| `YAWRDP_PROXY_USER_HEADER` | `Remote-User` | en-tête de l'identifiant en mode proxy |
| `YAWRDP_PROXY_GROUPS_HEADER` | `Remote-Groups` | en-tête des groupes |
| `YAWRDP_PROXY_ADMIN_GROUP` | — | groupe qui donne le rôle admin |
| `YAWRDP_LISTEN` | `0.0.0.0:8080` | adresse d'écoute |
| `YAWRDP_DATA_DIR` | `/data` | base SQLite |
| `YAWRDP_STATIC_DIR` | `/app/web` | front compilé |
| `YAWRDP_INSECURE_COOKIES` | — | `1` = cookies sans `Secure` (développement en HTTP seulement) |

En mode `proxy`, le login intégré est désactivé ; les comptes sont créés à la volée depuis `Remote-User` et le
rôle admin est resynchronisé à chaque requête. Seuls les proxys de confiance peuvent fournir ces en-têtes.

## Déploiement

```sh
docker build -t yawrdp:0.1.0 .
```

Exemple complet (Traefik + Authelia, conteneur dans l'espace réseau d'un tunnel WireGuard, secrets en
fichiers, système de fichiers en lecture seule) : `deploy/docker-compose.example.yml`.

Sécurité appliquée : CSP stricte (seul le script d'amorce du wasm, par empreinte), cookies `SameSite=Strict`,
en-tête anti-CSRF, contrôle d'origine du WebSocket, limitation des tentatives, réauthentification pour la 2FA,
session RDP coupée si la session web est révoquée, budgets mémoire et CPU sur tout ce qui vient du PC.

## Développement

```sh
cargo test --workspace --exclude yawrdp-web
(cd crates/web && trunk build --release --dist ../../dist)
YAWRDP_PUBLIC_URL=http://localhost:18431 YAWRDP_LISTEN=127.0.0.1:18431 YAWRDP_DATA_DIR=./data \
YAWRDP_STATIC_DIR=./dist YAWRDP_MASTER_KEY=$(openssl rand -base64 32) \
YAWRDP_ADMIN_PASSWORD=change-me-please cargo run -p yawrdp-server
```

## Licence

MIT OR Apache-2.0.
