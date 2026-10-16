# yawrdp

Client RDP web auto-hébergé, en Rust de bout en bout : serveur axum et front Leptos (wasm). La pile RDP est
écrite maison à partir des spécifications Microsoft. Elle remplace Apache Guacamole.

État : **étape 1/8**. Comptes, connexions, Wake-on-LAN et front sont en place ; la session RDP arrive à
partir de l'étape 2.

## Configuration

Chaque secret accepte `VAR` ou `VAR_FILE` (Docker secrets). Les deux à la fois sont refusés.

| Variable | Défaut | Rôle |
|---|---|---|
| `YAWRDP_PUBLIC_URL` | — (requis) | URL publique, origine des passkeys |
| `YAWRDP_MASTER_KEY(_FILE)` | — (requis) | 32 octets en base64 (`openssl rand -base64 32`), chiffre les secrets en base |
| `YAWRDP_ADMIN_PASSWORD(_FILE)` | — | crée le compte `admin` au premier démarrage (12 caractères minimum) |
| `YAWRDP_AUTH_MODE` | `builtin` | `builtin` (mot de passe + TOTP + passkeys) ou `proxy` |
| `YAWRDP_TRUSTED_PROXIES` | — | IP/CIDR des proxys de confiance (requis en mode proxy, sert aussi à `X-Forwarded-For`) |
| `YAWRDP_PROXY_USER_HEADER` | `Remote-User` | en-tête de l'identifiant en mode proxy |
| `YAWRDP_PROXY_GROUPS_HEADER` | `Remote-Groups` | en-tête des groupes |
| `YAWRDP_PROXY_ADMIN_GROUP` | — | groupe qui donne le rôle admin |
| `YAWRDP_LISTEN` | `0.0.0.0:8080` | adresse d'écoute |
| `YAWRDP_DATA_DIR` | `/data` | base SQLite |
| `YAWRDP_STATIC_DIR` | `/app/web` | front compilé |
| `YAWRDP_INSECURE_COOKIES` | — | `1` = cookies sans `Secure` (développement en HTTP seulement) |

En mode `proxy`, le login intégré est désactivé. Les comptes sont créés à la volée depuis `Remote-User`, et
le rôle admin est resynchronisé à chaque requête.

## Développement

```sh
cargo test -p yawrdp-server
(cd crates/web && trunk build --release --dist ../../dist)
YAWRDP_PUBLIC_URL=http://localhost:18431 YAWRDP_LISTEN=127.0.0.1:18431 YAWRDP_DATA_DIR=./data \
YAWRDP_STATIC_DIR=./dist YAWRDP_MASTER_KEY=$(openssl rand -base64 32) \
YAWRDP_ADMIN_PASSWORD=change-me-please cargo run -p yawrdp-server
```

## Licence

MIT OR Apache-2.0.
