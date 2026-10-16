# Pile RDP : connexion et NLA (étape 2)

Sources : MS-RDPBCGR (2.2.1.1 à 2.2.1.4, 2.2.10.2), MS-NLMP (3.3.2, 3.4, 4.2.4), MS-CSSP.
IronRDP et FreeRDP ne servent que de référence légère.

## Séquence

1. **X.224 Connection Request** : cookie `mstshash`, protocoles demandés `SSL | HYBRID | HYBRID_EX`.
2. **Connection Confirm** : protocole retenu, ou `RDP_NEG_FAILURE` avec un message clair.
3. **TLS** (rustls, ring). Le certificat RDP est auto-signé ; il sera épinglé par connexion
   (confiance au premier usage) dans le serveur.
4. **CredSSP v6 + NTLMv2** (`rdp-auth`) : la preuve de clé publique lie l'authentification au
   certificat TLS (SHA-256 avec nonce, versions 5 et plus). Un code NTSTATUS du serveur est traduit
   (ex. `0xC000006D` = identifiants refusés).
5. **Early User Authorization Result** (HYBRID_EX) : 4 octets, 0 = autorisé, 5 = accès RDP refusé.
6. **MCS Connect Initial / Response** (BER) avec GCC Conference Create (PER) et blocs client/serveur.

## Choix

- NTLM : drapeaux de mstsc (`0xE2088235`), MIC toujours présent (`MsvAvFlags`), SPN `TERMSRV/hôte`,
  réponse LM à zéro quand le serveur fournit un horodatage.
- Liaison de canal (EPA) : `MsvAvChannelBindings` = MD5 de `gss_channel_bindings` avec
  `tls-server-end-point:` + hachage du certificat (RFC 5929 : algorithme de la signature, SHA-256
  par défaut). Les paires propres au client (drapeaux, liaison, SPN) ne sont jamais reprises du
  serveur.
- CredSSP : versions 5 et 6 seulement ; les 2 à 4 n'ont pas de nonce dans la preuve de clé
  (CVE-2018-0886).
- Aucune crypto maison : MD4, MD5, HMAC, RC4, SHA-256 viennent de RustCrypto ; seuls les messages
  sont écrits ici. Le hasard et l'heure sont fournis par l'appelant, pour pouvoir tester.
- Client annoncé en RDP 10.7, avec les drapeaux précoces qui ouvrent EGFX, 32 bpp, heartbeat et
  disposition des écrans.

## Mesuré sur le PC cible (16/10/2026, via wireguard)

- Protocole retenu : HYBRID_EX ; drapeaux de négociation `0x2f` (EGFX supporté, restricted admin,
  redirected auth).
- TLS 1.3.
- NLA réussie avec un compte local (domaine vide), liaison de canal EPA comprise.
- Serveur RDP 10.12 (`0x00080011`), capacités précoces `0x4` (edge actions v2), chiffrement RDP 0/0.
- Canaux : E/S 1003, `cliprdr` 1004, `drdynvc` 1005.

## Sonde

`crates/rdp-probe` rejoue toute la séquence et affiche le résultat. Le mot de passe est lu depuis
`YAWRDP_PROBE_PASSWORD_FILE` et n'est jamais affiché.

```sh
docker run --rm --network container:wireguard \
  -v /srv/yawrdp/probe/rdp-probe:/rdp-probe:ro \
  -v /srv/yawrdp/secrets/rdp_password:/run/secrets/rdp_password:ro \
  -e YAWRDP_PROBE_HOST=192.0.2.50 -e YAWRDP_PROBE_USER=alice \
  -e YAWRDP_PROBE_PASSWORD_FILE=/run/secrets/rdp_password \
  debian:bookworm-slim /rdp-probe
```

## Session et EGFX : comportements de Windows mesurés (16/10/2026)

- Capacités EGFX 8.1 : seules certaines combinaisons de drapeaux sont admises ; AVC420 seul (0x10) fait
  fermer le canal graphique, il faut SMALL_CACHE | AVC420 (0x12).
- `FRAME_ACKNOWLEDGE.totalFramesDecoded` est un compteur : y mettre l'identifiant d'image (qui saute des
  valeurs) mène à `ERRINFO_GRAPHICSSUBSYSTEMFAILED` (0x112F) au bout de quelques secondes.
- RemoteFX Progressive : l'état des tuiles appartient à la surface, pas au contexte de codec ; des tuiles
  « différence » arrivent dans un contexte neuf. Effacer l'état à `DeleteEncodingContext` donne des tuiles
  grises (127,127,128).
- EGFX 10.x : sans `SCALEDMAP_DISABLE`, Windows emploie `MapSurfaceToScaledOutput` (0x0017).
- Sans la stratégie « H.264 4:4:4 prioritaire », Windows (mode mixte) n'envoie pas de H.264 pour du
  mouvement de fenêtres ; il en envoie lors d'un changement de disposition d'écrans.
- Le canal DisplayControl s'ouvre quelques secondes après la session : une taille demandée avant doit être
  rejouée à l'arrivée de ses capacités.
- Presse-papier : un Ctrl+V transmis trop tôt colle l'ancien contenu ; attendre l'accusé (Format List
  Response) de notre liste de formats, que Windows n'envoie qu'une fois notre contenu installé.
- Le Wake-on-LAN en broadcast ne traverse pas un tunnel IP ; la commande `/tool wol` du routeur MikroTik
  du réseau du PC, envoyée par SSH, fonctionne.
