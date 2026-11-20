## Quoi et pourquoi

<!-- Le scénario qui motive le changement ; l'issue liée (« Closes #… »). -->

## Comment c'est vérifié

<!-- Tests ajoutés, essai sur un vrai PC (version de Windows, codec négocié). Sans capture d'écran privée. -->

## Liste de contrôle

- [ ] `./scripts/ci.sh` passe (ou, à défaut, les étapes ci-dessous)
- [ ] `cargo test --workspace --exclude portique-web`
- [ ] `cargo clippy` (hôte sans `portique-web`, puis `portique-web` en `--target wasm32-unknown-unknown`) et `cargo fmt --all --check`
- [ ] `trunk build --release` si le front change
- [ ] sections de spec citées pour tout nouveau PDU
- [ ] aucune donnée réelle (capture, mot de passe, adresse) dans le diff
