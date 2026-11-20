# Contribuer à Portique

Merci de ton intérêt ! Ce guide tient en une page.

## Préparer l'environnement

- Rust stable, avec `rustfmt` et `clippy`
- cible wasm : `rustup target add wasm32-unknown-unknown`
- [trunk](https://trunkrs.dev) pour le front : `cargo install --locked trunk`
- `curl` et `openssl` : `scripts/vendor-xterm.sh` télécharge xterm.js et vérifie son empreinte

```sh
cargo test --workspace --exclude portique-web
cargo clippy --workspace --exclude portique-web --all-targets -- -D warnings
cargo clippy -p portique-web --target wasm32-unknown-unknown -- -D warnings   # le front ne compile qu'en wasm
cargo fmt --all --check
(cd crates/web && trunk build --release --dist ../../dist)
```

Ou tout d'un coup : `./scripts/ci.sh`, à lancer avant chaque push. La CI GitHub (`.github/workflows/ci.yml`)
rejoue ce même script sur chaque push et chaque pull request.

Tout ce qui est généré reste dans le dépôt et est ignoré par Git (`target/`, `dist/`, `data/`).

## Règles du projet

- **La spec fait foi.** Chaque structure de protocole cite sa section (`MS-RDPEGFX 2.2.2.1`, etc.) en
  commentaire. IronRDP et FreeRDP peuvent servir à lever une ambiguïté, mais on n'en copie pas de code.
- **Pas de crate RDP tierce**, et **pas de cryptographie maison** : RustCrypto, rustls, ring.
- **Tout ce qui vient du PC est hostile** : longueurs bornées, budgets de mémoire et de CPU, aucun `unwrap`
  sur une donnée reçue.
- **Tests** : un test par décodeur, avec les vecteurs de la spec quand elle en donne. Un bug corrigé arrive
  avec son test.
- **Style** : `rustfmt.toml` du dépôt. Commentaires et docs en français, identifiants en anglais.
- **Commits** : [Conventional Commits](https://www.conventionalcommits.org) en anglais
  (`fix(gfx): …`). Le corps explique le scénario qui a mené au changement.

## Confidentialité

Une capture d'écran, un enregistrement EGFX ou un journal de session montre le bureau de quelqu'un. N'en
joins jamais à une issue ou une PR sans l'avoir anonymisé. Ne mets jamais de mot de passe, de jeton, de clé
ni d'adresse e-mail personnelle dans un fichier suivi, un commit ou une issue : utilise des valeurs factices
(`user@example.com`).

## Proposer un changement

1. Ouvre d'abord une issue pour tout changement important, pour en discuter avant de coder.
2. Une PR = un sujet. Remplis le modèle de PR.
3. Les vérifications ci-dessus doivent passer.

En contribuant, tu acceptes que ton code soit publié sous la double licence MIT / Apache-2.0 du projet.
