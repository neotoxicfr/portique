#!/usr/bin/env bash
# Vérifications à lancer avant chaque push ; la CI GitHub (.github/workflows/ci.yml) lance ce même script.
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n== %s\n' "$*"; }

step "format"
cargo fmt --all --check
step "clippy (serveur et pile RDP)"
cargo clippy --workspace --exclude portique-web --all-targets --locked -- -D warnings
step "clippy (front, wasm uniquement)"
cargo clippy -p portique-web --target wasm32-unknown-unknown --locked -- -D warnings
step "tests"
cargo nextest run --workspace --exclude portique-web --locked
cargo test --doc --workspace --exclude portique-web --locked   # nextest ne lance pas les doctests
step "tests du front (logique pure, en natif)"
# Dossier cible à part : RUSTFLAGS différent, il invaliderait le cache des autres étapes.
CARGO_TARGET_DIR=target/web-natif RUSTFLAGS=--cfg=web_sys_unstable_apis cargo nextest run -p portique-web --locked
step "front"
./scripts/vendor-xterm.sh
(cd crates/web && trunk build --release --dist ../../dist)
step "dépendances : failles connues, licences, doublons, provenance (deny.toml)"
cargo deny --locked check --hide-inclusion-graph
step "dépendances déclarées mais inutilisées"
cargo machete
printf '\nCI locale OK\n'
