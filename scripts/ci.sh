#!/usr/bin/env bash
# Vérifications locales, à lancer avant chaque push (pas de CI GitHub : tout se fait sur le poste).
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
cargo test --workspace --exclude portique-web --locked
step "front"
(cd crates/web && trunk build --release --dist ../../dist)
if command -v cargo-audit >/dev/null; then
  step "audit des dépendances"
  cargo audit
fi
printf '\nCI locale OK\n'
