#!/usr/bin/env bash
# Release : ./scripts/release.sh 0.1.0 [notes.md]
# - vérifications de scripts/ci.sh ;
# - tag vX.Y.Z poussé : le workflow Release (.github/workflows/release.yml) publie l'image
#   ghcr.io/neotoxicfr/portique:X.Y.Z (sans « v ») et :latest, les archives et la release, corps vide ;
# - puis les notes rédigées (jamais générées) sont posées sur cette release.
# Seul le workflow crée la release : un tag poussé à la main donne le même résultat, notes à ajouter
# ensuite avec `gh release edit vX.Y.Z --notes-file …`.
# Prérequis : gh authentifié, arbre propre sur main.
set -euo pipefail
cd "$(dirname "$0")/.."

version=${1:?usage: release.sh X.Y.Z [notes.md]}
notes=${2:-.audit/release-v$version.md}
repo=neotoxicfr/portique

[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version X.Y.Z attendue (sans v)" >&2; exit 1; }
[[ -s $notes ]] || { echo "notes absentes : $notes" >&2; exit 1; }
[[ -z $(git status --porcelain) ]] || { echo "arbre de travail non propre" >&2; exit 1; }
[[ $(git branch --show-current) == main ]] || { echo "release depuis main uniquement" >&2; exit 1; }
grep -q "^version = \"$version\"" Cargo.toml || { echo "Cargo.toml n'est pas en $version" >&2; exit 1; }
grep -q "^## \[v$version\]" CHANGELOG.md || { echo "CHANGELOG.md sans entrée v$version" >&2; exit 1; }

./scripts/ci.sh

git tag -a "v$version" -m "v$version"
git push origin "v$version"

# Le run du tag peut mettre quelques secondes à apparaître.
sha=$(git rev-parse HEAD) run=
for _ in {1..30}; do
  run=$(gh run list -R "$repo" --workflow release.yml --event push --commit "$sha" --json databaseId -q '.[0].databaseId')
  [[ -n $run ]] && break
  sleep 10
done
[[ -n $run ]] || { echo "workflow Release introuvable pour v$version" >&2; exit 1; }
gh run watch "$run" -R "$repo" --exit-status --compact --interval 30
gh release edit "v$version" -R "$repo" --notes-file "$notes"
echo "release v$version publiée"
