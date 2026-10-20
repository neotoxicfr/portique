#!/usr/bin/env bash
# Release sans CI GitHub : ./scripts/release.sh 0.1.0 [notes.md]
# - vérifications de scripts/ci.sh ;
# - image Docker ghcr.io/neotoxicfr/yawrdp:X.Y.Z (sans « v ») et :latest, poussée ;
# - archive binaire + front (linux x86_64, glibc 2.38+) et SHA256SUMS ;
# - tag vX.Y.Z et release GitHub avec les notes rédigées (jamais générées).
# Prérequis : docker connecté à ghcr.io (write:packages), gh authentifié, arbre propre sur main.
set -euo pipefail
cd "$(dirname "$0")/.."

version=${1:?usage: release.sh X.Y.Z [notes.md]}
notes=${2:-.audit/release-v$version.md}
repo=neotoxicfr/yawrdp
image=ghcr.io/$repo

[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version X.Y.Z attendue (sans v)" >&2; exit 1; }
[[ -s $notes ]] || { echo "notes absentes : $notes" >&2; exit 1; }
[[ -z $(git status --porcelain) ]] || { echo "arbre de travail non propre" >&2; exit 1; }
[[ $(git branch --show-current) == main ]] || { echo "release depuis main uniquement" >&2; exit 1; }
grep -q "^version = \"$version\"" Cargo.toml || { echo "Cargo.toml n'est pas en $version" >&2; exit 1; }
grep -q "^## \[v$version\]" CHANGELOG.md || { echo "CHANGELOG.md sans entrée v$version" >&2; exit 1; }

./scripts/ci.sh

docker build --build-arg VERSION="$version" -t "$image:$version" -t "$image:latest" .

out=release/yawrdp-$version-x86_64-linux
rm -rf release && mkdir -p "$out"
cid=$(docker create "$image:$version")
docker cp "$cid:/usr/local/bin/yawrdp" "$out/yawrdp"
docker cp "$cid:/app/web" "$out/web"
docker rm "$cid" >/dev/null
cp README.md CHANGELOG.md LICENSE-MIT LICENSE-APACHE "$out/"
tar -C release -czf "$out.tar.gz" "$(basename "$out")"
(cd release && sha256sum ./*.tar.gz > SHA256SUMS)

docker push "$image:$version"
docker push "$image:latest"

git tag -a "v$version" -m "v$version"
git push origin "v$version"
gh release create "v$version" -R "$repo" --title "v$version" --notes-file "$notes" --verify-tag \
  "$out.tar.gz" release/SHA256SUMS
echo "release v$version publiée"
