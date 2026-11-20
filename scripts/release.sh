#!/usr/bin/env bash
# Release sans CI GitHub : ./scripts/release.sh 0.1.0 [notes.md]
# - vérifications de scripts/ci.sh ;
# - image ghcr.io/neotoxicfr/portique:X.Y.Z (sans « v ») et :latest, amd64 + arm64 (scripts/build-image.sh) ;
# - archives binaire + front (linux x86_64 et aarch64, glibc 2.38+) et SHA256SUMS ;
# - tag vX.Y.Z et release GitHub avec les notes rédigées (jamais générées).
# Prérequis : .env (voir .env.exemple), gh authentifié, arbre propre sur main.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=/dev/null
. ./.env

version=${1:?usage: release.sh X.Y.Z [notes.md]}
notes=${2:-.audit/release-v$version.md}
repo=neotoxicfr/portique
image=ghcr.io/$repo

[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version X.Y.Z attendue (sans v)" >&2; exit 1; }
[[ -s $notes ]] || { echo "notes absentes : $notes" >&2; exit 1; }
[[ -z $(git status --porcelain) ]] || { echo "arbre de travail non propre" >&2; exit 1; }
[[ $(git branch --show-current) == main ]] || { echo "release depuis main uniquement" >&2; exit 1; }
grep -q "^version = \"$version\"" Cargo.toml || { echo "Cargo.toml n'est pas en $version" >&2; exit 1; }
grep -q "^## \[v$version\]" CHANGELOG.md || { echo "CHANGELOG.md sans entrée v$version" >&2; exit 1; }

./scripts/ci.sh

ssh "$DOCKER_SSH" "cd '$REMOTE_DIR' && ARM_HOST='$ARM_HOST' scripts/build-image.sh $version $version latest"

# Archives extraites des images publiées, sur l'hôte Docker (release/ est dans le dossier partagé).
ssh "$DOCKER_SSH" "cd '$REMOTE_DIR' && rm -rf release && mkdir release && for a in amd64:x86_64 arm64:aarch64; do
    out=release/portique-$version-\${a#*:}-linux; mkdir -p \$out
    cid=\$(docker create $image:$version-\${a%%:*})
    docker cp \$cid:/usr/local/bin/portique \$out/portique && docker cp \$cid:/app/web \$out/web; docker rm \$cid >/dev/null
    cp README.md CHANGELOG.md LICENSE-MIT LICENSE-APACHE \$out/ && tar -C release -czf \$out.tar.gz \${out#release/}
  done && (cd release && sha256sum ./*.tar.gz > SHA256SUMS) && chown -R \$(stat -c %u:%g .) release"

git tag -a "v$version" -m "v$version"
git push origin "v$version"
gh release create "v$version" -R "$repo" --title "v$version" --notes-file "$notes" --verify-tag \
  release/*.tar.gz release/SHA256SUMS
echo "release v$version publiée"
