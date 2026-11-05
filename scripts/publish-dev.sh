#!/usr/bin/env bash
# Image de branche ghcr.io/neotoxicfr/yawrdp:dev, à republier à chaque livraison sur dev
# (dépôt privé : pas de CI GitHub). La prod suit ce tag.
# Prérequis : arbre propre dont HEAD = origin/dev, docker connecté à ghcr.io.
set -euo pipefail
cd "$(dirname "$0")/.."

image=ghcr.io/neotoxicfr/yawrdp
git fetch -q origin dev
[[ -z $(git status --porcelain) ]] || { echo "arbre de travail non propre" >&2; exit 1; }
[[ $(git rev-parse HEAD) == $(git rev-parse origin/dev) ]] || { echo "HEAD n'est pas origin/dev" >&2; exit 1; }

./scripts/ci.sh
sha=$(git rev-parse --short HEAD)
docker build --build-arg VERSION="dev-$sha" -t "$image:dev" .
docker push "$image:dev"
echo "$image:dev publiée (dev-$sha)"
