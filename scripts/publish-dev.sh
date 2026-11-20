#!/usr/bin/env bash
# Image de branche ghcr.io/neotoxicfr/portique:dev (amd64 + arm64), à republier à chaque livraison sur dev
# (dépôt privé : pas de CI GitHub). Les déploiements suivent ce tag.
# Prérequis : .env (voir .env.exemple), arbre propre dont HEAD = origin/dev.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=/dev/null
. ./.env

git fetch -q origin dev
[[ -z $(git status --porcelain) ]] || { echo "arbre de travail non propre" >&2; exit 1; }
[[ $(git rev-parse HEAD) == $(git rev-parse origin/dev) ]] || { echo "HEAD n'est pas origin/dev" >&2; exit 1; }

./scripts/ci.sh
sha=$(git rev-parse --short HEAD)
ssh "$DOCKER_SSH" "cd '$REMOTE_DIR' && ARM_HOST='$ARM_HOST' scripts/build-image.sh dev-$sha dev"

# Déploiements qui suivent :dev (DEPLOY dans .env, joints depuis l'hôte Docker) : « hôte:dossier » séparés
# par des espaces, « - » pour l'hôte Docker lui-même. Le compose y tire l'image, sauf `pull_policy: never`.
for d in ${DEPLOY:-}; do
  host=${d%%:*} dir=${d#*:}
  cmd="cd '$dir' && docker compose pull -q --ignore-buildable 2>/dev/null; docker compose up -d"
  if [[ $host == - ]]; then ssh "$DOCKER_SSH" "$cmd"; else ssh "$DOCKER_SSH" "ssh $host \"$cmd\""; fi
done
