#!/usr/bin/env bash
# Image de branche ghcr.io/neotoxicfr/portique:dev (amd64 + arm64), à republier à chaque livraison sur dev
# (construite ici : la CI GitHub ne publie que les releases). Les déploiements suivent ce tag.
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
# Valeur citée pour le shell distant (quel qu'il soit) : apostrophes comprises.
quote() { printf "'%s'" "${1//\'/\'\\\'\'}"; }
ssh "$DOCKER_SSH" "cd $(quote "$REMOTE_DIR") && ARM_HOST=$(quote "$ARM_HOST") scripts/build-image.sh dev-$sha dev"

# Déploiement qui suit :dev (facultatif) : mis à jour dès la publication, sans attendre une mise à jour planifiée.
up="docker compose pull -q && docker compose up -d"
if [[ -n ${DEPLOY_DIR:-} ]]; then
  ssh "$DOCKER_SSH" "cd $(quote "$DEPLOY_DIR") && $up"
fi
# Autres déploiements (facultatif), joints en SSH DEPUIS l'hôte Docker : « hôte:dossier » séparés par « ; »
# (un dossier peut contenir des espaces).
IFS=';' read -r -a others <<<"${DEPLOY_OTHERS:-}"
for d in "${others[@]}"; do
  [[ -n ${d// /} ]] || continue
  ssh "$DOCKER_SSH" "ssh $(quote "${d%%:*}") $(quote "cd $(quote "${d#*:}") && $up")"
done
