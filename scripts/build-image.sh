#!/usr/bin/env bash
# Image multi-architecture ghcr.io/neotoxicfr/portique : amd64 construite ici, arm64 construite en natif
# sur ARM_HOST (pas d'émulation), puis réunies sous chaque tag demandé.
# À lancer SUR l'hôte Docker connecté à ghcr.io (les scripts publish-dev.sh et release.sh le font par SSH) :
#   ARM_HOST=<hôte ssh arm64> scripts/build-image.sh <version> <tag> [tag…]
set -euo pipefail
cd "$(dirname "$0")/.."

version=${1:?usage: build-image.sh <version> <tag> [tag…]}
shift
(($#)) || { echo "au moins un tag" >&2; exit 1; }
: "${ARM_HOST:?ARM_HOST : hôte SSH arm64}"
image=ghcr.io/neotoxicfr/portique
arch_tag=$1   # images par architecture : <premier tag>-amd64 / -arm64
work=/tmp/portique-build-$arch_tag

# arm64 en parallèle : sources envoyées sans artefacts ni historique.
tar --exclude=./target --exclude=./.audit --exclude=./dist --exclude=./.git --exclude=./release -cf - . |
  ssh "$ARM_HOST" "rm -rf $work && mkdir -p $work && tar -C $work -xf - && cd $work &&
    docker build -q --build-arg VERSION=$version -t $image:$arch_tag-arm64 . >/dev/null; s=\$?; rm -rf $work; exit \$s" &
arm=$!
docker build -q --build-arg VERSION="$version" -t "$image:$arch_tag-amd64" . >/dev/null
wait "$arm"
ssh "$ARM_HOST" "docker save $image:$arch_tag-arm64 && docker rmi $image:$arch_tag-arm64 >/dev/null" | docker load -q >/dev/null

docker push -q "$image:$arch_tag-amd64"
docker push -q "$image:$arch_tag-arm64"
for tag in "$@"; do
  docker buildx imagetools create -t "$image:$tag" "$image:$arch_tag-amd64" "$image:$arch_tag-arm64"
done
docker builder prune -f >/dev/null
echo "$image : ${*} (amd64 + arm64, $version)"
