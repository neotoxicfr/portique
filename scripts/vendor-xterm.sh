#!/usr/bin/env bash
# Télécharge xterm.js et son extension d'ajustement depuis le registre npm, vérifie leur intégrité
# (SHA-512 publiée par npm, figée ici) et les place dans crates/web/vendor/xterm/ (ignoré par Git).
# Appelé par scripts/ci.sh et le Dockerfile avant `trunk build`. Mise à jour : changer versions et empreintes.
set -euo pipefail
# Deux exécutions sur le même dossier (CI locale lancée deux fois, agents en parallèle) : la seconde attend la
# première, sinon elle validerait le cache pendant que l'autre réécrit les fichiers. Verrou sur le script
# lui-même : aucun fichier de plus dans le dossier copié par trunk.
exec 9<"$0"
flock 9
cd "$(dirname "$0")/.."
dest=crates/web/vendor/xterm
pkgs=(
  "https://registry.npmjs.org/@xterm/xterm/-/xterm-6.0.0.tgz sha512-TQwDdQGtwwDt+2cgKDLn0IRaSxYu1tSUjgKarSDkUM0ZNiSRXFpjxEsvc/Zgc5kq5omJ+V0a8/kIM2WD3sMOYg=="
  "https://registry.npmjs.org/@xterm/addon-fit/-/addon-fit-0.11.0.tgz sha512-jYcgT6xtVYhnhgxh3QgYDnnNMYTcf8ElbxxFzX0IZo+vabQqSPAjC3c1wJrKB5E19VwQei89QCiZZP86DCPF7g=="
)
# Cache valable seulement pour ces versions et empreintes (`.pkgs` écrit après une installation complète).
want_pkgs=$(printf '%s\n' "${pkgs[@]}")
[[ -s $dest/xterm.js && -s $dest/addon-fit.js && -s $dest/xterm.css && $(cat "$dest/.pkgs" 2>/dev/null) == "$want_pkgs" ]] && exit 0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
for p in "${pkgs[@]}"; do
  url=${p% *} want=${p#* }
  f=$tmp/$(basename "$url")
  curl -fsSL -o "$f" "$url"
  got="sha512-$(openssl dgst -sha512 -binary "$f" | base64 -w0)"
  [[ $got == "$want" ]] || { echo "intégrité invalide pour $url" >&2; exit 1; }
  mkdir -p "$f.d" && tar -xzf "$f" -C "$f.d"
done
# Builds UMD (variables globales Terminal et FitAddon), sans la ligne sourceMappingURL.
rm -f "$dest/.pkgs"   # une copie interrompue ne doit pas passer pour une installation complète
grep -v '^//# sourceMappingURL=' "$tmp/xterm-6.0.0.tgz.d/package/lib/xterm.js" > "$dest/xterm.js"
grep -v '^//# sourceMappingURL=' "$tmp/addon-fit-0.11.0.tgz.d/package/lib/addon-fit.js" > "$dest/addon-fit.js"
cp "$tmp/xterm-6.0.0.tgz.d/package/css/xterm.css" "$dest/xterm.css"
cp "$tmp/xterm-6.0.0.tgz.d/package/LICENSE" "$dest/LICENSE"
printf '%s\n' "$want_pkgs" > "$dest/.pkgs"
echo "xterm.js 6.0.0 + addon-fit 0.11.0 vérifiés dans $dest"
