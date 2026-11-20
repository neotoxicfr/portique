#!/usr/bin/env bash
# Télécharge xterm.js et son extension d'ajustement depuis le registre npm, vérifie leur intégrité
# (SHA-512 publiée par npm, figée ici) et les place dans crates/web/vendor/xterm/ (ignoré par Git).
# Appelé par scripts/ci.sh et le Dockerfile avant `trunk build`. Mise à jour : changer versions et empreintes.
set -euo pipefail
cd "$(dirname "$0")/.."
dest=crates/web/vendor/xterm
pkgs=(
  "https://registry.npmjs.org/@xterm/xterm/-/xterm-6.0.0.tgz sha512-TQwDdQGtwwDt+2cgKDLn0IRaSxYu1tSUjgKarSDkUM0ZNiSRXFpjxEsvc/Zgc5kq5omJ+V0a8/kIM2WD3sMOYg=="
  "https://registry.npmjs.org/@xterm/addon-fit/-/addon-fit-0.11.0.tgz sha512-jYcgT6xtVYhnhgxh3QgYDnnNMYTcf8ElbxxFzX0IZo+vabQqSPAjC3c1wJrKB5E19VwQei89QCiZZP86DCPF7g=="
)
[[ -s $dest/xterm.js && -s $dest/addon-fit.js && -s $dest/xterm.css ]] && exit 0
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
grep -v '^//# sourceMappingURL=' "$tmp/xterm-6.0.0.tgz.d/package/lib/xterm.js" > "$dest/xterm.js"
grep -v '^//# sourceMappingURL=' "$tmp/addon-fit-0.11.0.tgz.d/package/lib/addon-fit.js" > "$dest/addon-fit.js"
cp "$tmp/xterm-6.0.0.tgz.d/package/css/xterm.css" "$dest/xterm.css"
cp "$tmp/xterm-6.0.0.tgz.d/package/LICENSE" "$dest/LICENSE"
echo "xterm.js 6.0.0 + addon-fit 0.11.0 vérifiés dans $dest"
