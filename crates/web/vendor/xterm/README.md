# xterm.js (vendored)

Terminal du client SSH, servi par Portique lui-même : aucun CDN, compatible avec la CSP (`script-src 'self'`).

| Fichier | Paquet npm | Version |
|---|---|---|
| `xterm.js` (UMD, `lib/xterm.js`), `xterm.css` | `@xterm/xterm` | 6.0.0 |
| `addon-fit.js` (UMD, `lib/addon-fit.js`) | `@xterm/addon-fit` | 0.11.0 |

Ces fichiers ne sont pas suivis par Git : `scripts/vendor-xterm.sh` les télécharge depuis le registre npm et
vérifie le champ `integrity` (SHA-512) figé dans le script ; seule la ligne `sourceMappingURL` est retirée des
scripts. `scripts/ci.sh` et le Dockerfile l'appellent avant `trunk build`. Licence MIT (`LICENSE`, celle de
xterm.js, vaut pour les deux paquets).

Mise à jour : changer versions, adresses et empreintes dans `scripts/vendor-xterm.sh`, puis ce tableau.
