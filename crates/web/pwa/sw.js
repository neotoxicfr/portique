// Service worker minimal : rend l'appli installable et sert la coquille hors ligne (page de
// reconnexion). L'API, le WebSocket et les scripts de préparation ne passent jamais par le cache.
// Changer le nom purge l'ancienne coquille (v1 pouvait resservir une page périmée).
const CACHE = "portique-v3";

// Le serveur répond index.html (200) à toute adresse inconnue : un fichier retiré par un déploiement
// reviendrait en HTML. Gardé sous l'URL du module, il casserait le prochain démarrage hors ligne.
// Le type de média ne tient pas compte de la casse (RFC 9110 8.3.1).
const isHtml = (r) => (r.headers.get("content-type") || "").toLowerCase().startsWith("text/html");

async function asset(url) {
  const r = await fetch(url);
  if (!r.ok || isHtml(r)) throw new Error(`${url} indisponible`);
  return [url, r];
}

// Préchargement : la page, puis chaque fichier généré qu'elle référence (noms empreintés par trunk :
// module wasm, script d'amorce, CSS), pour que la coquille démarre hors ligne dès le premier lancement.
// Tout est vérifié avant la première écriture : un échec laisse le cache et l'ancien worker intacts.
const XTERM = ["/xterm/xterm.js", "/xterm/addon-fit.js", "/xterm/xterm.css"];
async function precache() {
  const page = await fetch("/", { cache: "reload" });
  if (!page.ok) throw new Error("page indisponible");
  const html = await page.clone().text();
  const urls = new Set(["/manifest.webmanifest", "/icon.svg"]);
  for (const m of html.matchAll(/["'(](\/[\w.\-\/]+\.(?:js|wasm|css|png|svg|webmanifest))["')]/g)) urls.add(m[1]);
  const files = await Promise.all([...urls].map(asset));
  const c = await caches.open(CACHE);
  await Promise.all([c.put("/", page), ...files.map(([u, r]) => c.put(u, r))]);
  // Terminal : chargé à la demande, mis en cache en arrière-plan. Une requête lente ou en échec ne retarde pas
  // l'installation ; le gestionnaire fetch le garde aussi quand la page le charge.
  for (const u of XTERM) asset(u).then(([u, r]) => c.put(u, r)).catch(() => {});
}

self.addEventListener("install", (e) => {
  e.waitUntil(precache());
  self.skipWaiting();
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
  );
  self.clients.claim();
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.origin !== location.origin) return;
  if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/setup/")) return;
  // Réseau d'abord (nouvelle version immédiate), cache en secours pour la coquille.
  const navigate = e.request.mode === "navigate";
  const file = /\.(css|js|wasm|svg|png|webmanifest)$/.test(url.pathname);
  e.respondWith(
    fetch(e.request)
      .then(async (r) => {
        // Fichier remplacé par le repli HTML (retiré par un déploiement) ou en erreur : la copie en cache, si
        // elle existe, vaut mieux qu'une page HTML donnée au chargeur d'un module (onglet resté sur l'ancienne
        // version). Un fichier valide du réseau reste préféré.
        if (file && (!r.ok || isHtml(r))) return (await caches.match(e.request)) || r;
        // « / » ne reçoit que la coquille HTML d'une navigation ; un fichier ouvert dans un onglet (icône…)
        // garde sa propre URL.
        const shell = navigate && !file && isHtml(r);
        if (r.ok && (shell || file)) {
          const copy = r.clone();
          caches.open(CACHE).then((c) => c.put(shell ? "/" : e.request, copy));
        }
        return r;
      })
      .catch(() => caches.match(navigate && !file ? "/" : e.request))
  );
});
