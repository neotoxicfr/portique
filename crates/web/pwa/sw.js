// Service worker minimal : rend l'appli installable et sert la coquille hors ligne (page de
// reconnexion). L'API, le WebSocket et les scripts de préparation ne passent jamais par le cache.
// Changer le nom purge l'ancienne coquille (v1 pouvait resservir une page périmée).
const CACHE = "portique-v3";

// Le serveur répond index.html (200) à toute adresse inconnue : un fichier retiré par un déploiement
// reviendrait en HTML. Gardé sous l'URL du module, il casserait le prochain démarrage hors ligne.
const isHtml = (r) => (r.headers.get("content-type") || "").startsWith("text/html");

async function asset(url) {
  const r = await fetch(url);
  if (!r.ok || isHtml(r)) throw new Error(`${url} indisponible`);
  return [url, r];
}

// Préchargement : la page, puis chaque fichier généré qu'elle référence (noms empreintés par trunk :
// module wasm, script d'amorce, CSS), pour que la coquille démarre hors ligne dès le premier lancement.
// Tout est vérifié avant la première écriture : un échec laisse le cache et l'ancien worker intacts.
async function precache() {
  const page = await fetch("/", { cache: "reload" });
  if (!page.ok) throw new Error("page indisponible");
  const html = await page.clone().text();
  const urls = new Set(["/manifest.webmanifest", "/icon.svg"]);
  for (const m of html.matchAll(/["'(](\/[\w.\-\/]+\.(?:js|wasm|css|png|svg|webmanifest))["')]/g)) urls.add(m[1]);
  const files = await Promise.all([...urls].map(asset));
  // Terminal : chargé à la demande, absent n'empêche pas l'installation.
  const xterm = await Promise.allSettled(["/xterm/xterm.js", "/xterm/addon-fit.js", "/xterm/xterm.css"].map(asset));
  for (const x of xterm) if (x.status === "fulfilled") files.push(x.value);
  const c = await caches.open(CACHE);
  await Promise.all([c.put("/", page), ...files.map(([u, r]) => c.put(u, r))]);
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
  e.respondWith(
    fetch(e.request)
      .then((r) => {
        const shell = e.request.mode === "navigate" || (/\.(css|js|wasm|svg|png|webmanifest)$/.test(url.pathname) && !isHtml(r));
        if (r.ok && shell) {
          const copy = r.clone();
          caches.open(CACHE).then((c) => c.put(e.request.mode === "navigate" ? "/" : e.request, copy));
        }
        return r;
      })
      .catch(() => caches.match(e.request.mode === "navigate" ? "/" : e.request))
  );
});
