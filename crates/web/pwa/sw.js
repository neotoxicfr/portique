// Service worker minimal : rend l'appli installable et sert la coquille hors ligne (page de
// reconnexion). L'API, le WebSocket et les scripts de préparation ne passent jamais par le cache.
// Changer le nom purge l'ancienne coquille (v1 pouvait resservir une page périmée).
const CACHE = "portique-v3";

// Préchargement : la page, puis chaque fichier généré qu'elle référence (noms empreintés par trunk :
// module wasm, script d'amorce, CSS), pour que la coquille démarre hors ligne dès le premier lancement.
async function precache() {
  const c = await caches.open(CACHE);
  const page = await fetch("/", { cache: "reload" });
  if (!page.ok) throw new Error("page indisponible");
  await c.put("/", page.clone());
  const html = await page.text();
  const urls = new Set(["/manifest.webmanifest", "/icon.svg"]);
  for (const m of html.matchAll(/["'(](\/[\w.\-\/]+\.(?:js|wasm|css|png|svg|webmanifest))["')]/g)) urls.add(m[1]);
  await c.addAll([...urls]);
  // Terminal : chargé à la demande, absent n'empêche pas l'installation.
  await Promise.allSettled(["/xterm/xterm.js", "/xterm/addon-fit.js", "/xterm/xterm.css"].map((u) => c.add(u)));
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
        if (r.ok && (e.request.mode === "navigate" || /\.(css|js|wasm|svg|png|webmanifest)$/.test(url.pathname))) {
          const copy = r.clone();
          caches.open(CACHE).then((c) => c.put(e.request.mode === "navigate" ? "/" : e.request, copy));
        }
        return r;
      })
      .catch(() => caches.match(e.request.mode === "navigate" ? "/" : e.request))
  );
});
