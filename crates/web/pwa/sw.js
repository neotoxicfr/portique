// Service worker minimal : rend l'appli installable et sert la coquille hors ligne (page de
// reconnexion). L'API, le WebSocket et les scripts de préparation ne passent jamais par le cache.
const CACHE = "yawrdp-v1";

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(["/", "/manifest.webmanifest", "/icon.svg"])));
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
