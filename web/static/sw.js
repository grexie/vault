const CACHE = "remote-ssh-v1";
const ASSETS = [
  "/",
  "/index.html",
  "/app.css",
  "/app.js",
  "/crypto.js",
  "/favicon-32.png",
  "/icon-180.png",
  "/icon-192.png",
  "/manifest.webmanifest",
];
self.addEventListener("install", (event) =>
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(ASSETS))),
);
self.addEventListener("activate", (event) =>
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys.filter((key) => key !== CACHE).map((key) => caches.delete(key)),
        ),
      ),
  ),
);
self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (
    event.request.method !== "GET" ||
    url.origin !== self.location.origin ||
    url.pathname.startsWith("/api/") ||
    url.pathname.startsWith("/v1/")
  )
    return;
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request)),
  );
});
self.addEventListener("push", (event) =>
  event.waitUntil(
    (async () => {
      let data = {};
      try {
        data = event.data?.json() || {};
      } catch {}
      const id = /^[A-Za-z0-9_-]{43}$/.test(data.requestId || "")
        ? data.requestId
        : "";
      await self.registration.showNotification("SSH access requested", {
        body: "Open Remote SSH Agent to review and approve.",
        icon: "/icon-192.png",
        badge: "/icon-192.png",
        tag: id || "ssh-request",
        data: { url: id ? "/?request=" + id : "/" },
      });
    })(),
  ),
);
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(
    (async () => {
      const path = event.notification.data?.url || "/";
      const windows = await self.clients.matchAll({
        type: "window",
        includeUncontrolled: true,
      });
      for (const window of windows) {
        if (new URL(window.url).origin === self.location.origin) {
          await window.navigate(path);
          return window.focus();
        }
      }
      return self.clients.openWindow(path);
    })(),
  );
});
