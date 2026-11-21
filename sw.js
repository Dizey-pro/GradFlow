/* GradeFlow service worker
 * Bump VERSION on every release: old caches are deleted on activate.
 * Strategy:
 *   - Navigations (HTML):    network-first (4s timeout) -> cached shell fallback
 *   - Same-origin static:    stale-while-revalidate
 *   - Allow-listed CDNs/fonts/Firebase SDK scripts: stale-while-revalidate
 *   - Everything else (payment API, Firestore, Auth, EmailJS, /__/auth, non-GET): NOT intercepted
 */
const VERSION = 'v1.0.0';
const SHELL_CACHE = `gradeflow-shell-${VERSION}`;
const STATIC_CACHE = `gradeflow-static-${VERSION}`;

const SHELL_URLS = [
  './',
  './index.html',
  './manifest.json',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/maskable-192.png',
  './icons/maskable-512.png',
  './icons/apple-touch-icon.png',
  './icons/favicon-32.png',
  './icons/icon.svg'
];

// Third-party hosts that serve versioned, public, non-sensitive static assets.
const CDN_ALLOW = [
  { host: 'cdn.tailwindcss.com' },
  { host: 'cdnjs.cloudflare.com' },
  { host: 'cdn.jsdelivr.net' },
  { host: 'fonts.googleapis.com' },
  { host: 'fonts.gstatic.com' },
  { host: 'www.gstatic.com', pathPrefix: '/firebasejs/' } // SDK scripts only, not Firestore/Auth traffic
];

// Hosts/paths that must always go straight to the network.
const NEVER_CACHE_HOSTS = [
  'gradeflow-pay.netlify.app',   // API_BASE (payments)
  'firestore.googleapis.com',
  'identitytoolkit.googleapis.com',
  'securetoken.googleapis.com',
  'api.emailjs.com',
  'finivex'                      // any Finivex host (substring match)
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(SHELL_CACHE).then((cache) =>
      // Tolerate a missing optional file so one 404 can't block install.
      Promise.all(SHELL_URLS.map((u) => cache.add(new Request(u, { cache: 'reload' })).catch(() => {})))
    )
  );
  // No skipWaiting() here: the page shows "Update available" and asks the user (see SKIP_WAITING below).
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keep = new Set([SHELL_CACHE, STATIC_CACHE]);
    const keys = await caches.keys();
    await Promise.all(keys.filter((k) => k.startsWith('gradeflow-') && !keep.has(k)).map((k) => caches.delete(k)));
    if (self.registration.navigationPreload) { try { await self.registration.navigationPreload.enable(); } catch (e) {} }
    await self.clients.claim();
  })());
});

self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') self.skipWaiting();
  if (event.data && event.data.type === 'GET_VERSION' && event.source) event.source.postMessage({ type: 'VERSION', version: VERSION });
});

function allowedCdn(url) {
  return CDN_ALLOW.some((r) => url.hostname === r.host && (!r.pathPrefix || url.pathname.startsWith(r.pathPrefix)));
}
function neverCache(url) {
  if (url.pathname.startsWith('/__/')) return true; // Firebase Auth helper pages on same origin
  return NEVER_CACHE_HOSTS.some((h) => url.hostname.includes(h));
}

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;                       // never touch writes
  const url = new URL(req.url);
  if (!/^https?:$/.test(url.protocol)) return;
  if (neverCache(url)) return;
  if (req.headers.has('authorization')) return;           // never cache authenticated requests

  // 1) Navigations: network-first, offline fallback to the cached shell
  if (req.mode === 'navigate') {
    if (url.origin !== self.location.origin) return;
    event.respondWith(networkFirstNavigation(event));
    return;
  }

  // 2) Same-origin static assets and allow-listed CDNs: stale-while-revalidate
  if (url.origin === self.location.origin || allowedCdn(url)) {
    if (url.pathname.endsWith('/sw.js')) return;
    event.respondWith(staleWhileRevalidate(req));
  }
  // anything else: default browser behaviour
});

async function networkFirstNavigation(event) {
  const cache = await caches.open(SHELL_CACHE);
  try {
    const preload = event.preloadResponse ? await event.preloadResponse : null;
    const res = preload || await timeout(fetch(event.request), 4000);
    if (res && res.ok) cache.put('./index.html', res.clone()); // ?payment=... etc. all refresh the same shell
    return res;
  } catch (err) {
    const cached = (await cache.match('./index.html')) || (await cache.match('./'));
    if (cached) return cached;
    return new Response(
      '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
      '<body style="font-family:system-ui;background:#0f172a;color:#f8fafc;display:grid;place-items:center;min-height:100vh;margin:0;text-align:center;padding:1.5rem">' +
      '<div><h1 style="font-size:1.4rem">You\'re offline</h1><p style="color:#94a3b8">GradeFlow hasn\'t been saved on this device yet. Reconnect and reload.</p></div>',
      { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
    );
  }
}

async function staleWhileRevalidate(req) {
  const cache = await caches.open(STATIC_CACHE);
  const cached = await cache.match(req);
  const network = fetch(req).then((res) => {
    // Opaque (status 0) responses come from cross-origin <script>/<link> without CORS; they're safe to store.
    if (res && (res.ok || res.type === 'opaque')) cache.put(req, res.clone());
    return res;
  }).catch(() => null);
  if (cached) { network.catch(() => {}); return cached; }
  const res = await network;
  return res || new Response('', { status: 504, statusText: 'Offline' });
}

function timeout(promise, ms) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('timeout')), ms);
    promise.then((v) => { clearTimeout(t); resolve(v); }, (e) => { clearTimeout(t); reject(e); });
  });
}
