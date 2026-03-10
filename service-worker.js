const APP_CACHE = 'wireless-app-v1';
const STATIC_CACHE = 'wireless-static-v1';
const THIRD_PARTY_CACHE = 'wireless-third-party-v1';
const KNOWN_CACHES = [APP_CACHE, STATIC_CACHE, THIRD_PARTY_CACHE];

const APP_SHELL = [
  './',
  './index.html',
  './offline.html',
  './manifest.webmanifest',
  './robots.txt',
  './sitemap.xml',
  './social-preview.svg',
  './icons/icon.svg',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/icon-maskable-512.png',
  './icons/apple-touch-icon.png',
  './icons/favicon-32.png',
  './icons/favicon-16.png'
];

const THIRD_PARTY_ASSETS = [
  'https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;700&family=Sora:wght@500;600;700;800&display=swap',
  'https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/webfonts/fa-brands-400.woff2',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/webfonts/fa-regular-400.woff2',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/webfonts/fa-solid-900.woff2',
  'https://cdn.tailwindcss.com',
  'https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      const appCache = await caches.open(APP_CACHE);
      await appCache.addAll(APP_SHELL);

      const thirdPartyCache = await caches.open(THIRD_PARTY_CACHE);
      await Promise.all(
        THIRD_PARTY_ASSETS.map(async (url) => {
          try {
            const response = await fetch(url, { mode: 'no-cors', cache: 'no-cache' });
            await thirdPartyCache.put(url, response);
          } catch (error) {
            // Third-party assets should not block install.
          }
        })
      );

      await self.skipWaiting();
    })()
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const cacheNames = await caches.keys();
      await Promise.all(
        cacheNames
          .filter((cacheName) => !KNOWN_CACHES.includes(cacheName))
          .map((cacheName) => caches.delete(cacheName))
      );

      await self.clients.claim();
    })()
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;

  if (request.method !== 'GET') {
    return;
  }

  if (request.mode === 'navigate') {
    event.respondWith(handleNavigationRequest(request));
    return;
  }

  const requestUrl = new URL(request.url);

  if (requestUrl.origin === self.location.origin) {
    event.respondWith(cacheFirst(request, STATIC_CACHE));
    return;
  }

  event.respondWith(staleWhileRevalidate(request, THIRD_PARTY_CACHE));
});

async function handleNavigationRequest(request) {
  try {
    const networkResponse = await fetch(request);
    if (networkResponse && networkResponse.ok) {
      const appCache = await caches.open(APP_CACHE);
      await appCache.put(request, networkResponse.clone());
    }
    return networkResponse;
  } catch (error) {
    const cachedResponse =
      (await caches.match(request)) ||
      (await caches.match('./index.html')) ||
      (await caches.match('./offline.html'));

    return cachedResponse || Response.error();
  }
}

async function cacheFirst(request, cacheName) {
  const cachedResponse = await caches.match(request);
  if (cachedResponse) {
    return cachedResponse;
  }

  try {
    const networkResponse = await fetch(request);
    if (networkResponse && networkResponse.ok) {
      const cache = await caches.open(cacheName);
      cache.put(request, networkResponse.clone());
    }
    return networkResponse;
  } catch (error) {
    if (request.destination === 'document') {
      return (await caches.match('./offline.html')) || Response.error();
    }

    return cachedResponse || Response.error();
  }
}

async function staleWhileRevalidate(request, cacheName) {
  const cache = await caches.open(cacheName);
  const cachedResponse = await cache.match(request);

  const networkPromise = fetch(request, request.mode === 'no-cors' ? { mode: 'no-cors' } : undefined)
    .then((response) => {
      if (response && (response.ok || response.type === 'opaque')) {
        cache.put(request, response.clone());
      }
      return response;
    })
    .catch(() => null);

  return cachedResponse || (await networkPromise) || Response.error();
}
