const APP_CACHE = 'wireless-terminal-app-v8';
const STATIC_CACHE = 'wireless-terminal-static-v8';
const THIRD_PARTY_CACHE = 'wireless-terminal-third-party-v8';
const KNOWN_CACHES = [APP_CACHE, STATIC_CACHE, THIRD_PARTY_CACHE];

const APP_SHELL = [
  './',
  './index.html',
  './offline.html',
  './files/Oyetoke_Adedayo_CV.pdf',
  './files/glow.png',
  './files/elite.png',
  './files/ikere.png',
  './manifest.webmanifest',
  './robots.txt',
  './sitemap.xml',
  './assets/i18n.js',
  './social-preview.jpg',
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

const MANNARISE_PORTFOLIO_SCRIPT = `
<script>
(() => {
  const addMannaRiseProject = () => {
    if (document.querySelector('[data-project="mannarise"]')) return;

    const projectsSection = document.querySelector('#projects');
    if (!projectsSection) return;

    const projectGrid = projectsSection.querySelector('.grid') || projectsSection.querySelector('[class*="grid"]');
    if (!projectGrid) return;

    const card = document.createElement('article');
    card.dataset.project = 'mannarise';
    card.setAttribute('data-reveal', 'up');
    card.style.setProperty('--project-rgb', '22, 101, 52');
    card.className = 'project-card flex h-full flex-col rounded-2xl border border-stone-200 bg-white p-5 shadow-sm';

    card.innerHTML = `
      <div class="project-preview mb-5">
        <div class="project-preview-art">
          <div class="project-preview-grid"></div>
          <div class="project-preview-shell">
            <div class="project-preview-dots"><span></span><span></span><span></span></div>
            <div class="project-preview-panel project-preview-panel-one"></div>
            <div class="project-preview-panel project-preview-panel-two"></div>
            <div class="project-preview-panel project-preview-panel-three"></div>
          </div>
        </div>
      </div>
      <div class="flex flex-1 flex-col">
        <p class="mb-2 text-sm font-bold uppercase tracking-[0.18em] text-emerald-700">Faith-Based Platform</p>
        <h3 class="font-display text-xl font-semibold text-zinc-900">MannaRise</h3>
        <p class="mt-3 flex-1 text-sm leading-6 text-zinc-600">Laravel-powered devotional web application for daily devotionals, audio messages, and faith-based content delivery through a clean, responsive, database-driven experience.</p>
        <div class="project-stack mt-5">
          <span class="project-stack-tag" style="--tag-delay: 0ms">Laravel</span>
          <span class="project-stack-tag" style="--tag-delay: 80ms">MySQL</span>
          <span class="project-stack-tag" style="--tag-delay: 160ms">Audio Content</span>
          <span class="project-stack-tag" style="--tag-delay: 240ms">SEO</span>
        </div>
        <a href="https://mannarise.ct.ws/" target="_blank" rel="noopener noreferrer" class="project-link mt-6 text-sm font-bold text-emerald-700 hover:text-emerald-800">
          Visit Website <span class="project-link-arrow">&rarr;</span>
        </a>
      </div>
    `;

    projectGrid.appendChild(card);

    if ('IntersectionObserver' in window) {
      const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('is-visible');
            observer.unobserve(entry.target);
          }
        });
      }, { threshold: 0.15 });

      observer.observe(card);
    } else {
      card.classList.add('is-visible');
    }
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', addMannaRiseProject);
  } else {
    addMannaRiseProject();
  }
})();
</script>`;

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
      const responseToReturn = await injectMannaRiseProject(networkResponse.clone());
      const appCache = await caches.open(APP_CACHE);
      await appCache.put(request, responseToReturn.clone());
      return responseToReturn;
    }
    return networkResponse;
  } catch (error) {
    const cachedResponse =
      (await caches.match(request)) ||
      (await caches.match('./index.html')) ||
      (await caches.match('./offline.html'));

    if (cachedResponse) {
      return injectMannaRiseProject(cachedResponse);
    }

    return Response.error();
  }
}

async function injectMannaRiseProject(response) {
  const contentType = response.headers.get('content-type') || '';

  if (!contentType.includes('text/html')) {
    return response;
  }

  const html = await response.text();

  if (html.includes('data-project="mannarise"') || !html.includes('</body>')) {
    return new Response(html, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers
    });
  }

  const enhancedHtml = html.replace('</body>', `${MANNARISE_PORTFOLIO_SCRIPT}\n</body>`);
  const headers = new Headers(response.headers);
  headers.set('content-type', 'text/html; charset=utf-8');

  return new Response(enhancedHtml, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
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
