/**
 * BijliTracker Pro — Service Worker
 * Provides basic offline caching for static assets.
 * Place this file at your web root alongside index.html.
 */

const CACHE_NAME = 'bijlitracker-v1';
const STATIC_URLS = [
  '/',
  '/index.html',
  '/manifest.json',
];

// Install: cache static assets
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(STATIC_URLS))
  );
  self.skipWaiting();
});

// Activate: clean old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Fetch: network-first, cache fallback for navigation
self.addEventListener('fetch', event => {
  const { request } = event;
  // Only cache GET requests
  if (request.method !== 'GET') return;
  // Skip API calls — always go network
  if (request.url.includes('/api/')) return;

  event.respondWith(
    fetch(request)
      .then(response => {
        // Cache valid responses
        if (response && response.status === 200) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(request, clone));
        }
        return response;
      })
      .catch(() => caches.match(request))
  );
});
