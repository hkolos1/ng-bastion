/// <reference lib="webworker" />
// Custom service worker (synthetic; never deployed).
declare const self: ServiceWorkerGlobalScope;
let accessToken = '';

self.addEventListener('message', (event) => {
  if (event.data?.type === 'token') accessToken = event.data.token;
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  // NGB072: the bearer token is attached to every request, including third-party hosts.
  const authed = new Request(event.request, { headers: { Authorization: `Bearer ${accessToken}` } });
  event.respondWith(caches.open('runtime').then(async (cache) => {
    const response = await fetch(authed);
    // NGB074: error pages and opaque responses are cached and replayed.
    await cache.put(event.request, response.clone());
    return response;
  }));
});
