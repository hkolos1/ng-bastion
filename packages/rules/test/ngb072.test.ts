import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

describe('NGB072 service worker attaches credentials to any origin', () => {
  it('reports fetch handlers that add Authorization or credentials to every request', async () => {
    const res = await findings('NGB072', {
      'src/sw.js': `let token;
self.addEventListener('fetch', (event) => {
  event.respondWith(fetch(new Request(event.request, { headers: { Authorization: 'Bearer ' + token } })));
});`,
      'src/app/service-worker.ts': `declare const self: any;
self.onfetch = function (e: any) {
  const headers = new Headers(e.request.headers);
  headers.set('X-Api-Key', 'k');
  e.respondWith(fetch(e.request.url, { headers, credentials: 'include' }));
};`,
    });
    expect(res).toHaveLength(2);
    expect(res[0]!.confidence).toBe('high');
  });

  it('safe: handlers that check the destination origin first', async () => {
    expect(await findings('NGB072', {
      'src/sw.js': `const API = 'https://api.example.com';
self.addEventListener('fetch', (event) => {
  if (new URL(event.request.url).origin !== API) return;
  event.respondWith(fetch(new Request(event.request, { headers: { Authorization: 'Bearer ' + self.token } })));
});
self.addEventListener('fetch', (e) => { if (!e.request.url.startsWith(API)) return; e.respondWith(fetch(e.request, { credentials: 'include' })); });`,
    })).toEqual([]);
  });

  it('false-positive regression: Authorization headers outside service workers and handlers without credentials', async () => {
    expect(await findings('NGB072', {
      'src/app/api.ts': `export const f = (t: string) => fetch('/api', { headers: { Authorization: t } });`,
      'src/sw.js': `self.addEventListener('fetch', (e) => e.respondWith(caches.match(e.request).then((r) => r || fetch(e.request))));`,
    })).toEqual([]);
  });
});
