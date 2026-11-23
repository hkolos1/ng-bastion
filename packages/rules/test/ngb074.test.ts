import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

describe('NGB074 service worker caches unvalidated responses', () => {
  it('reports cache.put() of responses that were never checked', async () => {
    const res = await findings('NGB074', {
      'src/sw.js': `self.addEventListener('fetch', (event) => {
  event.respondWith(caches.open('runtime').then(async (cache) => {
    const res = await fetch(event.request);
    cache.put(event.request, res.clone());
    return res;
  }));
});`,
    });
    expect(res).toHaveLength(1);
    expect(res[0]!.location.file).toBe('src/sw.js');
  });

  it('safe: ok / status / type checks, synthesized responses, cache.add', async () => {
    expect(await findings('NGB074', {
      'src/sw.js': `self.addEventListener('fetch', (event) => {
  event.respondWith(caches.open('rt').then(async (cache) => {
    const res = await fetch(event.request);
    if (res.ok && res.type === 'basic') cache.put(event.request, res.clone());
    return res;
  }));
});
self.addEventListener('install', (e) => e.waitUntil(caches.open('v1').then((c) => { c.addAll(['/']); c.put('/offline', new Response('offline')); })));`,
    })).toEqual([]);
  });

  it('false-positive regression: IndexedDB put and non-worker files', async () => {
    expect(await findings('NGB074', {
      'src/sw.js': `self.addEventListener('sync', () => { const store = db.transaction('q', 'readwrite').objectStore('q'); store.put({ a: 1 }, 'k'); });`,
      'src/app/cache.ts': `export async function f(cache: Cache, r: Request) { cache.put(r, await fetch(r)); }`,
    })).toEqual([]);
  });
});
