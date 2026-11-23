import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const NGSW = (groups: unknown) => JSON.stringify({ index: '/index.html', dataGroups: groups }, null, 2);

describe('NGB032 service worker caches user-specific responses', () => {
  it('reports ngsw dataGroups that cache user endpoints or the whole API', async () => {
    const res = await findings('NGB032', {
      'ngsw-config.json': NGSW([
        { name: 'me', urls: ['/api/me', '/api/profile/**'], cacheConfig: { strategy: 'performance', maxSize: 10, maxAge: '1d' } },
        { name: 'all', urls: ['/api/**'], cacheConfig: { strategy: 'freshness', maxSize: 10, maxAge: '1h' } },
      ]),
      'src/main.ts': 'export {};',
    });
    expect(res.map((r) => r.confidence)).toEqual(['high', 'medium']);
    expect(res[0]!.location.file).toBe('ngsw-config.json');
  });

  it('reports custom service workers (JS) that cache every response', async () => {
    const res = await findings('NGB032', {
      'src/sw.js': `self.addEventListener('fetch', (event) => {
  event.respondWith(fetch(event.request).then((res) => caches.open('rt').then((cache) => { cache.put(event.request, res.clone()); return res; })));
});`,
      'src/main.ts': 'export {};',
    });
    expect(res).toHaveLength(1);
    expect(res[0]!.location.file).toBe('src/sw.js');
  });

  it('safe: public data groups and filtering service workers', async () => {
    expect(await findings('NGB032', {
      'ngsw-config.json': NGSW([{ name: 'catalog', urls: ['/api/catalog/**', 'https://cdn.example.com/**'], cacheConfig: { strategy: 'performance', maxSize: 10, maxAge: '1d' } }]),
      'src/service-worker.js': `self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET' || event.request.headers.has('Authorization')) return;
  event.respondWith(caches.open('rt').then((cache) => fetch(event.request).then((res) => { cache.put(event.request, res.clone()); return res; })));
});`,
      'src/main.ts': 'export {};',
    })).toEqual([]);
  });

  it('false-positive regression: non-service-worker files and generated ngsw-worker.js', async () => {
    expect(await findings('NGB032', {
      'src/app/util.js': `self.addEventListener('fetch', (e) => cache.put(e.request, r));`,
      'src/ngsw-worker.js': `self.addEventListener('fetch', (e) => cache.put(e.request, r));`,
      'src/main.ts': 'export {};',
    })).toEqual([]);
  });
});
