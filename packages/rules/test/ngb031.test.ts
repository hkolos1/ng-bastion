import { describe, expect, it } from 'vitest';
import { one } from './helpers.js';

describe('NGB031 sensitive data in CacheStorage', () => {
  it('reports caching an authenticated request (high) and a user endpoint (medium)', async () => {
    const res = await one('NGB031', `export async function f(token: string) {
  const cache = await caches.open('api');
  const req = new Request('/api/orders', { headers: { Authorization: 'Bearer ' + token } });
  await cache.put(req, await fetch(req));
  await cache.add('/api/me');
}`);
    expect(res.map((r) => r.confidence).sort()).toEqual(['high', 'medium']);
  });

  it('reports cached response bodies containing credentials and addAll of account URLs', async () => {
    const res = await one('NGB031', `export function f(accessToken: string) {
  caches.open('x').then((c) => {
    c.put('/session-cache', new Response(JSON.stringify({ accessToken })));
    c.addAll(['/assets/logo.svg', '/api/account']);
  });
}`);
    expect(res).toHaveLength(2);
  });

  it('safe: static assets', async () => {
    expect(await one('NGB031', `export async function f() { const c = await caches.open('static'); await c.addAll(['/assets/i18n/en.json', '/favicon.ico']); await c.add('/api/catalog'); }`)).toEqual([]);
  });

  it('false-positive regression: non-Cache put/add calls', async () => {
    expect(await one('NGB031', `const m = new Map(); const s = new Set<string>(); export function f(accessToken: string) { m.set('/api/me', accessToken); s.add('/api/me'); }`)).toEqual([]);
  });
});
