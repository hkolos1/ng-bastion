import { describe, expect, it } from 'vitest';
import { findings, one } from './helpers.js';

describe('NGB048 weak hash algorithm', () => {
  it('reports MD5 password hashing (high) and SHA-1 integrity digests (medium)', async () => {
    const res = await one('NGB048', `import CryptoJS from 'crypto-js';
export async function f(password: string, payload: ArrayBuffer) {
  const hashed = CryptoJS.MD5(password).toString();
  const signature = await crypto.subtle.digest('SHA-1', payload);
  return [hashed, signature];
}`);
    expect(res.map((r) => r.severity).sort()).toEqual(['high', 'medium']);
  });

  it('reports SHA-1 signing keys and Node createHash in SSR', async () => {
    const res = await findings('NGB048', {
      'src/app/k.ts': `export function k(raw: ArrayBuffer) { return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']); }`,
      'src/server.ts': `import { createHash } from 'node:crypto';\nexport function verifyToken(token: string) { return createHash('sha1').update(token).digest('hex'); }`,
    });
    expect(res).toHaveLength(2);
  });

  it('safe: SHA-256 and non-security MD5 (Gravatar, cache keys)', async () => {
    expect(await one('NGB048', `import md5 from 'md5';
export async function f(email: string, body: ArrayBuffer) {
  const avatar = 'https://www.gravatar.com/avatar/' + md5(email);
  const cacheKey = md5(JSON.stringify(body));
  const digest = await crypto.subtle.digest('SHA-256', body);
  return [avatar, cacheKey, digest];
}`)).toEqual([]);
  });

  it('false-positive regression: project functions named MD5', async () => {
    expect(await one('NGB048', `function MD5(x: string) { return x; } export function f(password: string) { return MD5(password); }`)).toEqual([]);
  });
});
