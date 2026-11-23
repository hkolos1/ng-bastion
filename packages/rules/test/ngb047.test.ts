import { describe, expect, it } from 'vitest';
import { one } from './helpers.js';

describe('NGB047 static IV in Web Crypto encryption', () => {
  it('reports constant AES-GCM IVs (high) and zero-filled CBC IVs (medium severity)', async () => {
    const res = await one('NGB047', `const IV = new TextEncoder().encode('0123456789ab');
export async function enc(key: CryptoKey, data: ArrayBuffer) {
  await crypto.subtle.encrypt({ name: 'AES-GCM', iv: IV }, key, data);
  await crypto.subtle.encrypt({ name: 'AES-CBC', iv: new Uint8Array(16) }, key, data);
}`);
    expect(res.map((r) => r.severity).sort()).toEqual(['high', 'medium']);
    expect(res.every((r) => r.confidence === 'high')).toBe(true);
  });

  it('reports a random IV created once at module level and reused (medium confidence)', async () => {
    const res = await one('NGB047', `const iv = crypto.getRandomValues(new Uint8Array(12));
export function enc(key: CryptoKey, data: ArrayBuffer) { return crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data); }`);
    expect(res).toHaveLength(1);
    expect(res[0]!.confidence).toBe('medium');
  });

  it('safe: fresh IV per call', async () => {
    expect(await one('NGB047', `export async function enc(key: CryptoKey, data: ArrayBuffer) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const alg = { name: 'AES-GCM', iv };
  return { iv, ct: await crypto.subtle.encrypt(alg, key, data) };
}`)).toEqual([]);
  });

  it('false-positive regression: RSA-OAEP and non-SubtleCrypto encrypt()', async () => {
    expect(await one('NGB047', `const enc = { encrypt: (_a: object) => 0 };
export function f(key: CryptoKey, data: ArrayBuffer) { crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, data); enc.encrypt({ name: 'AES-GCM', iv: new Uint8Array(12) }); }`)).toEqual([]);
  });
});
