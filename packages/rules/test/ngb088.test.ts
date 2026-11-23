import { describe, expect, it } from 'vitest';
import { findings, one } from './helpers.js';

describe('NGB088 insufficient asymmetric key size', () => {
  it('reports small RSA moduli in Web Crypto, Node and node-forge', async () => {
    const res = await findings('NGB088', {
      'src/app/keys.ts': `const BITS = 1024;
export function gen() {
  return crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: BITS, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
}`,
      'src/server/keys.ts': `import { generateKeyPairSync, createDiffieHellman } from 'crypto';
import forge from 'node-forge';
export function gen() {
  generateKeyPairSync('rsa', { modulusLength: 1536 });
  generateKeyPairSync('ec', { namedCurve: 'secp192k1' });
  generateKeyPairSync('dh', { primeLength: 1024 });
  createDiffieHellman(512);
  return forge.pki.rsa.generateKeyPair({ bits: 1024 });
}`,
    });
    expect(res).toHaveLength(6);
    expect(res.find((r) => r.message.includes('1536'))!.severity).toBe('medium');
    expect(res.filter((r) => r.severity === 'high')).toHaveLength(5);
  });

  it('safe: 2048+ RSA, P-256, Ed25519', async () => {
    expect(await findings('NGB088', {
      'src/server/keys.ts': `import { generateKeyPairSync } from 'node:crypto';
export async function gen() {
  generateKeyPairSync('rsa', { modulusLength: 3072 });
  generateKeyPairSync('ec', { namedCurve: 'P-256' });
  generateKeyPairSync('ed25519');
  await crypto.subtle.generateKey({ name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, false, ['sign']);
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, false, ['sign']);
}`,
    })).toEqual([]);
  });

  it('false-positive regression: AES key lengths and non-crypto generateKeyPair', async () => {
    expect(await one('NGB088', `export const svc = { generateKeyPair(o: { modulusLength: number }) { return o; } };
export async function f() {
  svc.generateKeyPair({ modulusLength: 512 });
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 128 }, false, ['encrypt']);
}`)).toEqual([]);
  });
});
