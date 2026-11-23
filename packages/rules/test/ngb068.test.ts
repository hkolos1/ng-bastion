import { describe, expect, it } from 'vitest';
import { findings, one } from './helpers.js';

describe('NGB068 hardcoded cryptographic key', () => {
  it('reports constant keys in Web Crypto and CryptoJS', async () => {
    const res = await one('NGB068', `import CryptoJS from 'crypto-js';
const KEY = 'k3y-0123456789ab';
export async function f(data: string) {
  await crypto.subtle.importKey('raw', new TextEncoder().encode(KEY), 'AES-GCM', false, ['encrypt']);
  await crypto.subtle.importKey('jwk', { kty: 'oct', k: 'c2VjcmV0LWtleQ' }, 'AES-GCM', false, ['encrypt']);
  await crypto.subtle.importKey('raw', new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]), 'AES-GCM', false, ['encrypt']);
  CryptoJS.AES.encrypt(data, 'my passphrase');
  CryptoJS.HmacSHA256(data, CryptoJS.enc.Utf8.parse('hmac-key'));
}`);
    expect(res).toHaveLength(5);
    expect(res.every((f) => f.snippet === undefined)).toBe(true);
    expect(res[0]!.evidence.join(' ')).not.toContain('0123456789');
  });

  it('reports constant keys in Node crypto and jsonwebtoken', async () => {
    const res = await findings('NGB068', {
      'src/server.ts': `import { createCipheriv, createHmac } from 'node:crypto';
import jwt from 'jsonwebtoken';
export function f(iv: Buffer, body: string) {
  createCipheriv('aes-256-gcm', Buffer.from('0123456789abcdef0123456789abcdef'), iv);
  createHmac('sha256', 'webhook-secret').update(body).digest('hex');
  return jwt.sign({ sub: '1' }, 'jwt-secret');
}`,
    });
    expect(res).toHaveLength(3);
  });

  it('safe: generated keys, keys from environment / parameters, public keys', async () => {
    expect(await findings('NGB068', {
      'src/app/a.ts': `export async function f(raw: ArrayBuffer, spki: ArrayBuffer) {
  await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
  await crypto.subtle.importKey('spki', spki, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
}`,
      'src/server.ts': `import { createHmac } from 'crypto';
import jwt from 'jsonwebtoken';
export function g(body: string) { createHmac('sha256', process.env['WEBHOOK_SECRET']!).update(body); return jwt.sign({}, process.env['JWT_SECRET']!); }`,
    })).toEqual([]);
  });

  it('false-positive regression: project encrypt() / sign() helpers and non-crypto parse()', async () => {
    expect(await one('NGB068', `const AES = { encrypt: (d: string, k: string) => d + k };
function sign(p: object, k: string) { return JSON.stringify(p) + k; }
export const a = AES.encrypt('x', 'constant'); export const b = sign({}, 'constant');
export const c = JSON.parse('{"k":1}');`)).toEqual([]);
  });
});
