import { describe, expect, it } from 'vitest';
import { findings, one } from './helpers.js';

describe('NGB086 static password-hashing salt', () => {
  it('reports constant salts in Web Crypto PBKDF2, Node pbkdf2 / scrypt, CryptoJS and bcrypt', async () => {
    const res = await findings('NGB086', {
      'src/app/vault.ts': `const SALT = new TextEncoder().encode('static-salt');
export async function derive(key: CryptoKey) {
  return crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: SALT, iterations: 600000 }, key, 256);
}
export function legacy(pw: string) { return CryptoJS.PBKDF2(pw, 'pepper', { keySize: 8, iterations: 600000 }); }
declare const CryptoJS: { PBKDF2(p: string, s: string, o: object): unknown };`,
      'src/server/hash.ts': `import { pbkdf2Sync, scryptSync } from 'node:crypto';
import bcrypt from 'bcryptjs';
const crypto = require('crypto');
export function h(pw: string) {
  pbkdf2Sync(pw, Buffer.from('fixed'), 600000, 32, 'sha256');
  scryptSync(pw, 'salt', 64);
  crypto.pbkdf2(pw, new Uint8Array(16), 600000, 32, 'sha256', () => undefined);
  return bcrypt.hashSync(pw, '$2a$10$abcdefghijklmnopqrstuu');
}`,
    });
    expect(res).toHaveLength(6);
    expect(res.every((r) => r.confidence === 'high')).toBe(true);
  });

  it('safe: random salts and library-managed salts', async () => {
    expect(await findings('NGB086', {
      'src/server/hash.ts': `import { pbkdf2Sync, randomBytes } from 'crypto';
import bcrypt from 'bcrypt';
export async function h(pw: string, key: CryptoKey) {
  const salt = randomBytes(16);
  pbkdf2Sync(pw, salt, 600000, 32, 'sha256');
  await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: crypto.getRandomValues(new Uint8Array(16)), iterations: 600000 }, key, 256);
  return bcrypt.hash(pw, 12);
}`,
    })).toEqual([]);
  });

  it('false-positive regression: HKDF info/salt and user-defined pbkdf2 helpers', async () => {
    expect(await one('NGB086', `function pbkdf2Sync(a: string, b: string) { return a + b; }
export async function f(key: CryptoKey) {
  pbkdf2Sync('x', 'y');
  return crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new Uint8Array(0) }, key, 256);
}`)).toEqual([]);
  });
});
