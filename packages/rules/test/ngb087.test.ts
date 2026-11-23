import { describe, expect, it } from 'vitest';
import { findings, one } from './helpers.js';

describe('NGB087 insufficient password-hashing work factor', () => {
  it('reports low PBKDF2 iteration counts per hash (Web Crypto, Node, CryptoJS)', async () => {
    const res = await findings('NGB087', {
      'src/app/vault.ts': `const ITERATIONS = 100_000;
export async function derive(key: CryptoKey, salt: Uint8Array) {
  await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 1000 }, key, 256);
  await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: { name: 'SHA-1' }, salt, iterations: 600000 }, key, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-512', salt, iterations: ITERATIONS }, key, 256);
}
export function legacy(pw: string, salt: string) { return CryptoJS.PBKDF2(pw, salt, { keySize: 8, iterations: 2 ** 12 }); }
declare const CryptoJS: { PBKDF2(p: string, s: string, o: object): unknown };`,
      'src/server/hash.ts': `import { pbkdf2Sync } from 'crypto';
export const h = (pw: string, salt: Buffer) => pbkdf2Sync(pw, salt, 10000, 32, 'sha512');`,
    });
    expect(res).toHaveLength(5);
    expect(res.filter((r) => r.severity === 'high')).toHaveLength(2); // 1000 and 4096
    expect(res.find((r) => r.message.includes('CryptoJS'))!.confidence).toBe('medium'); // hasher unknown
  });

  it('reports bcrypt cost, scrypt cost (incl. Node defaults) and argon2 memory', async () => {
    const res = await findings('NGB087', {
      'src/server/hash.ts': `import bcrypt from 'bcrypt';
import * as argon2 from 'argon2';
import { scryptSync } from 'node:crypto';
export async function h(pw: string, salt: Buffer) {
  await bcrypt.hash(pw, 8);
  bcrypt.genSaltSync(9);
  scryptSync(pw, salt, 64, { N: 1 << 14 });
  scryptSync(pw, salt, 64);
  return argon2.hash(pw, { memoryCost: 4096, timeCost: 3 });
}`,
    });
    expect(res).toHaveLength(5);
    expect(res.find((r) => r.message.includes('Node defaults'))!.severity).toBe('low');
  });

  it('safe: OWASP-compliant parameters and library defaults', async () => {
    expect(await findings('NGB087', {
      'src/server/hash.ts': `import bcrypt from 'bcrypt';
import argon2 from 'argon2';
import { pbkdf2Sync, scryptSync } from 'crypto';
export async function h(pw: string, salt: Buffer, key: CryptoKey) {
  await bcrypt.hash(pw, 12);
  pbkdf2Sync(pw, salt, 600_000, 32, 'sha256');
  pbkdf2Sync(pw, salt, 210000, 64, 'sha512');
  scryptSync(pw, salt, 64, { N: 2 ** 17 });
  scryptSync(pw, salt, 64, { N: 2 ** 15, r: 8, p: 4 });
  await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600000 }, key, 256);
  await argon2.hash(pw);
  return argon2.hash(pw, { memoryCost: 19456, timeCost: 2 });
}`,
    })).toEqual([]);
  });

  it('false-positive regression: runtime-configured iterations and bcrypt with a generated salt', async () => {
    expect(await one('NGB087', `import bcrypt from 'bcryptjs';
export async function h(pw: string, salt: Uint8Array, key: CryptoKey, cfg: { iterations: number }) {
  await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: cfg.iterations }, key, 256);
  return bcrypt.hash(pw, await bcrypt.genSalt());
}`)).toEqual([]);
  });
});
