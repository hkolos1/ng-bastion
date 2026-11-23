import { describe, expect, it } from 'vitest';
import { findings, one } from './helpers.js';
import { cipherWeakness } from '../src/rules/ngb065-broken-or-weak-cipher.js';

describe('NGB065 broken or weak cipher', () => {
  it('classifies cipher names', () => {
    expect(cipherWeakness('des-ede3-cbc')?.severity).toBe('medium');
    expect(cipherWeakness('des-cbc')?.severity).toBe('high');
    expect(cipherWeakness('rc4')?.severity).toBe('high');
    expect(cipherWeakness('aes-256-ecb')?.severity).toBe('medium');
    expect(cipherWeakness('aes-256-gcm')).toBeUndefined();
    expect(cipherWeakness('chacha20-poly1305')).toBeUndefined();
    expect(cipherWeakness('aes-128-cbc')).toBeUndefined();
  });

  it('reports Node crypto, deprecated createCipher, CryptoJS and forge', async () => {
    const res = await findings('NGB065', {
      'src/server.ts': `import { createCipheriv } from 'node:crypto';
import * as crypto from 'crypto';
const c = require('crypto');
export function f(key: Buffer, iv: Buffer) {
  createCipheriv('des-ede3-cbc', key, iv);
  crypto.createDecipheriv('rc4', key, null);
  c.createCipheriv('aes-128-ecb', key, null);
  crypto.createCipher('aes-256-cbc', 'password');
}`,
      'src/app/legacy.ts': `import CryptoJS from 'crypto-js';
declare const forge: any;
export const a = CryptoJS.DES.encrypt('m', 'k');
export const b = CryptoJS.AES.encrypt('m', 'k', { mode: CryptoJS.mode.ECB });
export const d = forge.cipher.createCipher('3DES-CBC', 'k');`,
    });
    expect(res).toHaveLength(7);
    expect(res.find((f) => f.message.includes('createCipher()'))?.severity).toBe('medium');
    expect(res.find((f) => f.message.includes('DES.encrypt'))?.severity).toBe('high');
  });

  it('safe: AES-GCM, ChaCha20, CryptoJS AES default mode', async () => {
    expect(await findings('NGB065', {
      'src/server.ts': `import { createCipheriv, randomBytes } from 'crypto';
export function f(key: Buffer) { createCipheriv('aes-256-gcm', key, randomBytes(12)); createCipheriv('chacha20-poly1305', key, randomBytes(12), { authTagLength: 16 }); }`,
      'src/app/a.ts': `import CryptoJS from 'crypto-js'; export const x = CryptoJS.AES.encrypt('m', 'k', { mode: CryptoJS.mode.CBC });`,
    })).toEqual([]);
  });

  it('false-positive regression: project functions named like crypto APIs, non-crypto DES members', async () => {
    expect(await one('NGB065', `function createCipheriv(alg: string) { return alg; }
const store = { DES: { encrypt: (x: string) => x } };
export const a = createCipheriv('des-cbc'); export const b = store.DES.encrypt('x');`)).toEqual([]);
  });
});
