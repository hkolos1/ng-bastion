import { describe, expect, it } from 'vitest';
import { findings, one } from './helpers.js';

describe('NGB089 truncated authentication tag', () => {
  it('reports short AES-GCM tagLength (Web Crypto) and authTagLength (Node)', async () => {
    const res = await findings('NGB089', {
      'src/app/enc.ts': `export async function enc(key: CryptoKey, iv: Uint8Array, data: ArrayBuffer) {
  await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 32 }, key, data);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 96 }, key, data);
}`,
      'src/server/enc.ts': `import { createCipheriv } from 'crypto';
export const c = (key: Buffer, iv: Buffer) => createCipheriv('aes-256-gcm', key, iv, { authTagLength: 8 });`,
    });
    expect(res.map((r) => r.severity).sort()).toEqual(['low', 'medium', 'medium']);
  });

  it('reports GCM decryption that accepts a tag of any length', async () => {
    const res = await one('NGB089', `import * as crypto from 'node:crypto';
export function dec(key: Buffer, iv: Buffer, data: Buffer) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  const tag = data.subarray(data.length - 16);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data.subarray(0, -16)), decipher.final()]);
}`);
    expect(res).toHaveLength(1);
    expect(res[0]!.confidence).toBe('medium');
  });

  it('safe: default tags, fixed authTagLength, length check before setAuthTag', async () => {
    expect(await findings('NGB089', {
      'src/server/enc.ts': `import { createDecipheriv } from 'crypto';
export async function f(key: Buffer, iv: Buffer, tag: Buffer, k: CryptoKey, data: ArrayBuffer) {
  await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, k, data);
  await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, data);
  const d1 = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  d1.setAuthTag(tag);
  const d2 = createDecipheriv('aes-128-gcm', key, iv);
  if (tag.length !== 16) throw new Error('bad tag');
  d2.setAuthTag(tag);
}`,
    })).toEqual([]);
  });

  it('false-positive regression: AES-CBC deciphers and AES-CTR tagLength-like options', async () => {
    expect(await one('NGB089', `import { createDecipheriv } from 'crypto';
export function f(key: Buffer, iv: Buffer, k: CryptoKey, data: ArrayBuffer) {
  const d = createDecipheriv('aes-256-cbc', key, iv);
  return crypto.subtle.encrypt({ name: 'AES-CTR', counter: iv, length: 64 }, k, data);
}`)).toEqual([]);
  });
});
