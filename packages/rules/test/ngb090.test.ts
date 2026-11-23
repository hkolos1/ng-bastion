import { describe, expect, it } from 'vitest';
import { findings, one } from './helpers.js';

describe('NGB090 signature verification result ignored', () => {
  it('reports discarded crypto.subtle.verify results', async () => {
    const res = await one('NGB090', `export async function check(key: CryptoKey, sig: ArrayBuffer, data: ArrayBuffer) {
  await crypto.subtle.verify('HMAC', key, sig, data);
  const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sig, data);
  void crypto.subtle.verify('HMAC', key, sig, data);
  crypto.subtle.verify('HMAC', key, sig, data).then(() => console.log('verified'));
  return JSON.parse(new TextDecoder().decode(data));
}`);
    expect(res).toHaveLength(4);
    expect(res.some((r) => r.message.includes("'ok'"))).toBe(true);
  });

  it('reports Node crypto.verify and Verify#verify statements', async () => {
    const res = await findings('NGB090', {
      'src/server/webhook.ts': `import crypto, { createVerify } from 'crypto';
export function hook(body: string, sig: string, key: string) {
  crypto.verify('sha256', Buffer.from(body), key, Buffer.from(sig, 'base64'));
  const v = createVerify('sha256');
  v.update(body);
  v.verify(key, sig, 'base64');
  createVerify('sha256').update(body).verify(key, sig, 'base64');
  return JSON.parse(body);
}`,
    });
    expect(res).toHaveLength(3);
  });

  it('safe: results that are checked or returned', async () => {
    expect(await findings('NGB090', {
      'src/server/webhook.ts': `import { verify, createVerify } from 'crypto';
export async function hook(body: string, sig: string, key: string, k: CryptoKey, s: ArrayBuffer, d: ArrayBuffer) {
  if (!verify('sha256', Buffer.from(body), key, Buffer.from(sig))) throw new Error('bad');
  const ok = createVerify('sha256').update(body).verify(key, sig, 'base64');
  if (!ok) throw new Error('bad');
  verify('sha256', Buffer.from(body), key, Buffer.from(sig), (err, valid) => { if (!valid) throw err; });
  return crypto.subtle.verify('HMAC', k, s, d);
}`,
    })).toEqual([]);
  });

  it('false-positive regression: jwt.verify (throws) and project verify() methods', async () => {
    expect(await one('NGB090', `import jwt from 'jsonwebtoken';
export class Form { verify() { return true; } }
export function f(token: string, key: string, form: Form) {
  jwt.verify(token, key);
  form.verify();
}`)).toEqual([]);
  });
});
