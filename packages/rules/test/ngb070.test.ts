import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const srv = (body: string) => findings('NGB070', { 'src/server.ts': `import type { Request, Response } from 'express';\nimport { createHmac, timingSafeEqual } from 'node:crypto';\n${body}` });

describe('NGB070 timing-unsafe secret comparison', () => {
  it('reports request values compared with HMACs and secrets', async () => {
    const res = await srv(`declare const secret: string; declare const API_KEY: string;
export function a(req: Request, res: Response) {
  const expected = createHmac('sha256', secret).update(req.body.raw).digest('hex');
  if (req.get('x-signature') !== expected) return res.sendStatus(401);
  return undefined;
}
export function b(req: Request) { return req.headers['x-api-key'] === API_KEY; }
export function c(req: Request, accessToken: string) { const given = req.body.token; return given == accessToken; }`);
    expect(res.map((f) => f.location.line)).toEqual([6, 9, 10]);
    expect(res[0]!.confidence).toBe('high');
  });

  it('safe: timingSafeEqual, comparisons with constants / lengths / non-secret values', async () => {
    expect(await srv(`declare const secret: string;
export function a(req: Request) {
  const expected = Buffer.from(createHmac('sha256', secret).update('x').digest('hex'));
  const given = Buffer.from(String(req.get('x-signature')));
  return given.length === expected.length && timingSafeEqual(given, expected);
}
export function b(req: Request, user: { id: string }) {
  return req.query['mode'] === 'preview' || req.body.userId === user.id || req.get('x-signature') === undefined || typeof req.body.token === 'string';
}`)).toEqual([]);
  });

  it('false-positive regression: browser code and metadata names are not analyzed', async () => {
    expect(await findings('NGB070', {
      'src/app/a.ts': `export function f(apiKey: string, input: HTMLInputElement) { return input.value === apiKey; }`,
      'src/server.ts': `import type { Request } from 'express';
export function g(req: Request, signatureHeader: string, tokenExpiry: number) { return req.get('h') === signatureHeader || req.body.exp === tokenExpiry; }`,
    })).toEqual([]);
  });
});
