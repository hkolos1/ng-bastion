import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

describe('NGB059 JWT decoded without signature verification', () => {
  it('reports decode() driving authorization (high) and plain decodes (medium)', async () => {
    const res = await findings('NGB059', {
      'src/server.ts': `import jwt from 'jsonwebtoken';
import { decodeJwt } from 'jose';
import type { Request, Response, NextFunction } from 'express';
export function admin(req: Request, res: Response, next: NextFunction) {
  const claims = jwt.decode(req.headers.authorization!.slice(7)) as { role?: string };
  if (claims.role === 'admin') return next();
  res.sendStatus(403);
}
export function who(req: Request, res: Response) {
  req.user = decodeJwt(String(req.headers.authorization));
  res.end();
}
export function name(token: string) { return (jwt.decode(token) as { name: string }).name; }`,
    });
    expect(res.map((f) => f.severity).sort()).toEqual(['high', 'high', 'medium']);
  });

  it("reports jwt.verify() accepting 'none'", async () => {
    const [f] = await findings('NGB059', {
      'src/server.ts': `const jwt = require('jsonwebtoken');
export function v(t: string, k: string) { return jwt.verify(t, k, { algorithms: ['HS256', 'none'] }); }`,
    });
    expect(f!.message).toMatch(/none/);
  });

  it('safe: verification in the same function, browser-side decoding', async () => {
    expect(await findings('NGB059', {
      'src/server.ts': `import jwt from 'jsonwebtoken';
export function v(t: string, keys: Record<string, string>) {
  const header = jwt.decode(t, { complete: true });
  return jwt.verify(t, keys[String(header)], { algorithms: ['RS256'] });
}`,
      'src/app/profile.ts': `import { jwtDecode } from 'jwt-decode';
import { decodeJwt } from 'jose';
export const name = (t: string) => [jwtDecode<{ name: string }>(t).name, decodeJwt(t).sub];`,
    })).toEqual([]);
  });

  it('false-positive regression: project decode() functions and other modules', async () => {
    expect(await findings('NGB059', {
      'src/server.ts': `import { decode } from './codec';
import express from 'express';
export function f(s: string) { return decode(s); }
export const g = (s: string) => Buffer.from(s, 'base64').toString();`,
      'src/codec.ts': `export function decode(s: string) { return s; }`,
    })).toEqual([]);
  });
});
