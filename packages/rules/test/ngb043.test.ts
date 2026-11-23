import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const EXPRESS = `import type { Request, Response } from 'express';\n`;

describe('NGB043 insecure session cookie attributes', () => {
  it('reports res.cookie without HttpOnly / Secure', async () => {
    const res = await findings('NGB043', {
      'src/server.ts': `${EXPRESS}export function login(req: Request, res: Response, sid: string) {
  res.cookie('session', sid, { sameSite: 'none' });
  res.cookie('refresh_token', sid, { httpOnly: true });
}`,
    });
    expect(res.map((r) => r.severity).sort()).toEqual(['high', 'medium']);
    expect(res.find((r) => r.severity === 'high')!.message).toMatch(/SameSite=None without Secure/);
  });

  it('reports Set-Cookie headers built as strings', async () => {
    const res = await findings('NGB043', {
      'src/server.ts': `${EXPRESS}export function f(res: Response, token: string) { res.setHeader('Set-Cookie', \`jwt=\${token}; Path=/; Secure\`); }`,
    });
    expect(res).toHaveLength(1);
    expect(res[0]!.message).toMatch(/missing HttpOnly/);
  });

  it('safe: hardened cookies, dynamic secure flag, CSRF and preference cookies', async () => {
    expect(await findings('NGB043', {
      'src/server.ts': `${EXPRESS}export function f(res: Response, sid: string, x: string) {
  res.cookie('__Host-session', sid, { httpOnly: true, secure: true, sameSite: 'lax', path: '/' });
  res.cookie('sid', sid, { httpOnly: true, secure: process.env['NODE_ENV'] === 'production' });
  res.cookie('XSRF-TOKEN', x);
  res.cookie('theme', 'dark');
  res.setHeader('Set-Cookie', 'session=abc; HttpOnly; Secure; SameSite=Strict');
}`,
    })).toEqual([]);
  });

  it('false-positive regression: non-response cookie() methods', async () => {
    expect(await findings('NGB043', {
      'src/app/a.ts': `const jar = { cookie: (_n: string, _v: string) => 0 }; export function f(sid: string) { jar.cookie('session', sid); }`,
    })).toEqual([]);
  });
});
