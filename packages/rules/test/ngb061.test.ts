import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const srv = (body: string) => findings('NGB061', { 'src/server.ts': `import type { Request, Response } from 'express';\n${body}` });

describe('NGB061 server-side open redirect', () => {
  it('reports request data in res.redirect / Location headers', async () => {
    const res = await srv(`export function a(req: Request, res: Response) { res.redirect(req.query['next'] as string); }
export function b(req: Request, res: Response) { res.redirect(302, req.body.returnTo); }
export function c(req: Request, res: Response) { res.setHeader('Location', String(req.query['u'])); res.statusCode = 302; res.end(); }
export function d(req: Request, res: Response) { res.status(301).location(req.params['to']!).end(); }`);
    expect(res.map((f) => f.location.line)).toEqual([2, 3, 4, 5]);
    expect(res[0]!.trace?.[0]?.description).toMatch(/query/);
  });

  it('reports untyped (req, res) handlers', async () => {
    const res = await findings('NGB061', { 'src/server.ts': `const app: any = {}; app.get('/r', (req, res) => { res.redirect(req.query.next); });` });
    expect(res).toHaveLength(1);
  });

  it('safe: pinned paths, allowlist and relative-path checks, constants', async () => {
    expect(await srv(`const ALLOWED = ['https://app.example.com'];
export function a(req: Request, res: Response) { res.redirect('/orders/' + encodeURIComponent(String(req.params['id']))); }
export function b(req: Request, res: Response) { const next = String(req.query['next']); if (!next.startsWith('/') || next.startsWith('//')) return; res.redirect(next); }
export function c(req: Request, res: Response) { const u = new URL(String(req.query['u'])); if (ALLOWED.includes(u.origin)) res.redirect(u.href); }
export function d(_req: Request, res: Response) { res.redirect('/login'); }`)).toEqual([]);
  });

  it('false-positive regression: Host header redirects belong to NGB042; non-response objects', async () => {
    expect(await srv(`export function a(req: Request, res: Response) { res.redirect(\`https://\${req.get('host')}/x\`); }
export function b(req: Request, router: { redirect(u: string): void }) { router.redirect(String(req.query['x'])); }`)).toEqual([]);
  });
});
