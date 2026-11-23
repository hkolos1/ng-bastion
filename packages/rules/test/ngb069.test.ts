import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const srv = (body: string) => findings('NGB069', { 'src/server.ts': `import type { Request, Response } from 'express';\nimport escapeHtml from 'escape-html';\n${body}` });

describe('NGB069 reflected XSS in server responses', () => {
  it('reports request data written into HTML responses', async () => {
    const res = await srv(`export function a(req: Request, res: Response) { res.send(\`<p>No results for \${req.query['q']}</p>\`); }
export function b(req: Request, res: Response) { res.status(404).send('<h1>' + req.params['page'] + ' not found</h1>'); }
export function c(req: Request, res: Response) { const name = req.body.name; res.write('<b>' + name + '</b>'); res.end(); }`);
    expect(res.map((f) => f.location.line)).toEqual([3, 4, 5]);
    expect(res[0]!.evidenceKind).toBe('dataflow');
  });

  it('reports untyped (req, res) handlers and partially escaped output', async () => {
    const res = await findings('NGB069', { 'src/server.ts': `import escapeHtml from 'escape-html'; const app: any = {};
app.get('/x', (req, res) => res.send('<p>' + escapeHtml(req.query.a) + req.query.b + '</p>'));` });
    expect(res).toHaveLength(1);
    expect(res[0]!.message).toMatch(/query/);
  });

  it('safe: escaped values, JSON, non-HTML content types, constants', async () => {
    expect(await srv(`export function a(req: Request, res: Response) { res.send(\`<p>\${escapeHtml(String(req.query['q']))}</p>\`); }
export function b(req: Request, res: Response) { res.json({ q: req.query['q'] }); }
export function c(req: Request, res: Response) { res.type('text/plain').send(String(req.query['q'])); }
export function d(req: Request, res: Response) { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ q: req.query['q'] })); }
export function e(_req: Request, res: Response) { res.send('<p>ok</p>'); }
export function f(req: Request, res: Response) { res.send({ echo: req.body }); }`)).toEqual([]);
  });

  it('false-positive regression: Host header (NGB042) and non-response send()', async () => {
    expect(await srv(`export function a(req: Request, res: Response) { res.send('<a href="//' + req.get('host') + '/">home</a>'); }
export function b(req: Request, socket: { send(v: string): void }) { socket.send(String(req.query['q'])); }`)).toEqual([]);
  });
});
