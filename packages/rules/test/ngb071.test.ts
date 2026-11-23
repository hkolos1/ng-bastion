import { describe, expect, it } from 'vitest';
import { NG, findings, one } from './helpers.js';

const firebase = (source: string, value = '/') => JSON.stringify({ hosting: { public: 'dist', headers: [{ source, headers: [{ key: 'Service-Worker-Allowed', value }] }] } }, null, 2);

describe('NGB071 service worker scope expansion', () => {
  it('reports Service-Worker-Allowed for globs and all responses (firebase, vercel, _headers, Azure globalHeaders)', async () => {
    const res = await findings('NGB071', {
      'firebase.json': firebase('**'),
      'vercel.json': JSON.stringify({ headers: [{ source: '/assets/(.*)', headers: [{ key: 'Service-Worker-Allowed', value: '/app/' }] }] }),
      'public/_headers': '/static/*\n  Service-Worker-Allowed: /\n',
      'staticwebapp.config.json': JSON.stringify({ globalHeaders: { 'Service-Worker-Allowed': '/' } }),
      'src/main.ts': 'export {};',
    });
    expect(res).toHaveLength(4);
    expect(res.map((r) => r.severity).sort()).toEqual(['low', 'medium', 'medium', 'medium']);
  });

  it('reports unconditional server headers and untrusted registration scopes', async () => {
    const res = await findings('NGB071', {
      'src/server.ts': `import type { Request, Response, NextFunction } from 'express';
export function mw(req: Request, res: Response, next: NextFunction) { res.setHeader('Service-Worker-Allowed', '/'); next(); }`,
      'src/app/sw-loader.ts': `${NG}export class C { private route = inject(ActivatedRoute);
  run() { navigator.serviceWorker.register('/sw.js', { scope: this.route.snapshot.queryParams['scope'] }); } }`,
    });
    expect(res).toHaveLength(2);
  });

  it('safe: header only for the worker script, script-specific routes, constant scopes', async () => {
    expect(await findings('NGB071', {
      'firebase.json': firebase('/assets/sw.js'),
      'public/_headers': '/sw.js\n  Service-Worker-Allowed: /\n',
      'src/server.ts': `declare const app: any;
app.get('/assets/sw.js', (req: unknown, res: { setHeader(k: string, v: string): void }) => { res.setHeader('Service-Worker-Allowed', '/'); });`,
      'src/app/main.ts': `navigator.serviceWorker.register('/assets/sw.js', { scope: '/' });`,
    })).toEqual([]);
  });

  it('false-positive regression: other headers on wildcard sources, other register() methods', async () => {
    expect(await one('NGB071', `${NG}export class C { private route = inject(ActivatedRoute);
  run(registry: { register(a: string, o: object): void }) { registry.register('x', { scope: this.route.snapshot.queryParams['s'] }); } }`)).toEqual([]);
    expect(await findings('NGB071', { 'firebase.json': JSON.stringify({ hosting: { headers: [{ source: '**', headers: [{ key: 'X-Frame-Options', value: 'DENY' }] }] } }), 'src/main.ts': 'export {};' })).toEqual([]);
  });
});
