import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const EXPRESS = `import type { Request, Response } from 'express';\n`;

describe('NGB081 permissive CORS with credentials', () => {
  it('reports reflected Origin with credentials and cors({ origin: true, credentials: true })', async () => {
    const res = await findings('NGB081', {
      'src/server.ts': `${EXPRESS}import cors from 'cors';
declare const app: { use(x: unknown): void };
app.use(cors({ origin: true, credentials: true }));
app.use(cors({ origin: (origin: string, cb: (e: null, ok: unknown) => void) => cb(null, origin), credentials: true }));
export function allow(req: Request, res: Response) {
  const origin = req.headers.origin;
  res.setHeader('Access-Control-Allow-Origin', origin as string);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
}
export function allowNull(req: Request, res: Response) {
  res.set('Access-Control-Allow-Origin', 'null');
  res.set('Access-Control-Allow-Credentials', 'true');
}`,
    });
    expect(res).toHaveLength(4);
    expect(res.every((r) => r.confidence === 'high')).toBe(true);
  });

  it('reports null origin with credentials in hosting configs', async () => {
    const res = await findings('NGB081', {
      'firebase.json': JSON.stringify({ hosting: { headers: [{ source: '/api/**', headers: [{ key: 'Access-Control-Allow-Origin', value: 'null' }, { key: 'Access-Control-Allow-Credentials', value: 'true' }] }] } }),
    });
    expect(res).toHaveLength(1);
  });

  it('safe: allowlisted origins, no credentials, explicit origin list', async () => {
    expect(await findings('NGB081', {
      'src/server.ts': `${EXPRESS}import cors from 'cors';
declare const app: { use(x: unknown): void };
const ALLOWED = ['https://app.example.com'];
app.use(cors({ origin: ALLOWED, credentials: true }));
app.use(cors({ origin: true }));
app.use(cors({ origin: (o: string, cb: (e: null, ok: boolean) => void) => cb(null, ALLOWED.includes(o)), credentials: true }));
export function allow(req: Request, res: Response) {
  const origin = req.get('origin');
  if (origin && ALLOWED.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
}
export function pub(req: Request, res: Response) { res.setHeader('Access-Control-Allow-Origin', req.headers.origin as string); }`,
    })).toEqual([]);
  });

  it('false-positive regression: wildcard with credentials (browsers refuse it) and non-response setHeader', async () => {
    expect(await findings('NGB081', {
      'src/server.ts': `${EXPRESS}export function f(req: Request, res: Response, headers: Map<string, string>) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  headers.set('Access-Control-Allow-Origin', req.headers.origin as string);
}`,
    })).toEqual([]);
  });
});
