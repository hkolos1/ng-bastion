import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const EXPRESS = `import type { Request, Response, NextFunction } from 'express';\n`;

describe('NGB082 spoofable client IP used for access control', () => {
  it('reports forwarding headers in access decisions (direct and through a variable)', async () => {
    const res = await findings('NGB082', {
      'src/server.ts': `${EXPRESS}const ADMIN_IPS = new Set(['10.0.0.5']);
export function adminOnly(req: Request, res: Response, next: NextFunction) {
  const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0].trim();
  if (!ADMIN_IPS.has(ip)) return res.sendStatus(403);
  next();
}
export function internal(req: Request, res: Response) {
  return req.get('x-real-ip') === '127.0.0.1' ? res.send('ok') : res.sendStatus(403);
}`,
    });
    expect(res).toHaveLength(2);
    expect(res.every((r) => r.severity === 'high')).toBe(true);
  });

  it("reports req.ip checks when trust proxy is true for every hop", async () => {
    const res = await findings('NGB082', {
      'src/server.ts': `${EXPRESS}declare const app: { set(k: string, v: unknown): void };
app.set('trust proxy', true);
export function local(req: Request, res: Response, next: NextFunction) {
  if (req.ip !== '127.0.0.1') return res.sendStatus(403);
  next();
}`,
    });
    expect(res).toHaveLength(1);
    expect(res[0]!.severity).toBe('medium');
  });

  it('safe: socket address, req.ip with a fixed hop count, logging the header', async () => {
    expect(await findings('NGB082', {
      'src/server.ts': `${EXPRESS}declare const app: { set(k: string, v: unknown): void };
app.set('trust proxy', 1);
export function local(req: Request, res: Response, next: NextFunction) {
  if (req.socket.remoteAddress !== '127.0.0.1') return res.sendStatus(403);
  if (req.ip !== '127.0.0.1') return res.sendStatus(403);
  console.log('client', req.headers['x-forwarded-for']);
  next();
}`,
    })).toEqual([]);
  });

  it('false-positive regression: header presence checks and non-IP comparisons', async () => {
    expect(await findings('NGB082', {
      'src/server.ts': `${EXPRESS}export function f(req: Request, res: Response) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) res.setHeader('X-Proxied', 'yes');
  if (req.get('x-forwarded-proto') === 'http') return res.redirect('https://example.com');
}`,
    })).toEqual([]);
  });
});
