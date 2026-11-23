import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const EXPRESS = `import type { Request, Response, NextFunction } from 'express';\ndeclare function authenticate(b: unknown): Promise<{ id: string }>;\n`;

describe('NGB084 session not regenerated after login', () => {
  it('reports login handlers that mark the session authenticated without regenerate()', async () => {
    const res = await findings('NGB084', {
      'src/server/login.ts': `${EXPRESS}export async function login(req: Request, res: Response) {
  const user = await authenticate(req.body);
  req.session.userId = user.id;
  req.session.authenticated = true;
  res.redirect('/');
}`,
      'src/server/untyped.ts': `declare const app: { post(p: string, h: (req: any, res: any) => void): void };
declare function check(b: unknown): { id: string };
app.post('/login', (req, res) => { req.session.user = check(req.body); res.redirect('/'); });`,
    });
    expect(res).toHaveLength(3);
    expect(res.every((r) => r.evidenceKind === 'heuristic')).toBe(true);
  });

  it('safe: regenerate() around the assignment', async () => {
    expect(await findings('NGB084', {
      'src/server/login.ts': `${EXPRESS}export async function login(req: Request, res: Response, next: NextFunction) {
  const user = await authenticate(req.body);
  req.session.regenerate((err: Error | undefined) => {
    if (err) return next(err);
    req.session.userId = user.id;
    res.redirect('/');
  });
}`,
    })).toEqual([]);
  });

  it('false-positive regression: logout, non-auth session data, non-request session objects', async () => {
    expect(await findings('NGB084', {
      'src/server/session.ts': `${EXPRESS}export function f(req: Request, res: Response, store: { session: { user?: string } }) {
  req.session.user = null;
  req.session.userId = undefined;
  req.session.cart = ['sku-1'];
  req.session.theme = 'dark';
  store.session.user = 'x';
  res.end();
}`,
    })).toEqual([]);
  });
});
