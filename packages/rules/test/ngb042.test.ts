import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const EXPRESS = `import type { Request, Response } from 'express';\n`;

describe('NGB042 host header injection in SSR', () => {
  it('reports provider base URLs and server-side fetches built from Host / X-Forwarded-Host', async () => {
    const res = await findings('NGB042', {
      'src/server.ts': `${EXPRESS}declare const API_BASE_URL: unknown;
export function handle(req: Request, res: Response) {
  const providers = [{ provide: API_BASE_URL, useValue: \`\${req.protocol}://\${req.get('host')}/api\` }];
  fetch(\`https://\${req.headers['x-forwarded-host']}/internal/health\`);
  return providers;
}`,
    });
    expect(res).toHaveLength(2);
    expect(res.every((r) => r.severity === 'high')).toBe(true);
    expect(res[0]!.trace?.[0]?.description).toMatch(/request/);
  });

  it('reports redirects and Fetch Request headers (Angular REQUEST token)', async () => {
    const res = await findings('NGB042', {
      'src/app/redirect.ts': `${EXPRESS}export function r(req: Request, res: Response, request: globalThis.Request) {
  res.redirect(\`https://\${req.hostname}/login\`);
  fetch(\`https://\${request.headers.get('host')}/api/me\`);
}`,
    });
    expect(res.map((r) => r.severity).sort()).toEqual(['high', 'medium']);
  });

  it('safe: configured origins and allowlisted hosts', async () => {
    expect(await findings('NGB042', {
      'src/server.ts': `${EXPRESS}declare const API_BASE_URL: unknown;
const ALLOWED_HOSTS = ['app.example.com'];
export function handle(req: Request, res: Response) {
  const host = req.get('host') ?? '';
  if (!ALLOWED_HOSTS.includes(host)) return res.status(400).end();
  res.redirect(\`https://\${host}/login\`);
  return [{ provide: API_BASE_URL, useValue: process.env['PUBLIC_ORIGIN'] + '/api' }];
}`,
    })).toEqual([]);
  });

  it('false-positive regression: non-request objects with a host property', async () => {
    expect(await findings('NGB042', {
      'src/app/a.ts': `export function f(cfg: { host: string; get(k: string): string }) { fetch(\`https://\${cfg.host}/x\`); fetch(\`https://\${cfg.get('host')}/y\`); }`,
    })).toEqual([]);
  });
});
