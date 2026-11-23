import { describe, expect, it } from 'vitest';
import { one } from './helpers.js';

describe('NGB025 authentication cookie set from JavaScript', () => {
  it('reports document.cookie with a session cookie name and missing attributes', async () => {
    const res = await one('NGB025', `export function save(res: { accessToken: string }) { document.cookie = \`access_token=\${res.accessToken}; path=/\`; }`);
    expect(res).toHaveLength(1);
    expect(res[0]!.confidence).toBe('high');
    expect(res[0]!.evidence.join()).toMatch(/missing attributes: secure, samesite/);
    expect(res[0]!.snippet).toBeUndefined();
  });

  it('reports ngx-cookie-service and js-cookie', async () => {
    const res = await one('NGB025', `import { CookieService } from 'ngx-cookie-service';
import Cookies from 'js-cookie';
export class S {
  constructor(private cookies: CookieService) {}
  a(sid: string) { this.cookies.set('session', sid, { secure: true, sameSite: 'Strict' }); }
  b(jwt: string) { Cookies.set('jwt', jwt); }
}`);
    expect(res).toHaveLength(2);
    expect(res[0]!.evidence.join()).not.toMatch(/missing/);
  });

  it('reports a credential-named value under a generic cookie name (value evidence)', async () => {
    const res = await one('NGB025', `export function f(refreshToken: string) { document.cookie = 'rt=' + refreshToken; }`);
    expect(res).toHaveLength(1);
  });

  it('safe: preference cookies and XSRF cookies are not reported', async () => {
    expect(await one('NGB025', `export function f(theme: string, x: string) { document.cookie = \`theme=\${theme}; Secure; SameSite=Lax\`; document.cookie = 'XSRF-TOKEN=' + x; }`)).toEqual([]);
  });

  it('false-positive regression: reading cookies and unrelated set() calls are ignored', async () => {
    expect(await one('NGB025', `const m = new Map<string, string>(); export function f(t: string) { m.set('session', t); return document.cookie; }`)).toEqual([]);
  });
});
