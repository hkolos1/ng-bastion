import { describe, expect, it } from 'vitest';
import { NG, findings, one } from './helpers.js';

describe('NGB060 untrusted OAuth redirect URI', () => {
  it('reports redirect URIs from the query string in config, params and request URLs', async () => {
    const res = await findings('NGB060', {
      'src/app/login.ts': `${NG}import { OAuthService } from 'angular-oauth2-oidc';
export class Login {
  private route = inject(ActivatedRoute);
  private oauth = inject(OAuthService);
  start(issuer: string) {
    const back = this.route.snapshot.queryParams['returnTo'];
    this.oauth.configure({ issuer, clientId: 'spa', responseType: 'code', redirectUri: back });
    const p = new URLSearchParams({ client_id: 'spa' });
    p.set('redirect_uri', location.hash.slice(1));
    location.assign(\`\${issuer}/authorize?client_id=spa&redirect_uri=\${encodeURIComponent(window.name)}\`);
  }
}`,
    });
    expect(res).toHaveLength(3);
    expect(res.every((f) => f.evidenceKind === 'dataflow' && f.confidence !== 'high')).toBe(true);
  });

  it('reports concatenated request URLs', async () => {
    const [f] = await one('NGB060', `export function go(issuer: string) {
  const cb = new URLSearchParams(location.search).get('cb') ?? '';
  location.href = issuer + '/logout?post_logout_redirect_uri=' + cb;
}`);
    expect(f).toBeDefined();
  });

  it('safe: constant origin, own current URL, allowlisted hosts', async () => {
    expect(await one('NGB060', `const ALLOWED = ['app.example.com'];
export function cfg(issuer: string) {
  const q = new URLSearchParams(location.search).get('cb') ?? '';
  const a = { redirectUri: location.origin + '/auth/callback', postLogoutRedirectUri: window.location.href };
  const b = { redirect_uri: \`https://app.example.com/cb?next=\${q}\` };
  if (ALLOWED.includes(new URL(q).hostname)) { const c = { redirectUri: q }; return [a, b, c]; }
  return [a, b, issuer];
}`)).toEqual([]);
  });

  it('false-positive regression: unrelated redirect properties and constant values', async () => {
    expect(await one('NGB060', `export function f() {
  const returnUrl = new URLSearchParams(location.search).get('r');
  return { returnUrl, redirectUri: '/callback', redirect: returnUrl };
}`)).toEqual([]);
  });
});
