import { describe, expect, it } from 'vitest';
import { NG, findings, one } from './helpers.js';

describe('NGB057 missing OIDC nonce', () => {
  it('reports disableNonceCheck on OAuthService', async () => {
    const [f, ...rest] = await one('NGB057', `${NG}import { OAuthService } from 'angular-oauth2-oidc';
export class Login {
  private oauth = inject(OAuthService);
  init() { return this.oauth.loadDiscoveryDocumentAndTryLogin({ disableNonceCheck: true }); }
}`);
    expect(rest).toEqual([]);
    expect(f!.confidence).toBe('high');
  });

  it('reports hand-written id_token requests without nonce (template, concatenation, URLSearchParams)', async () => {
    const res = await findings('NGB057', {
      'src/app/login.ts': `export function login(issuer: string, id: string, cb: string, state: string) {
  location.assign(\`\${issuer}/authorize?client_id=\${id}&response_type=id_token&redirect_uri=\${cb}&state=\${state}\`);
  window.open(issuer + '/authorize?response_type=id_token%20token&client_id=' + id);
  const q = new URLSearchParams({ client_id: id, redirect_uri: cb, response_type: 'id_token token', state });
  return q;
}`,
    });
    expect(res).toHaveLength(3);
    expect(res.every((f) => f.severity === 'medium')).toBe(true);
  });

  it('safe: nonce present, code flow, library configuration', async () => {
    expect(await findings('NGB057', {
      'src/app/login.ts': `import { AuthConfig } from 'angular-oauth2-oidc';
export function login(issuer: string, id: string, cb: string, nonce: string) {
  location.assign(\`\${issuer}/authorize?client_id=\${id}&response_type=id_token&redirect_uri=\${cb}&nonce=\${nonce}\`);
  location.assign(\`\${issuer}/authorize?client_id=\${id}&response_type=code&redirect_uri=\${cb}\`);
  return new URLSearchParams({ client_id: id, redirect_uri: cb, response_type: 'id_token', nonce });
}
export const cfg: AuthConfig = { issuer: 'https://id.example.com', responseType: 'code', clientId: 'spa' };`,
    })).toEqual([]);
  });

  it('false-positive regression: disableNonceCheck false, other services, documentation strings', async () => {
    expect(await findings('NGB057', {
      'src/app/a.ts': `${NG}import { OAuthService } from 'angular-oauth2-oidc';
class Other { tryLogin(_o: object) { return true; } }
export class A {
  private oauth = inject(OAuthService);
  run() { this.oauth.tryLogin({ disableNonceCheck: false }); new Other().tryLogin({ disableNonceCheck: true }); }
}
export const HELP = 'Set response_type to code';
export const params = { response_type: 'id_token' };`,
    })).toEqual([]);
  });
});
