import { describe, expect, it } from 'vitest';
import { NG, findings, one } from './helpers.js';

describe('NGB058 ID token sent as API bearer token', () => {
  it('reports OAuthService.getIdToken() in an interceptor (high) and idToken values (medium)', async () => {
    const res = await findings('NGB058', {
      'src/app/auth.interceptor.ts': `${NG}import { OAuthService } from 'angular-oauth2-oidc';
import { HttpInterceptorFn, HttpHeaders } from '@angular/common/http';
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const oauth = inject(OAuthService);
  return next(req.clone({ setHeaders: { Authorization: \`Bearer \${oauth.getIdToken()}\` } }));
};
export function headers(session: { idToken: string }) {
  return new HttpHeaders().set('Authorization', 'Bearer ' + session.idToken);
}`,
    });
    expect(res.map((f) => f.confidence).sort()).toEqual(['high', 'medium']);
  });

  it('reports with low confidence when the ID token name appears only along the data flow', async () => {
    const [f] = await one('NGB058', `export function call(store: { id_token: string }) {
  const t = store['id_token'];
  const bearer = t;
  return fetch('/api', { headers: { authorization: 'Bearer ' + bearer } });
}`);
    expect(f).toBeDefined();
  });

  it('safe: access tokens and Firebase ID tokens', async () => {
    expect(await findings('NGB058', {
      'src/app/a.ts': `${NG}import { OAuthService } from 'angular-oauth2-oidc';
import { Auth } from '@angular/fire/auth';
export class A {
  private oauth = inject(OAuthService);
  private auth = inject(Auth);
  h1() { return { Authorization: \`Bearer \${this.oauth.getAccessToken()}\` }; }
  async h2() { return { Authorization: \`Bearer \${await this.auth.currentUser!.getIdToken()}\` }; }
}`,
    })).toEqual([]);
  });

  it('false-positive regression: ID token used outside Authorization headers and claims helpers', async () => {
    expect(await one('NGB058', `export function f(idToken: string, idTokenClaims: { sub: string }) {
  sessionStorage.setItem('hint', idToken);
  return { Authorization: 'Bearer ' + idTokenClaims.sub, 'X-Id-Token-Hint': idToken };
}`)).toEqual([]);
  });
});
