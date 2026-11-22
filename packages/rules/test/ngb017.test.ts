import { describe, expect, it } from 'vitest';
import { NG, findings, one } from './helpers.js';

describe('NGB017 sensitive data in URLs', () => {
  it('reports an access token in an HttpClient query string (high)', async () => {
    const [f, ...rest] = await one('NGB017', `${NG}
export class Api {
  private http = inject(HttpClient);
  accessToken = '';
  load() { return this.http.get(\`/api/report?access_token=\${this.accessToken}&page=1\`); }
}`);
    expect(rest).toHaveLength(0);
    expect(f!.confidence).toBe('high');
    expect(f!.severity).toBe('high');
    expect(f!.message).toContain(`URL parameter 'access_token'`);
  });

  it('reports params objects, HttpParams and router queryParams', async () => {
    const res = await one('NGB017', `${NG}
import { HttpParams } from '@angular/common/http';
export class C {
  private http = inject(HttpClient);
  private router = inject(Router);
  go(password: string, cvv: string, sessionId: string) {
    this.http.get('/api/x', { params: { password } });
    new HttpParams().set('cvv', cvv);
    this.router.navigate(['/confirm'], { queryParams: { sessionId } });
  }
}`);
    expect(res).toHaveLength(3);
    expect(res.map((f) => f.message).join('\n')).toMatch(/password[\s\S]*cvv[\s\S]*sessionId/);
  });

  it('follows a URL built in a variable and URLSearchParams/location', async () => {
    const res = await one('NGB017', `export function f(refreshToken: string) {
  const url = '/cb?rt=' + refreshToken;
  fetch(url);
  const u = new URL(location.href);
  u.searchParams.set('jwt', refreshToken);
}`);
    expect(res).toHaveLength(2);
  });

  it('does not report OAuth/OIDC protocol parameters', async () => {
    expect(await one('NGB017', `export function login(state: string, nonce: string, code: string, idToken: string) {
  location.assign(\`https://idp.example.com/authorize?client_id=app&state=\${state}&nonce=\${nonce}\`);
  fetch(\`/token?code=\${code}\`);
  location.assign(\`https://idp.example.com/logout?id_token_hint=\${idToken}\`);
}`)).toEqual([]);
  });

  it('safe equivalent: token in a header or POST body is not reported', async () => {
    expect(await one('NGB017', `${NG}
export class C {
  private http = inject(HttpClient);
  token = '';
  go(password: string) {
    this.http.get('/api/report', { headers: { Authorization: 'Bearer ' + this.token } });
    this.http.post('/api/login', { password });
  }
}`)).toEqual([]);
  });

  it('false-positive regression: opaque payment references and ids in paths are not sensitive', async () => {
    expect(await findings('NGB017', {
      'src/app/a.ts': `${NG}
export class C {
  private http = inject(HttpClient);
  go(paymentToken: string, userId: string, orderId: string) {
    this.http.get(\`/api/orders/\${orderId}/users/\${userId}?payment_token=\${paymentToken}\`);
  }
}`,
    })).toEqual([]);
  });
});
