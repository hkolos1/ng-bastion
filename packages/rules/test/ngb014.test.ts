import { describe, expect, it } from 'vitest';
import { NG, findings, one } from './helpers.js';

describe('NGB014 insecure token storage', () => {
  it('reports an access token from a login response (key + value agree → high)', async () => {
    const res = await one('NGB014', `${NG}
export class AuthService {
  private http = inject(HttpClient);
  login() { this.http.post<{ accessToken: string }>('/api/login', {}).subscribe(res => localStorage.setItem('access_token', res.accessToken)); }
}`);
    expect(res).toHaveLength(1);
    expect(res[0]!.confidence).toBe('high');
    expect(res[0]!.severity).toBe('high');
    expect(res[0]!.evidence.join('\n')).toMatch(/storage key 'access_token'/);
  });

  it('resolves constant keys, property writes and IndexedDB', async () => {
    const res = await one('NGB014', `const TOKEN_KEY = 'jwt';
declare const t: string;
localStorage.setItem(TOKEN_KEY, t);
localStorage['refreshToken'] = t;
declare const store: IDBObjectStore;
store.put({ sessionId: t }, 'current');`);
    expect(res.map((f) => f.location.line)).toEqual([3, 4, 6]);
  });

  it('sessionStorage is medium severity; weak key alone is medium confidence', async () => {
    const res = await one('NGB014', `declare const v: string;\nsessionStorage.setItem('token', v);`);
    expect(res[0]!.severity).toBe('medium');
    expect(res[0]!.confidence).toBe('medium');
  });

  it('cross-file: token value traced from a service', async () => {
    const res = await findings('NGB014', {
      'src/app/auth.ts': `export class Auth { refreshToken = ''; }`,
      'src/app/persist.ts': `import { Auth } from './auth';\nexport function persist(a: Auth) { localStorage.setItem('session', a.refreshToken); }`,
    });
    expect(res).toHaveLength(1);
  });

  it('negative: non-credential data, CSRF tokens, metadata and hashed values', async () => {
    expect(await one('NGB014', `declare const v: string;
localStorage.setItem('theme', 'dark');
localStorage.setItem('XSRF-TOKEN', v);
localStorage.setItem('tokenExpiry', String(Date.now()));
localStorage.setItem('pushToken', v);
declare function sha256(x: string): string;
declare const accessToken: string;
localStorage.setItem('fp', sha256(accessToken));
localStorage.setItem('lang', JSON.stringify({ locale: 'en', page: 2 }));`)).toEqual([]);
  });

  it('false-positive regression: payment data is NGB015, not NGB014', async () => {
    expect(await one('NGB014', `declare const cardNumber: string;\nlocalStorage.setItem('card', cardNumber);`)).toEqual([]);
  });
});
