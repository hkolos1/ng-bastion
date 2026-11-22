import { describe, expect, it } from 'vitest';
import { NG, findings, one } from './helpers.js';

const SSR = `${NG}import { TransferState, makeStateKey } from '@angular/core';
import { provideClientHydration, withHttpTransferCacheOptions } from '@angular/platform-browser';
`;

describe('NGB020 sensitive SSR transfer cache', () => {
  it('reports a session token stored in TransferState (high)', async () => {
    const [f, ...rest] = await one('NGB020', `${SSR}
const AUTH = makeStateKey<string>('auth');
export class Boot {
  private state = inject(TransferState);
  run(accessToken: string) { this.state.set(AUTH, accessToken); }
}`);
    expect(rest).toHaveLength(0);
    expect(f!.confidence).toBe('high');
    expect(f!.severity).toBe('high');
  });

  it('reports per-user data from an authenticated endpoint across files with a trace (medium)', async () => {
    const res = await findings('NGB020', {
      'src/app/me.service.ts': `${SSR}
export class MeService { private http = inject(HttpClient); me() { return this.http.get('/api/me'); } }`,
      'src/app/boot.ts': `${SSR}import { MeService } from './me.service';
const KEY = makeStateKey<unknown>('current');
export class Boot {
  constructor(private ts: TransferState, private svc: MeService) {}
  run() { this.svc.me().subscribe(data => this.ts.set(KEY, data)); }
}`,
    });
    expect(res).toHaveLength(1);
    expect(res[0]!.confidence).toBe('medium');
    expect(res[0]!.trace![0]!.file).toBe('src/app/me.service.ts');
  });

  it('reports HTTP transfer cache options that include authenticated requests or sensitive headers', async () => {
    const res = await one('NGB020', `${SSR}
export const a = provideClientHydration(withHttpTransferCacheOptions({ includeRequestsWithAuthHeaders: true }));
export const b = provideClientHydration(withHttpTransferCacheOptions({ includeHeaders: ['ETag', 'Set-Cookie'], filter: () => true }));`);
    expect(res).toHaveLength(2);
    const [auth, headers] = res.sort((x, y) => x.location.line - y.location.line);
    expect(auth!.confidence).toBe('high');
    expect(headers!.message).toContain('set-cookie');
    expect(headers!.confidence).toBe('medium');
  });

  it('does not report public state (products, translations, config)', async () => {
    expect(await one('NGB020', `${SSR}
const PRODUCTS = makeStateKey<unknown>('products');
export class C {
  private state = inject(TransferState);
  private http = inject(HttpClient);
  load() { this.http.get('/api/products').subscribe(products => this.state.set(PRODUCTS, products)); }
  i18n(translations: Record<string, string>) { this.state.set(makeStateKey('i18n'), translations); }
}`)).toEqual([]);
  });

  it('safe equivalent: default HTTP transfer cache options are not reported', async () => {
    expect(await one('NGB020', `${SSR}
export const p = provideClientHydration(withHttpTransferCacheOptions({ includePostRequests: false, includeHeaders: ['ETag'] }));`)).toEqual([]);
  });

  it('false-positive regression: set() on a Map or project class is ignored', async () => {
    expect(await one('NGB020', `export class Cache { set(_k: string, _v: unknown) {} }
export function f(accessToken: string) { new Map().set('t', accessToken); new Cache().set('t', accessToken); }`)).toEqual([]);
  });
});
