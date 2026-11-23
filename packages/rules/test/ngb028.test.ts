import { describe, expect, it } from 'vitest';
import { one } from './helpers.js';

describe('NGB028 sensitive data on global objects', () => {
  it('reports window/globalThis properties holding credentials', async () => {
    const res = await one('NGB028', `export function f(res: { access_token: string }, apiKey: string) {
  (window as any).__AUTH__ = { accessToken: res.access_token };
  (globalThis as any).apiKey = apiKey;
  (window as any)['sessionId'] = 'x';
}`);
    expect(res).toHaveLength(3);
    expect(res.every((r) => r.snippet === undefined)).toBe(true);
  });

  it('reports Object.defineProperty(window, …)', async () => {
    const res = await one('NGB028', `export function f(jwt: string) { Object.defineProperty(window, 'jwt', { value: jwt }); }`);
    expect(res).toHaveLength(1);
  });

  it('safe: non-sensitive globals and window.location', async () => {
    expect(await one('NGB028', `export function f(cfg: { theme: string }) { (window as any).appVersion = '1.0'; (window as any).config = cfg; window.location.href = '/'; }`)).toEqual([]);
  });

  it('false-positive regression: local variables named window and window.name (NGB029)', async () => {
    expect(await one('NGB028', `export function f(token: string) { const window = { token: '' }; window.token = token; }
export function g(token: string) { globalThis.name = token; }`)).toEqual([]);
  });
});
