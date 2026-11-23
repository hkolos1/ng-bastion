import { describe, expect, it } from 'vitest';
import { NG, one } from './helpers.js';

describe('NGB029 sensitive data in navigation state', () => {
  it('reports window.name with high severity', async () => {
    const res = await one('NGB029', `export function f(accessToken: string) { window.name = accessToken; }`);
    expect(res).toHaveLength(1);
    expect(res[0]!.severity).toBe('high');
  });

  it('reports history state and Router navigation state', async () => {
    const res = await one('NGB029', `${NG}export class C {
  constructor(private router: Router) {}
  go(form: { cardNumber: string; cvv: string }, refreshToken: string) {
    history.pushState({ refreshToken }, '', '/next');
    this.router.navigate(['/confirm'], { state: { cardNumber: form.cardNumber, cvv: form.cvv } });
  }
}`);
    expect(res.map((r) => r.severity)).toEqual(['medium', 'medium']);
  });

  it('safe: non-sensitive state', async () => {
    expect(await one('NGB029', `${NG}export class C { constructor(private router: Router) {} go(id: number) { window.name = 'main'; history.replaceState({ step: 2 }, ''); this.router.navigateByUrl('/x', { state: { from: id } }); } }`)).toEqual([]);
  });

  it('false-positive regression: Router-like objects and masked values', async () => {
    expect(await one('NGB029', `const router = { navigate: (_c: unknown, _o: unknown) => 0 };
export function f(maskedPan: string, token: string) { router.navigate([], { state: { token } }); history.pushState({ maskedPan }, ''); }`)).toEqual([]);
  });
});
