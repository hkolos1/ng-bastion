import { describe, expect, it } from 'vitest';
import { NG, findings, one } from './helpers.js';

describe('NGB016 sensitive data logging', () => {
  it('reports an access token passed to console.log (high, pattern)', async () => {
    const [f, ...rest] = await one('NGB016', `${NG}
export class Auth {
  accessToken = '';
  onLogin(res: { accessToken: string }) { this.accessToken = res.accessToken; console.log('logged in', this.accessToken); }
}`);
    expect(rest).toHaveLength(0);
    expect(f!.severity).toBe('high');
    expect(f!.confidence).toBe('high');
    expect(f!.message).toContain('console.log()');
    expect(f!.message).toContain('accessToken');
  });

  it('reports payment data sent to Sentry and dataLayer', async () => {
    const res = await one('NGB016', `import * as Sentry from '@sentry/angular';
declare const dataLayer: unknown[];
export function track(cardNumber: string, cvv: string) {
  Sentry.setExtra('card', cardNumber);
  dataLayer.push({ event: 'pay', cvv });
}`);
    expect(res.map((f) => f.message)).toEqual([
      expect.stringContaining('Sentry.setExtra()'),
      expect.stringContaining('dataLayer.push()'),
    ]);
    expect(res.every((f) => f.confidence === 'high')).toBe(true);
  });

  it('uses the declared type of a logged object as medium-confidence evidence (cross-file)', async () => {
    const res = await findings('NGB016', {
      'src/app/models.ts': `export interface LoginRequest { username: string; password: string }`,
      'src/app/login.ts': `import { LoginRequest } from './models';
export function submit(req: LoginRequest) { console.debug('submitting', req); }`,
    });
    expect(res).toHaveLength(1);
    expect(res[0]!.confidence).toBe('medium');
    expect(res[0]!.evidence.join(' ')).toContain('password');
  });

  it('does not report generic objects without evidence or token metadata', async () => {
    expect(await one('NGB016', `export class C {
  tokenExpiry = 0;
  user = { id: 1, name: 'a' };
  log() { console.log(this.user); console.log('expires', this.tokenExpiry); console.info('token refreshed'); }
}`)).toEqual([]);
  });

  it('safe equivalent: masked values are not reported', async () => {
    expect(await one('NGB016', `declare function maskPan(v: string): string;
export function f(cardNumber: string, accessToken: string) {
  console.log(maskPan(cardNumber));
  console.log('card', cardNumber.slice(-4));
  console.log(accessToken.replace(/./g, '*'));
}`)).toEqual([]);
  });

  it('false-positive regression: a project logger method named log is not console', async () => {
    expect(await one('NGB016', `class Logger { log(..._a: unknown[]) {} }
export function f(password: string) { new Logger().log(password); }`)).toEqual([]);
  });
});
