import { describe, expect, it } from 'vitest';
import { findings, one } from './helpers.js';

describe('NGB067 sensitive data sent to analytics', () => {
  it('reports credentials and payment data to analytics SDKs', async () => {
    const res = await one('NGB067', `declare const analytics: any; declare const mixpanel: any; declare const LogRocket: any;
export function f(form: { password: string; plan: string }, accessToken: string, cardNumber: string) {
  analytics.track('Signed Up', { password: form.password });
  mixpanel.register({ accessToken });
  LogRocket.identify('u1', { cardNumber });
}`);
    expect(res).toHaveLength(3);
    expect(res.every((f) => f.severity === 'medium')).toBe(true);
  });

  it('reports personal data in event payloads (gtag, dataLayer, named SDK imports)', async () => {
    const res = await findings('NGB067', {
      'src/app/a.ts': `import { track } from '@amplitude/analytics-browser';
declare function gtag(...a: unknown[]): void; declare const dataLayer: unknown[];
export function f(user: { email: string; phoneNumber: string }) {
  gtag('event', 'purchase', { email: user.email });
  dataLayer.push({ event: 'signup', phoneNumber: user.phoneNumber });
  track('Viewed', { dateOfBirth: '2000-01-01' });
}`,
    });
    expect(res.map((f) => f.location.line)).toEqual([4, 5, 6]);
    expect(res.every((f) => f.severity === 'low')).toBe(true);
  });

  it('safe: opaque IDs, identify() with e-mail traits, non-sensitive events', async () => {
    expect(await one('NGB067', `declare const analytics: any; declare const posthog: any;
export function f(userId: string, email: string, plan: string) {
  analytics.identify(userId, { email });
  posthog.capture('upgrade', { plan });
  analytics.page();
}`)).toEqual([]);
  });

  it('false-positive regression: NGB016 sinks are not repeated, project "analytics" services, metadata names', async () => {
    expect(await one('NGB067', `declare function gtag(...a: unknown[]): void;
class Analytics { track(e: string, p: object) { return [e, p]; } }
export function f(accessToken: string, a: Analytics, emailVerified: boolean) {
  gtag('event', 'x', { accessToken });
  a.track('x', { accessToken });
  gtag('event', 'y', { emailVerified });
}`)).toEqual([]);
  });
});
