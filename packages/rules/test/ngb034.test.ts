import { describe, expect, it } from 'vitest';
import { NG, one } from './helpers.js';

describe('NGB034 untrusted postMessage target origin', () => {
  it('reports replies to an unvalidated event.origin (high with a sensitive payload)', async () => {
    const res = await one('NGB034', `export function init(accessToken: string) {
  window.addEventListener('message', (e: MessageEvent) => {
    (e.source as Window).postMessage({ accessToken }, e.origin);
  });
}`);
    expect(res).toHaveLength(1);
    expect(res[0]!.severity).toBe('high');
  });

  it('reports target origins from the referrer and query parameters', async () => {
    const res = await one('NGB034', `${NG}export class W {
  constructor(private route: ActivatedRoute) {}
  ready() {
    window.parent.postMessage({ ready: true }, new URL(document.referrer).origin);
    window.opener.postMessage('done', { targetOrigin: this.route.snapshot.queryParamMap.get('origin')! });
  }
}`);
    expect(res).toHaveLength(2);
    expect(res.every((r) => r.severity === 'medium')).toBe(true);
  });

  it('safe: validated sender, constant origins', async () => {
    expect(await one('NGB034', `const ALLOWED = ['https://app.example.com'];
export function init(accessToken: string) {
  window.addEventListener('message', (e: MessageEvent) => {
    if (!ALLOWED.includes(e.origin)) return;
    (e.source as Window).postMessage({ accessToken }, e.origin);
  });
  window.parent.postMessage('x', 'https://app.example.com');
}`)).toEqual([]);
  });

  it('false-positive regression: the own origin (location.origin) is not attacker-controlled', async () => {
    expect(await one('NGB034', `export function f(code: string) { window.postMessage({ code }, window.location.origin); window.opener.postMessage('x', location.protocol + '//' + location.host); }`)).toEqual([]);
  });

  it('false-positive regression: worker postMessage and wildcard (NGB006) are not reported here', async () => {
    expect(await one('NGB034', `export function f(w: Worker, data: string) { w.postMessage(data); window.parent.postMessage(data, '*'); }`)).toEqual([]);
  });
});
