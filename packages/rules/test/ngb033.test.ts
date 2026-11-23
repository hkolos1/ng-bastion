import { describe, expect, it } from 'vitest';
import { one } from './helpers.js';

describe('NGB033 window.open() without noopener', () => {
  it('reports external constant and dynamic URLs opened in a new window', async () => {
    const res = await one('NGB033', `export function f(url: string) {
  window.open('https://partner.example.com/offer', '_blank');
  window.open(url);
}`);
    expect(res.map((r) => r.confidence)).toEqual(['high', 'medium']);
    expect(res[0]!.severity).toBe('low');
  });

  it('safe: noopener / noreferrer, same-window targets, relative URLs', async () => {
    expect(await one('NGB033', `export function f(url: string) {
  window.open(url, '_blank', 'noopener,noreferrer');
  window.open('https://x.example', '_blank', 'noreferrer');
  window.open(url, '_self');
  window.open('/help', '_blank');
  window.open(\`/docs/\${url}\`);
}`)).toEqual([]);
  });

  it('false-positive regression: popups whose handle is used, and non-window open()', async () => {
    expect(await one('NGB033', `export function f(url: string) {
  const popup = window.open(url, 'auth', 'width=500');
  popup?.postMessage('hi', 'https://idp.example');
  const dialog = { open: (_u: string) => 0 };
  dialog.open('https://x.example');
}`)).toEqual([]);
  });
});
