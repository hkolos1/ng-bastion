import { describe, expect, it } from 'vitest';
import { NG, findings } from './helpers.js';

describe('NGB030 permissive referrer policy', () => {
  it('reports unsafe-url in index.html and no-referrer-when-downgrade on an element', async () => {
    const res = await findings('NGB030', {
      'src/index.html': '<html><head><meta name="referrer" content="unsafe-url"></head><body><img src="https://x/y.png" referrerpolicy="no-referrer-when-downgrade"></body></html>',
      'src/main.ts': 'export {};',
    });
    expect(res.map((r) => r.severity).sort()).toEqual(['low', 'medium']);
  });

  it('reports templates, fetch options, headers and hosting configs', async () => {
    const res = await findings('NGB030', {
      'src/app/c.ts': `${NG}@Component({ selector: 'c', template: '<a href="https://partner.example" referrerpolicy="unsafe-url">p</a>' })
export class C {}
export function f(res: { setHeader(k: string, v: string): void }) {
  fetch('/x', { referrerPolicy: 'unsafe-url' });
  res.setHeader('Referrer-Policy', 'no-referrer, unsafe-url');
}`,
      'firebase.json': JSON.stringify({ hosting: { headers: [{ source: '**', headers: [{ key: 'Referrer-Policy', value: 'unsafe-url' }] }] } }),
    });
    expect(res).toHaveLength(4);
  });

  it('safe: strict policies and fallback lists ending in a strict policy', async () => {
    expect(await findings('NGB030', {
      'src/index.html': '<meta name="referrer" content="strict-origin-when-cross-origin">',
      'src/app/c.ts': `export function f(res: { setHeader(k: string, v: string): void }) { fetch('/x', { referrerPolicy: 'no-referrer' }); res.setHeader('Referrer-Policy', 'unsafe-url, same-origin'); }`,
    })).toEqual([]);
  });

  it('false-positive regression: commented-out markup and unrelated attributes', async () => {
    expect(await findings('NGB030', {
      'src/index.html': '<!-- <meta name="referrer" content="unsafe-url"> --><meta name="description" content="unsafe-url">',
      'src/app/c.ts': `export const x = { policy: 'unsafe-url' };`,
    })).toEqual([]);
  });
});
