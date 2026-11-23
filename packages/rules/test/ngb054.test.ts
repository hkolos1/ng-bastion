import { describe, expect, it } from 'vitest';
import { findings, one } from './helpers.js';

describe('NGB054 untrusted base URL', () => {
  it('reports <base href> set from the URL (high) and APP_BASE_HREF from a query parameter (medium)', async () => {
    const res = await findings('NGB054', {
      'src/app/base.ts': `export function setBase() {
  const base = document.querySelector('base')!;
  base.href = new URLSearchParams(location.search).get('cdn') ?? '/';
  const b2 = document.createElement('base');
  b2.setAttribute('href', location.hash.slice(1));
}`,
      'src/app/app.config.ts': `import { APP_BASE_HREF } from '@angular/common';
export const appConfig = { providers: [
  { provide: APP_BASE_HREF, useFactory: () => new URLSearchParams(location.search).get('base') ?? '/' },
  { provide: APP_BASE_HREF, useValue: window.name },
] };`,
    });
    expect(res.map((f) => f.severity).sort()).toEqual(['high', 'high', 'medium', 'medium']);
    expect(res.every((f) => f.evidenceKind === 'dataflow')).toBe(true);
  });

  it('reports a bare "/" prefix with low confidence', async () => {
    const [f] = await one('NGB054', `import { APP_BASE_HREF } from '@angular/common';
export const p = [{ provide: APP_BASE_HREF, useFactory: () => '/' + location.hash.slice(1) }];`);
    expect(f!.confidence).toBe('low');
  });

  it('safe: constant bases, pinned prefixes and validated tenants', async () => {
    expect(await one('NGB054', `import { APP_BASE_HREF } from '@angular/common';
const seg = location.pathname.split('/')[1];
export const p = [
  { provide: APP_BASE_HREF, useValue: '/app/' },
  { provide: APP_BASE_HREF, useFactory: () => '/t/' + seg + '/' },
  { provide: APP_BASE_HREF, useFactory: () => \`https://cdn.example.com/\${seg}/\` },
];
export function f() { document.querySelector('base')!.href = '/static/'; }`)).toEqual([]);
  });

  it('false-positive regression: href on anchors and project tokens named like APP_BASE_HREF', async () => {
    expect(await one('NGB054', `import { InjectionToken } from '@angular/core';
const APP_BASE_HREF = new InjectionToken<string>('mine');
export const p = [{ provide: APP_BASE_HREF, useValue: location.hash }];
export function f(a: HTMLAnchorElement) { a.href = location.hash.slice(1); document.querySelector('a')!.setAttribute('href', location.hash); }`)).toEqual([]);
  });
});
