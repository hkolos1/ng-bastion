import { describe, expect, it } from 'vitest';
import { NG, findings } from './helpers.js';

const SERVER = { 'src/main.server.ts': `export default function bootstrap() { return null; }` };

describe('NGB055 cross-request state in SSR module scope', () => {
  it('reports user data from HTTP and credentials written to module state', async () => {
    const res = await findings('NGB055', {
      ...SERVER,
      'src/app/auth.service.ts': `${NG}import { tap } from 'rxjs';
let currentUser: unknown;
const tokens = new Map<string, string>();
export class Auth {
  private http = inject(HttpClient);
  load() { return this.http.get('/api/me').pipe(tap((u) => (currentUser = u))); }
  remember(id: string, accessToken: string) { tokens.set(id, accessToken); }
}`,
    });
    expect(res.map((f) => `${f.severity}/${f.confidence}`).sort()).toEqual(['high/high', 'medium/medium']);
    expect(res.find((f) => f.severity === 'medium')!.message).toMatch(/currentUser/);
  });

  it('reports per-user names with low confidence', async () => {
    const [f, ...rest] = await findings('NGB055', {
      ...SERVER,
      'src/app/cart.ts': `const state: { cart?: unknown } = {};
export function setCart(c: unknown) { state.cart = c; }`,
    });
    expect(rest).toEqual([]);
    expect(f!.confidence).toBe('low');
  });

  it('safe: browser-only projects, browser-guarded writes, initialization and services', async () => {
    const files = {
      'src/app/a.ts': `${NG}import { PLATFORM_ID } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
let currentUser: unknown;
const LABELS = new Map([['a', 'b']]);
LABELS.set('c', 'd');
export class A {
  private platform = inject(PLATFORM_ID);
  user = signal<unknown>(undefined);
  set(u: unknown) {
    if (isPlatformBrowser(this.platform)) currentUser = u;
    if (typeof window !== 'undefined') { currentUser = u; }
    this.user.set(u);
  }
}`,
    };
    expect(await findings('NGB055', files)).toEqual([]);
    expect(await findings('NGB055', { ...files, ...SERVER })).toEqual([]);
    // Without SSR the same module state is per user.
    expect(await findings('NGB055', { 'src/app/b.ts': `let currentUser: unknown; export function s(u: unknown) { currentUser = u; }` })).toEqual([]);
  });

  it('false-positive regression: server entry files, locals and generic counters', async () => {
    expect(await findings('NGB055', {
      ...SERVER,
      'src/server.ts': `import express from 'express';
const sessions = new Map<string, unknown>();
export function h(req: { body: { user: unknown } }) { sessions.set('x', req.body.user); }`,
      'src/app/a.ts': `let retries = 0;
const seen = new Set<string>();
export function f(id: string) { retries = retries + 1; seen.add(id); let user = {}; user = { a: 1 }; return user; }`,
    })).toEqual([]);
  });
});
