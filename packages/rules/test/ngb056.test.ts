import { describe, expect, it } from 'vitest';
import { one } from './helpers.js';

const tt = `declare const trustedTypes: { createPolicy(n: string, o: object): unknown };\n`;

describe('NGB056 pass-through Trusted Types policy', () => {
  it('reports pass-through default (high) and named (medium) policies', async () => {
    const res = await one('NGB056', `${tt}
export function init() {
  trustedTypes.createPolicy('default', { createHTML: (s: string) => s, createScriptURL(s: string) { return String(s); } });
  (window as any).trustedTypes.createPolicy('legacy-widget', { createScript: function (s: string) { return s as string; } });
}`);
    expect(res.map((f) => f.severity)).toEqual(['high', 'high', 'medium']);
    expect(res[0]!.message).toMatch(/every DOM sink/);
  });

  it('reports a policy function declared elsewhere', async () => {
    const res = await one('NGB056', `${tt}
const identity = (s: string) => s;
export const p = trustedTypes.createPolicy('app', { createHTML: identity });`);
    expect(res).toHaveLength(1);
  });

  it('safe: sanitizing and validating policies', async () => {
    expect(await one('NGB056', `${tt}import DOMPurify from 'dompurify';
export const p = trustedTypes.createPolicy('default', {
  createHTML: (s: string) => DOMPurify.sanitize(s),
  createScriptURL: (s: string) => { if (new URL(s, location.href).origin !== location.origin) throw new TypeError('blocked'); return s; },
  createScript: (s: string) => (s === 'ok()' ? s : ''),
});`)).toEqual([]);
  });

  it('false-positive regression: other createPolicy() methods and non-factory members', async () => {
    expect(await one('NGB056', `class Registry { createPolicy(_n: string, _o: object) { return 1; } }
export const r = new Registry().createPolicy('default', { createHTML: (s: string) => s });
declare const trustedTypes: { createPolicy(n: string, o: object): unknown };
export const q = trustedTypes.createPolicy('x', { name: (s: string) => s });`)).toEqual([]);
  });
});
