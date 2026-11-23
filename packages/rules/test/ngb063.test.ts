import { describe, expect, it } from 'vitest';
import { one } from './helpers.js';

describe('NGB063 DOM-clobberable global in a sensitive sink', () => {
  it('reports optional globals that reach script / navigation / HTML sinks', async () => {
    const res = await one('NGB063', `export function load() {
  const cfg = (window as any).APP_CONFIG || {};
  const s = document.createElement('script');
  s.src = cfg.cdn + '/widget.js';
  location.assign((window as any).returnUrl);
  const a = document.createElement('a');
  a.setAttribute('href', (document as any).helpLink ?? '/help');
  return import((window as any)['pluginUrl']);
}`);
    expect(res).toHaveLength(4);
    expect(res[0]!.confidence).toBe('medium');
    expect(res.find((f) => f.message.includes('returnUrl'))?.confidence).toBe('low');
    expect(res.find((f) => f.message.includes('helpLink'))?.message).toMatch(/name="helpLink"/);
  });

  it('reports declared-but-never-assigned globals (declare global)', async () => {
    const res = await one('NGB063', `declare global { interface Window { ENV?: { api: string } } }
export function f(el: HTMLIFrameElement) { el.src = window.ENV?.api ?? 'about:blank'; }`);
    expect(res).toHaveLength(1);
  });

  it('safe: standard DOM properties, globals the app assigns, non-DOM sinks', async () => {
    expect(await one('NGB063', `declare global { interface Window { APP: { cdn: string } } }
window.APP = { cdn: 'https://cdn.example.com' };
export function f(el: HTMLScriptElement, model: { href: string }) {
  el.src = window.APP.cdn + '/x.js';
  el.src = window.location.origin + '/x.js';
  model.href = (window as any).someLink;
  document.body.innerHTML = document.title;
}`)).toEqual([]);
  });

  it('false-positive regression: locally declared "window" variables and computed values', async () => {
    expect(await one('NGB063', `export function f(window: { cfg: string }, el: HTMLScriptElement) { el.src = window.cfg; el.src = String((globalThis as any).getUrl?.()); }`)).toEqual([]);
  });
});
