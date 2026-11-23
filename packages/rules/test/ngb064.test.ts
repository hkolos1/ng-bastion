import { describe, expect, it } from 'vitest';
import { NG, one } from './helpers.js';

describe('NGB064 untrusted CSS injection', () => {
  it('reports untrusted CSS in cssText, style attributes, <style> text and style sheets', async () => {
    const res = await one('NGB064', `${NG}
export class C {
  private route = inject(ActivatedRoute);
  private renderer = inject(Renderer2);
  run(el: HTMLElement, styleEl: HTMLStyleElement, sheet: CSSStyleSheet) {
    const css = this.route.snapshot.queryParams['css'];
    el.style.cssText = css;
    el.setAttribute('style', css);
    this.renderer.setAttribute(el, 'style', css);
    styleEl.textContent = css;
    sheet.insertRule(css);
    sheet.replaceSync(css);
  }
}`);
    expect(res).toHaveLength(6);
    expect(res[0]!.evidenceKind).toBe('dataflow');
  });

  it('reports postMessage data in a style sheet', async () => {
    expect(await one('NGB064', `window.addEventListener('message', (e: MessageEvent) => { const s = document.createElement('style'); s.textContent = e.data; });`)).toHaveLength(1);
  });

  it('safe: constants, single validated properties, setProperty', async () => {
    expect(await one('NGB064', `${NG}
export class C {
  private route = inject(ActivatedRoute);
  run(el: HTMLElement, styleEl: HTMLStyleElement) {
    el.style.cssText = 'display: none';
    styleEl.textContent = ':root { --accent: #336699 }';
    el.style.setProperty('--accent', this.route.snapshot.queryParams['c']);
  }
}`)).toEqual([]);
  });

  it('false-positive regression: unresolved parameters and non-DOM "style" properties', async () => {
    expect(await one('NGB064', `export function f(el: HTMLElement, css: string, cfg: { style: string }, q: URLSearchParams) { el.style.cssText = css; cfg.style = location.search; }`)).toEqual([]);
  });
});
