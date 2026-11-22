import { describe, expect, it } from 'vitest';
import { NG, one } from './helpers.js';

describe('NGB005 untrusted dynamic script loading', () => {
  it('reports a script src taken from the URL', async () => {
    const [f] = await one('NGB005', `export function load() {
  const s = document.createElement('script');
  s.src = new URLSearchParams(location.search).get('widget') ?? '';
  document.body.appendChild(s);
}`);
    expect(f!.confidence).toBe('high');
    expect(f!.message).toContain('script src');
  });

  it('reports Renderer2-created scripts and inline script text as critical', async () => {
    const res = await one('NGB005', `${NG}
export class L {
  constructor(private r: Renderer2) {}
  private script = this.r.createElement('script');
  go(e: MessageEvent) {
    this.r.setAttribute(this.script, 'src', e.data.url);
    const inline = document.createElement('script');
    inline.textContent = e.data.code;
  }
}`);
    expect(res).toHaveLength(2);
    expect(res.find((f) => f.message.includes('inline'))!.severity).toBe('critical');
  });

  it('reports plain-http constant script URLs', async () => {
    const [f] = await one('NGB005', `const s = document.createElement('script'); s.src = 'http://cdn.example.com/a.js';`);
    expect(f!.severity).toBe('medium');
    expect(f!.evidenceKind).toBe('pattern');
  });

  it('does not report constant https or fixed-origin URLs (trusted location)', async () => {
    expect(await one('NGB005', `export function load(version: string) {
  const a = document.createElement('script'); a.src = 'https://cdn.example.com/chat.js';
  const b = document.createElement('script'); b.src = \`https://cdn.example.com/widget/\${version}/w.js\`;
}`)).toEqual([]);
  });

  it('reports dynamic import() with an untrusted specifier', async () => {
    const [f] = await one('NGB005', `export async function plugin() { return import(location.hash.slice(1)); }`);
    expect(f!.message).toContain('import()');
  });

  it('false-positive regression: src on non-script elements is ignored', async () => {
    expect(await one('NGB005', `const img = document.createElement('img'); img.src = location.hash;`)).toEqual([]);
  });
});
