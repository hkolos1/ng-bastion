import { describe, expect, it } from 'vitest';
import { findings, one } from './helpers.js';

const html = (map: string) => `<!doctype html><html><head><script type="importmap">${map}</script></head><body></body></html>`;

describe('NGB100 untrusted import map', () => {
  it('reports plain-HTTP import map entries in index.html', async () => {
    const res = await findings('NGB100', { 'src/main.ts': 'export {};', 'src/index.html': html('{ "imports": { "lib": "http://cdn.example.com/lib.js" }, "scopes": { "/a/": { "x": "http://cdn.example.com/x.js" } } }') });
    expect(res).toHaveLength(2);
    expect(res[0]!.location.file).toBe('src/index.html');
  });

  it('reports import maps filled from untrusted data and importShim.addImportMap', async () => {
    const res = await one('NGB100', `declare const importShim: { addImportMap(m: unknown): void };
export function boot() {
  const app = new URLSearchParams(location.search).get('app');
  const s = document.createElement('script');
  s.type = 'importmap';
  s.textContent = '{"imports":{"app":"' + app + '"}}';
  document.head.append(s);
  importShim.addImportMap(JSON.parse(localStorage.getItem('map')!));
}`);
    expect(res).toHaveLength(2);
  });

  it('safe: same-origin / https entries and constant dynamic maps', async () => {
    expect(await findings('NGB100', {
      'src/index.html': html('{ "imports": { "app": "/assets/app.js", "lib": "https://cdn.example.com/lib.js" } }'),
      'src/main.ts': `const s = document.createElement('script'); s.type = 'importmap'; s.textContent = JSON.stringify({ imports: { app: '/app.js' } });`,
    })).toEqual([]);
  });

  it('false-positive regression: untrusted text in ordinary script elements, commented-out and invalid maps', async () => {
    expect(await findings('NGB100', {
      'src/index.html': `<!-- <script type="importmap">{"imports":{"a":"http://x.example.com/a.js"}}</script> --><script type="importmap">{ not json http://x.example.com }</script>`,
      'src/main.ts': `const s = document.createElement('script'); s.type = 'module'; s.textContent = location.hash;`,
    })).toEqual([]);
  });
});
