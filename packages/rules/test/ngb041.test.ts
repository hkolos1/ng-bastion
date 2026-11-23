import { describe, expect, it } from 'vitest';
import { findings, one } from './helpers.js';

describe('NGB041 unsafe inline state serialization', () => {
  it('reports JSON.stringify inside an inline script string (high when traced to a request value)', async () => {
    const res = await findings('NGB041', {
      'src/server.ts': `import type { Request, Response } from 'express';
declare const html: string;
export function render(req: Request, res: Response, user: { name: string; email: string }) {
  res.send(html.replace('</head>', \`<script>window.__USER__ = \${JSON.stringify(user)}</script></head>\`));
  res.send('<script type="application/json" id="q">' + JSON.stringify(req.query) + '</script>');
}`,
    });
    expect(res).toHaveLength(2);
    expect(res.map((r) => r.confidence).sort()).toEqual(['high', 'medium']);
  });

  it('reports script textContent set during SSR (isPlatformServer guard)', async () => {
    const res = await one('NGB041', `import { isPlatformServer } from '@angular/common';
declare const platformId: object;
export function hydrate(doc: Document, state: object) {
  if (isPlatformServer(platformId)) {
    const s = doc.createElement('script');
    s.textContent = JSON.stringify(state);
    doc.head.appendChild(s);
  }
}`);
    expect(res).toHaveLength(1);
  });

  it('safe: escaped JSON, serialize-javascript, constants, browser-only script text', async () => {
    expect(await findings('NGB041', {
      'src/server.ts': `declare function serialize(v: unknown): string;
export function a(user: object) {
  const json = JSON.stringify(user).replace(/</g, '\\\\u003c');
  return \`<script>window.__U__ = \${json}</script>\` + \`<script>var s = \${serialize(user)}</script>\` + '<script>var v = ' + '1' + '</script>';
}
export function b(user: object) { return \`<div data-x="\${user}"></div><script src="/main.js"></script>\`; }`,
      'src/app/live.ts': `export function c(state: object) { const s = document.createElement('script'); s.textContent = JSON.stringify(state); }`,
    })).toEqual([]);
  });

  it('false-positive regression: closed scripts before the value are not inline-script context', async () => {
    expect(await one('NGB041', `export function f(name: string) { return \`<script src="/a.js"></script><p>\${name}</p>\`; }`)).toEqual([]);
  });
});
