import { describe, expect, it } from 'vitest';
import { NG, findings, one } from './helpers.js';

describe('NGB050 document.domain relaxation', () => {
  it('reports document.domain assignments (also via injected DOCUMENT)', async () => {
    const res = await one('NGB050', `${NG}import { DOCUMENT } from '@angular/common';
export class C { private doc: Document = inject(DOCUMENT); run() { document.domain = 'example.com'; this.doc.domain = 'example.com'; } }`);
    expect(res).toHaveLength(2);
  });

  it('reports Origin-Agent-Cluster: ?0 in hosting configs and server code', async () => {
    const res = await findings('NGB050', {
      'firebase.json': JSON.stringify({ hosting: { headers: [{ source: '**', headers: [{ key: 'Origin-Agent-Cluster', value: '?0' }] }] } }),
      'src/server.ts': `export function f(res: { setHeader(k: string, v: string): void }) { res.setHeader('Origin-Agent-Cluster', '?0'); }`,
    });
    expect(res).toHaveLength(2);
    expect(res.every((r) => r.severity === 'low')).toBe(true);
  });

  it('safe: reading document.domain, Origin-Agent-Cluster: ?1', async () => {
    expect(await findings('NGB050', {
      'src/app/a.ts': `export const d = document.domain;`,
      'firebase.json': JSON.stringify({ hosting: { headers: [{ source: '**', headers: [{ key: 'Origin-Agent-Cluster', value: '?1' }] }] } }),
    })).toEqual([]);
  });

  it('false-positive regression: domain properties on other objects', async () => {
    expect(await one('NGB050', `export function f(cookie: { domain: string }) { cookie.domain = 'example.com'; }`)).toEqual([]);
  });
});
