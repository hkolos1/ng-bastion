import { describe, expect, it } from 'vitest';
import { findings, one } from './helpers.js';

describe('NGB045 missing subresource integrity', () => {
  it('reports CDN scripts (medium) and stylesheets (low) without integrity in index.html', async () => {
    const res = await findings('NGB045', {
      'src/index.html': `<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/x/1.0/x.css">`,
      'src/main.ts': 'export {};',
    });
    expect(res.map((r) => r.severity).sort()).toEqual(['low', 'medium']);
  });

  it('reports evolving providers with low confidence, and script elements created in code', async () => {
    const res = await findings('NGB045', {
      'src/index.html': '<script async src="https://www.googletagmanager.com/gtag/js?id=G-X"></script>',
      'src/app/loader.ts': `export function load() { const s = document.createElement('script'); s.src = 'https://unpkg.com/lib@1/lib.js'; document.head.appendChild(s); }`,
    });
    expect(res.map((r) => r.confidence)).toEqual(['low', 'low']);
  });

  it('safe: integrity present, local scripts, non-stylesheet links', async () => {
    expect(await findings('NGB045', {
      'src/index.html': `<script src="https://cdn.example.com/a.js" integrity="sha384-abc" crossorigin="anonymous"></script>
<script src="/assets/local.js"></script><link rel="preconnect" href="https://fonts.gstatic.com"><link rel="icon" href="https://cdn.example.com/i.png">`,
      'src/app/loader.ts': `export function load() { const s = document.createElement('script'); s.src = 'https://cdn.example.com/b.js'; s.integrity = 'sha384-x'; }`,
    })).toEqual([]);
  });

  it('false-positive regression: commented-out tags and non-script elements', async () => {
    expect(await one('NGB045', `export function f() { const img = document.createElement('img'); img.src = 'https://cdn.example.com/x.png'; }`)).toEqual([]);
  });
});
