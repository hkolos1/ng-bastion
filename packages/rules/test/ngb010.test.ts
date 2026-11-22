import { describe, expect, it } from 'vitest';
import { NG, findings, scanFiles } from './helpers.js';

const cmp = (tpl: string) => ({ 'src/app/c.ts': `${NG}@Component({ selector: 'c', template: \`${tpl}\` })\nexport class C { url: unknown; }` });

describe('NGB010 overly permissive iframe', () => {
  it('reports allow-scripts + allow-same-origin in a template (high confidence, medium severity)', async () => {
    const [f, ...rest] = await findings('NGB010', cmp(`<iframe src="/help.html" sandbox="allow-scripts allow-same-origin"></iframe>`));
    expect(rest).toHaveLength(0);
    expect(f!.confidence).toBe('high');
    expect(f!.severity).toBe('medium');
    expect(f!.location.line).toBe(5);
  });

  it('reports powerful permission delegation to a dynamic source', async () => {
    const res = await findings('NGB010', cmp(`<iframe [src]="url" sandbox="allow-scripts" allow="camera; microphone"></iframe>`));
    expect(res).toHaveLength(1);
    expect(res[0]!.message).toMatch(/camera, microphone/);
  });

  it('reports unsandboxed dynamic iframes only with low confidence', async () => {
    const [f] = await findings('NGB010', cmp(`<iframe [src]="url"></iframe>`));
    expect(f!.confidence).toBe('low');
    expect(f!.evidenceKind).toBe('heuristic');
  });

  it('does not report static same-origin iframes or narrow sandboxes (safe equivalents)', async () => {
    expect(await findings('NGB010', cmp(`<iframe src="/docs/embed.html"></iframe><iframe [src]="url" sandbox="allow-scripts" allow="camera https://video.example.com"></iframe>`))).toEqual([]);
  });

  it('dynamic sandbox bindings produce a diagnostic instead of a finding', async () => {
    const r = await scanFiles(cmp(`<iframe src="/x.html" [attr.sandbox]="mode"></iframe>`), ['NGB010']);
    expect(r.findings).toEqual([]);
    expect(r.diagnostics.some((d) => d.code === 'unsupported-construct' && /dynamic sandbox/.test(d.message))).toBe(true);
  });

  it('covers DOM-created iframes and index.html', async () => {
    const res = await findings('NGB010', {
      'src/main.ts': `export function embed(url: string) {
  const f = document.createElement('iframe');
  f.setAttribute('sandbox', 'allow-scripts allow-same-origin');
  f.src = url;
  document.body.appendChild(f);
}`,
      'src/index.html': `<html><body>\n<iframe src="https://maps.example.com" allow="geolocation"></iframe>\n<iframe src="/a" sandbox="allow-same-origin allow-scripts"></iframe></body></html>`,
    });
    expect(res.map((f) => f.location.file).sort()).toEqual(['src/index.html', 'src/main.ts']);
  });

  it('false-positive regression: external template file is analysed with correct lines', async () => {
    const res = await findings('NGB010', {
      'src/app/x.ts': `${NG}@Component({ selector: 'x', templateUrl: './x.html' })\nexport class X {}`,
      'src/app/x.html': `<p>hi</p>\n<iframe src="/a" sandbox="allow-forms"></iframe>\n<iframe src="/b" sandbox="allow-scripts allow-same-origin"></iframe>`,
    });
    expect(res).toHaveLength(1);
    expect(res[0]!.location).toMatchObject({ file: 'src/app/x.html', line: 3 });
  });
});
