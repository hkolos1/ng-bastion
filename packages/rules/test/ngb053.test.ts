import { describe, expect, it } from 'vitest';
import { NG, findings, one } from './helpers.js';

describe('NGB053 runtime template compilation', () => {
  it('reports a runtime Component() whose template comes from the URL (critical, dataflow)', async () => {
    const [f, ...rest] = await one('NGB053', `${NG}
export class Builder {
  private route = inject(ActivatedRoute);
  build() {
    const layout = this.route.snapshot.queryParams['layout'];
    return Component({ selector: 'app-dyn', template: layout })(class {});
  }
}`);
    expect(rest).toEqual([]);
    expect(f!.severity).toBe('critical');
    expect(f!.evidenceKind).toBe('dataflow');
    expect(f!.trace![0]!.description).toMatch(/layout/);
  });

  it('reports HTTP-provided templates (high) and unresolved dynamic templates (low)', async () => {
    const res = await findings('NGB053', {
      'src/app/a.ts': `${NG}import { ɵcompileComponent } from '@angular/core';
export class Cms {
  private http = inject(HttpClient);
  load(type: object) { this.http.get<string>('/api/tpl').subscribe((tpl) => ɵcompileComponent(type as never, { template: tpl })); }
}
export function make(tpl: string) { @Component({ selector: 'x', template: tpl }) class X {} return X; }`,
    });
    expect(res.map((f) => `${f.severity}/${f.confidence}`).sort()).toEqual(['high/medium', 'medium/low']);
  });

  it('safe: constant templates, constants from other declarations and constant template literals', async () => {
    expect(await findings('NGB053', {
      'src/app/tpl.ts': `export const TPL = '<p>{{ x }}</p>';`,
      'src/app/a.ts': `${NG}import { TPL } from './tpl';
const WRAP = \`<section>\${TPL}</section>\`;
@Component({ selector: 'a', template: '<p>{{ a }}</p>' }) export class A { a = 1; }
@Component({ selector: 'b', template: TPL }) export class B {}
@Component({ selector: 'c', template: WRAP }) export class C {}`,
    })).toEqual([]);
  });

  it('false-positive regression: project functions named Component and other template properties', async () => {
    expect(await one('NGB053', `function Component(o: { template: string }) { return o; }
export function f(t: string) { Component({ template: t }); return { template: t }; }`)).toEqual([]);
  });
});
