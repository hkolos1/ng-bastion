import { describe, expect, it } from 'vitest';
import { NG, findings, one } from './helpers.js';

describe('NGB037 regular expression injection', () => {
  it('reports new RegExp from a query parameter (medium) and String.match with a message string', async () => {
    const res = await one('NGB037', `${NG}export class S {
  constructor(private route: ActivatedRoute) {}
  filter(items: string[]) { const q = this.route.snapshot.queryParamMap.get('q') ?? ''; return items.filter((i) => new RegExp(q, 'i').test(i)); }
  listen() { window.addEventListener('message', (e: MessageEvent) => 'abc'.match(e.data as string)); }
}`);
    expect(res).toHaveLength(2);
    expect(res[0]!.severity).toBe('medium');
  });

  it('reports SSR server code with high severity', async () => {
    const res = await findings('NGB037', {
      'src/server.ts': `declare const location: Location;\nexport function route(u: string) { return new RegExp(location.search.slice(3)).test(u); }`,
    });
    expect(res[0]!.severity).toBe('high');
  });

  it('safe: escaped input and constant patterns', async () => {
    expect(await one('NGB037', `${NG}declare function escapeRegExp(s: string): string;
export class S {
  constructor(private route: ActivatedRoute) {}
  run(items: string[]) {
    const q = escapeRegExp(this.route.snapshot.queryParamMap.get('q') ?? '');
    items.filter((i) => new RegExp(q).test(i));
    items.filter((i) => new RegExp('^a+$').test(i));
    'x'.match(/abc/);
  }
}`)).toEqual([]);
  });

  it('false-positive regression: RegExp object arguments and user-typed search are low', async () => {
    const res = await one('NGB037', `export function f(input: HTMLInputElement, re: RegExp) { 'x'.match(re); return new RegExp(input.value); }`);
    expect(res).toHaveLength(1);
    expect(res[0]!.severity).toBe('low');
  });
});
