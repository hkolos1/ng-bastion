import { describe, expect, it } from 'vitest';
import { NG, one } from './helpers.js';

describe('NGB036 prototype pollution', () => {
  it('reports lodash merge of message data and set() with a URL path', async () => {
    const res = await one('NGB036', `${NG}import { merge, set } from 'lodash-es';
export class C {
  settings = {};
  constructor(private route: ActivatedRoute) {
    window.addEventListener('message', (e: MessageEvent) => merge(this.settings, JSON.parse(e.data)));
  }
  apply() { set(this.settings, this.route.snapshot.queryParamMap.get('path')!, true); }
}`);
    expect(res).toHaveLength(2);
  });

  it('reports nested computed assignment with attacker keys', async () => {
    const res = await one('NGB036', `export function f() {
  const store: any = {};
  window.addEventListener('message', (e: MessageEvent) => { store[e.data.section][e.data.key] = e.data.value; });
}`);
    expect(res).toHaveLength(1);
  });

  it('safe: guarded keys, trusted data, shallow spread', async () => {
    expect(await one('NGB036', `import { merge } from 'lodash-es';
const defaults = { a: 1 };
export function f(local: object) {
  const store: any = {};
  merge({}, defaults, local);
  window.addEventListener('message', (e: MessageEvent) => {
    const { section, key } = e.data;
    if (section === '__proto__' || key === '__proto__' || section === 'constructor') return;
    store[section][key] = e.data.value;
    const copy = { ...e.data };
  });
}`)).toEqual([]);
  });

  it('false-positive regression: project functions named merge/set are not lodash', async () => {
    expect(await one('NGB036', `function merge(a: object, b: object) { return { ...a, ...b }; }
export function f() { window.addEventListener('message', (e: MessageEvent) => merge({}, e.data)); }`)).toEqual([]);
  });
});
