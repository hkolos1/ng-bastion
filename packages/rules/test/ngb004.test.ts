import { describe, expect, it } from 'vitest';
import { one } from './helpers.js';

describe('NGB004 dynamic code execution', () => {
  it('reports eval of a URL fragment as critical', async () => {
    const [f] = await one('NGB004', `export function run() { const code = location.hash.slice(1); return eval(code); }`);
    expect(f!.severity).toBe('critical');
    expect(f!.confidence).toBe('high');
  });

  it('reports new Function, Function() and string setTimeout', async () => {
    const res = await one('NGB004', `export function a(e: MessageEvent) {
  new Function('x', e.data);
  Function(window.name)();
  setTimeout('go(' + location.search + ')', 10);
}`);
    expect(res).toHaveLength(3);
  });

  it('does not report setTimeout with a callback or eval of constants', async () => {
    expect(await one('NGB004', `export function a() { setTimeout(() => console.log(location.hash), 5); eval('1 + 1'); }`)).toEqual([]);
  });

  it('false-positive regression: a project function named eval is not the global eval', async () => {
    expect(await one('NGB004', `function evaluate(x: string) { return x.length; }
const ops = { eval: evaluate };
export const r = ops.eval(location.hash);
function local() { const eval2 = (s: string) => s; return eval2(location.hash); }
export { local };`)).toEqual([]);
  });

  it('reports dynamic code of unknown origin with low confidence', async () => {
    const [f] = await one('NGB004', `export function calc(expr: string) { return eval(expr); }`);
    expect(f!.confidence).toBe('low');
    expect(f!.evidenceKind).toBe('heuristic');
  });
});
