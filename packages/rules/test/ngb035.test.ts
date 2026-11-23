import { describe, expect, it } from 'vitest';
import { NG, one } from './helpers.js';

describe('NGB035 untrusted dynamic method dispatch', () => {
  it('reports message-controlled method names on this (high)', async () => {
    const res = await one('NGB035', `export class Bridge {
  constructor() { window.addEventListener('message', (e: MessageEvent) => this.dispatch(e.data)); }
  dispatch(msg: { method: string; args: unknown[] }) { (this as any)[msg.method](...msg.args); }
}`);
    expect(res).toHaveLength(1);
    expect(res[0]!.severity).toBe('high');
  });

  it('reports URL-controlled handler lookups (medium) including .call()', async () => {
    const res = await one('NGB035', `${NG}const handlers: Record<string, () => void> = { a: () => 0 };
export class C {
  constructor(private route: ActivatedRoute) {}
  run() { const action = this.route.snapshot.queryParamMap.get('action')!; handlers[action].call(null); }
}`);
    expect(res).toHaveLength(1);
    expect(res[0]!.severity).toBe('medium');
  });

  it('safe: own-property and allowlist checks, constant keys', async () => {
    expect(await one('NGB035', `const handlers: Record<string, () => void> = { a: () => 0 };
export function f() {
  window.addEventListener('message', (e: MessageEvent) => {
    const cmd = e.data.cmd as string;
    if (Object.hasOwn(handlers, cmd)) handlers[cmd]();
    if (['a', 'b'].includes(cmd)) handlers[cmd]();
    handlers['a']();
  });
}`)).toEqual([]);
  });

  it('false-positive regression: in / typeof checks do not count, local keys are not sources', async () => {
    const res = await one('NGB035', `const handlers: Record<string, () => void> = { a: () => 0 };
export function f(keys: string[]) {
  for (const k of keys) handlers[k]();
  window.addEventListener('message', (e: MessageEvent) => { if (e.data.cmd in handlers) handlers[e.data.cmd](); });
}`);
    expect(res).toHaveLength(1);
  });
});
