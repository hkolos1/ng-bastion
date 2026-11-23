import { describe, expect, it } from 'vitest';
import { NG, one } from './helpers.js';

describe('NGB075 untrusted worker script', () => {
  it('reports workers and service workers loaded from untrusted URLs', async () => {
    const res = await one('NGB075', `${NG}export class C { private route = inject(ActivatedRoute);
  run() {
    const engine = this.route.snapshot.queryParams['engine'];
    new Worker(engine);
    new SharedWorker(\`\${location.hash.slice(1)}\`);
    navigator.serviceWorker.register(this.route.snapshot.queryParams['sw']);
  } }`);
    expect(res).toHaveLength(3);
    expect(res.every((r) => r.evidenceKind === 'dataflow')).toBe(true);
  });

  it('reports Blob workers built from untrusted code (postMessage data)', async () => {
    const res = await one('NGB075', `window.addEventListener('message', (e: MessageEvent) => {
  const blob = new Blob([e.data.code], { type: 'text/javascript' });
  new Worker(URL.createObjectURL(blob));
});`);
    expect(res).toHaveLength(1);
    expect(res[0]!.message).toMatch(/code/);
  });

  it('safe: Angular CLI worker bundles and constant service-worker paths', async () => {
    expect(await one('NGB075', `export function f() {
  new Worker(new URL('./app.worker', import.meta.url), { type: 'module' });
  navigator.serviceWorker.register('/ngsw-worker.js');
  new Worker(URL.createObjectURL(new Blob(['self.onmessage = () => {}'])));
}`)).toEqual([]);
  });

  it('false-positive regression: project classes named Worker, user-typed input', async () => {
    expect(await one('NGB075', `class Worker { constructor(public name: string) {} }
export function f(input: HTMLInputElement) { return new Worker(location.search); }
export function g(input: HTMLInputElement) { return new SharedWorker(input.value); }`)).toEqual([]);
  });
});
