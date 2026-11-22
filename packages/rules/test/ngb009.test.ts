import { describe, expect, it } from 'vitest';
import { NG, findings, one } from './helpers.js';

describe('NGB009 unvalidated message payload', () => {
  it('reports message data reaching navigation without validation (dataflow trace)', async () => {
    const [f, ...rest] = await one('NGB009', `export function a() {
  window.addEventListener('message', (e: MessageEvent<{ url: string }>) => { const msg = e.data as { url: string }; location.href = msg.url; });
}`);
    expect(rest).toHaveLength(0);
    expect(f!.confidence).toBe('high');
    expect(f!.evidenceKind).toBe('dataflow');
    expect(f!.trace!.at(0)!.kind).toBe('source');
    expect(f!.trace!.at(-1)!.kind).toBe('sink');
  });

  it('accepts typeof checks and schema parsing (safe equivalents)', async () => {
    expect(await one('NGB009', `declare const Msg: { safeParse(v: unknown): { success: boolean; data: { url: string } } };
export function a(el: HTMLElement) {
  window.addEventListener('message', (e) => { if (typeof e.data !== 'string') return; el.innerHTML = e.data; });
  window.addEventListener('message', (e) => { const r = Msg.safeParse(e.data); if (r.success) location.href = r.data.url; });
}`)).toEqual([]);
  });

  it('discriminant-only checks are medium; type predicates low; strict origin lowers to low', async () => {
    const res = await one('NGB009', `interface Cmd { type: 'nav'; url: string }
function isCmd(x: unknown): x is Cmd { return true; }
export function a() {
  window.addEventListener('message', (e) => { if (e.data.type === 'nav') location.assign(e.data.url); });
  window.addEventListener('message', (e) => { if (isCmd(e.data)) window.open(e.data.url); });
  window.addEventListener('message', (e) => { if (e.origin !== 'https://a.com') return; localStorage.setItem('cfg', e.data); });
}`);
    expect(res.map((f) => f.confidence).sort()).toEqual(['low', 'low', 'medium']);
  });

  it('follows message data across files into a service', async () => {
    const res = await findings('NGB009', {
      'src/nav.service.ts': `${NG}export class NavService { private router = inject(Router); go(path: string) { this.router.navigateByUrl(path); } }`,
      'src/listener.ts': `import { NavService } from './nav.service';
export class Listener {
  constructor(private nav: NavService) {}
  init() { window.addEventListener('message', ({ data }: MessageEvent) => this.nav.go(data.path)); }
}`,
    });
    expect(res).toHaveLength(1);
    expect(res[0]!.location.file).toBe('src/nav.service.ts');
  });

  it('false-positive regression: message data used only for logging / non-sensitive state is ignored', async () => {
    expect(await one('NGB009', `export class A { last: unknown; init() { window.addEventListener('message', (e) => { this.last = e.data; console.log(e.data); }); } }`)).toEqual([]);
  });
});
