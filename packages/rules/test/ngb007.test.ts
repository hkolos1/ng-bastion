import { describe, expect, it } from 'vitest';
import { NG, findings, one } from './helpers.js';

describe('NGB007 missing origin validation', () => {
  it('reports an unchecked handler doing sensitive work (high)', async () => {
    const [f, ...rest] = await one('NGB007', `export function init(el: HTMLElement) {
  window.addEventListener('message', (e) => { el.innerHTML = e.data; });
}`);
    expect(rest).toHaveLength(0);
    expect(f!.confidence).toBe('high');
    expect(f!.severity).toBe('high');
    expect(f!.message).toMatch(/without validating event.origin/);
  });

  it('accepts strict equality with early return and allowlist membership', async () => {
    expect(await one('NGB007', `const ALLOWED = ['https://a.example.com'];
export function a(el: HTMLElement) {
  window.addEventListener('message', (e) => { if (e.origin !== 'https://a.example.com') return; el.innerHTML = e.data; });
  window.addEventListener('message', (e) => { if (ALLOWED.includes(e.origin)) { el.innerHTML = e.data; } });
  window.addEventListener('message', ({ origin, data }: MessageEvent) => { if (!new Set(ALLOWED).has(origin)) return; el.textContent = data; });
}`)).toEqual([]);
  });

  it('reports weak substring checks with medium confidence', async () => {
    const [f] = await one('NGB007', `export function a(el: HTMLElement) {
  window.addEventListener('message', (e) => { if (e.origin.startsWith('https://trusted.com')) el.innerHTML = e.data; });
}`);
    expect(f!.confidence).toBe('medium');
    expect(f!.message).toMatch(/weak origin check/);
  });

  it('reports inverted / non-dominating origin checks', async () => {
    const [f] = await one('NGB007', `export function a(el: HTMLElement) {
  window.addEventListener('message', (e) => { console.log(e.origin); el.innerHTML = e.data; });
}`);
    expect(f!.message).toMatch(/does not guard/);
    const [g] = await one('NGB007', `export function b(el: HTMLElement) {
  window.addEventListener('message', (e) => { if (e.origin === 'https://x.com') return; el.innerHTML = e.data; });
}`);
    expect(g).toBeDefined();
  });

  it('supports @HostListener, host bindings and delegation to a helper', async () => {
    const res = await findings('NGB007', {
      'src/handler.service.ts': `export class HandlerService { apply(data: unknown) { localStorage.setItem('cfg', JSON.stringify(data)); } }`,
      'src/widget.ts': `${NG}import { HostListener } from '@angular/core';
import { HandlerService } from './handler.service';
export class Widget {
  constructor(private svc: HandlerService) {}
  @HostListener('window:message', ['$event'])
  onMessage(e: MessageEvent) { this.svc.apply(e.data); }
}
@Component({ selector: 'h', template: '', host: { '(window:message)': 'handle($event)' } })
export class Hosted {
  handle(event: MessageEvent) { if (isTrusted(event.origin)) this.process(event); }
  process(ev: MessageEvent) { document.title = ev.data; }
}
function isTrusted(o: string) { return o === 'https://ok.example.com'; }`,
    });
    expect(res).toHaveLength(1);
    expect(res[0]!.location.file).toBe('src/widget.ts');
    expect(res[0]!.evidence.join(' ')).toMatch(/HostListener/);
  });

  it('honours origin filters inside fromEvent pipes; ignores handlers that never read data', async () => {
    expect(await one('NGB007', `import { fromEvent, filter } from 'rxjs';
export function a(el: HTMLElement) {
  fromEvent<MessageEvent>(window, 'message').pipe(filter((e) => e.origin === 'https://a.com')).subscribe((e) => { el.innerHTML = e.data; });
  window.addEventListener('message', (e) => console.log('ping from', e.origin));
}`)).toEqual([]);
  });

  it('false-positive regression: MessagePort / worker listeners are not window handlers', async () => {
    expect(await one('NGB007', `export function a(port: MessagePort, el: HTMLElement) { port.addEventListener('message', (e) => { el.innerHTML = e.data; }); }`)).toEqual([]);
  });
});
