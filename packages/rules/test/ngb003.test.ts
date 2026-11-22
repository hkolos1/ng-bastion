import { describe, expect, it } from 'vitest';
import { NG, findings, one } from './helpers.js';

describe('NGB003 DOM injection sink', () => {
  it('reports innerHTML on ElementRef.nativeElement from a query parameter', async () => {
    const [f] = await one('NGB003', `${NG}
export class Preview {
  private el = inject(ElementRef<HTMLElement>);
  private route = inject(ActivatedRoute);
  show() { this.el.nativeElement.innerHTML = this.route.snapshot.queryParams['msg']; }
}`);
    expect(f!.message).toContain('innerHTML');
    expect(f!.trace!.map((s) => s.kind)).toEqual(['source', 'sink']);
  });

  it('reports insertAdjacentHTML, document.write and Renderer2.setProperty', async () => {
    const res = await one('NGB003', `${NG}
export class W {
  constructor(private r: Renderer2, private host: ElementRef) {}
  go(div: HTMLDivElement) {
    div.insertAdjacentHTML('beforeend', location.hash);
    document.write(window.name);
    this.r.setProperty(this.host.nativeElement, 'innerHTML', document.referrer);
  }
}`);
    expect(res.map((f) => f.message.match(/written to (.*?) without/)?.[1]).sort()).toEqual(['Renderer2.setProperty(…, \'innerHTML\')', 'document.write()', 'insertAdjacentHTML()']);
  });

  it('does not report the sanitized [innerHTML] template binding', async () => {
    expect(await one('NGB003', `${NG}
@Component({ selector: 'x', template: '<div [innerHTML]="html"></div>' })
export class T { private route = inject(ActivatedRoute); html = this.route.snapshot.queryParams['h']; }`)).toEqual([]);
  });

  it('does not report textContent (safe equivalent) or constant markup', async () => {
    expect(await one('NGB003', `export function f(el: HTMLElement) { el.textContent = location.hash; el.innerHTML = '<hr>'; }`)).toEqual([]);
  });

  it('does not report DOMPurify-sanitized HTML', async () => {
    expect(await one('NGB003', `import DOMPurify from 'dompurify';
export function f(el: HTMLElement) { el.innerHTML = DOMPurify.sanitize(location.hash); }`)).toEqual([]);
  });

  it('false-positive regression: innerHTML on a non-DOM object is ignored', async () => {
    expect(await one('NGB003', `export class Model { innerHTML = ''; }
export function f(m: Model) { m.innerHTML = location.hash; }`)).toEqual([]);
  });

  it('traces a postMessage payload through a redirect-like helper across files', async () => {
    const res = await findings('NGB003', {
      'src/app/render.ts': `export function render(target: HTMLElement, html: string) { target.innerHTML = html; }`,
      'src/app/listener.ts': `import { render } from './render';
window.addEventListener('message', (e: MessageEvent) => render(document.body, e.data));`,
    });
    expect(res).toHaveLength(1);
    expect(res[0]!.trace![0]!.description).toBe('MessageEvent.data');
    expect(res[0]!.confidence).toBe('high');
  });
});
