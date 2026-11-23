import { describe, expect, it } from 'vitest';
import { traceSink } from './helpers.js';

const SINK = 'declare function sink(v: unknown): void;\n';
const ROUTE = `import { ActivatedRoute } from '@angular/router';\nimport { inject } from '@angular/core';\n`;

describe('taint engine: basic propagation', () => {
  it('follows a direct location source through a variable', async () => {
    const [r] = await traceSink({ 'a.ts': `${SINK}const q = location.search; sink(q);` });
    expect(r!.flows).toHaveLength(1);
    expect(r!.flows[0]!.source.kind).toBe('url');
    expect(r!.flows[0]!.confidence).toBe('high');
    expect(r!.flows[0]!.steps.map((s) => s.kind)).toEqual(['source', 'assignment']);
  });

  it('treats constants as constant and reports no flows', async () => {
    const [r] = await traceSink({ 'a.ts': `${SINK}const BASE = '<b>hi</b>'; const x = BASE + '!'; sink(x); sink(\`a\${1}\`);` });
    expect(r!.flows).toHaveLength(0);
    expect(r!.constant).toBe(true);
    expect(r!.constants).toContain('<b>hi</b>');
  });

  it('follows string transformations and template literals', async () => {
    const [r] = await traceSink({ 'a.ts': `${SINK}const h = location.hash.slice(1).trim(); sink(\`<p>\${h.toLowerCase()}</p>\`);` });
    expect(r!.flows[0]!.source.description).toBe('location.hash');
    expect(r!.flows[0]!.steps.some((s) => s.kind === 'transform')).toBe(true);
  });

  it('follows reassignment of a let variable', async () => {
    const [r] = await traceSink({ 'a.ts': `${SINK}let v = 'safe'; v = window.name; sink(v);` });
    expect(r!.flows[0]!.source.kind).toBe('window-name');
    expect(r!.constants).toContain('safe');
  });

  it('marks unresolvable origins as unresolved, not constant', async () => {
    const [r] = await traceSink({ 'a.ts': `${SINK}export function show(v: string) { sink(v); }` });
    expect(r!.flows).toHaveLength(0);
    expect(r!.constant).toBe(false);
    expect(r!.unresolved[0]!.reason).toMatch(/no visible callers/);
  });
});

describe('taint engine: interprocedural', () => {
  it('maps parameters to arguments at call sites', async () => {
    const [r] = await traceSink({ 'a.ts': `${SINK}function render(html: string) { sink(html); }\nrender(document.URL);\nrender('static');` });
    expect(r!.flows).toHaveLength(1);
    expect(r!.flows[0]!.steps.map((s) => s.kind)).toEqual(['source', 'argument']);
    expect(r!.constants).toContain('static');
  });

  it('orders trace steps from source to sink', async () => {
    const [r] = await traceSink({ 'a.ts': `${SINK}function wrap(x: string) {\n  const y = '<b>' + x;\n  return y;\n}\nconst h = location.hash;\nsink(wrap(h));` });
    const lines = r!.flows[0]!.steps.map((s) => s.location.line);
    expect(r!.flows[0]!.steps.map((s) => s.kind)).toEqual(['source', 'assignment', 'argument', 'transform', 'assignment', 'return']);
    expect(lines[0]).toBe(6);
    expect(lines.at(-1)).toBe(7);
  });

  it('follows return values with context-sensitive parameter binding', async () => {
    const [tainted, clean] = await traceSink({
      'a.ts': `${SINK}function wrap(x: string) { return '<div>' + x + '</div>'; }\nsink(wrap(location.hash));\nsink(wrap('fixed'));`,
    });
    expect(tainted!.flows).toHaveLength(1);
    expect(clean!.flows).toHaveLength(0);
    expect(clean!.constant).toBe(true);
  });

  it('crosses files through imported helpers', async () => {
    const [r] = await traceSink({
      'util.ts': `export const fromHash = () => window.location.hash.substring(1);\nexport function build(v: string) { return \`<i>\${v}</i>\`; }`,
      'main.ts': `${SINK}import { fromHash, build } from './util';\nsink(build(fromHash()));`,
    });
    expect(r!.flows).toHaveLength(1);
    const files = new Set(r!.flows[0]!.steps.map((s) => s.location.file.split('/').pop()));
    expect(files).toEqual(new Set(['util.ts', 'main.ts']));
  });

  it('follows Angular services through injected fields and query params', async () => {
    const [r] = await traceSink({
      'content.service.ts': `${ROUTE}export class ContentService {\n  private route = inject(ActivatedRoute);\n  preview(): string { const raw = this.route.snapshot.queryParamMap.get('html') ?? ''; return raw; }\n}`,
      'preview.component.ts': `${SINK}import { ContentService } from './content.service';\nexport class Preview {\n  constructor(private content: ContentService) {}\n  show() { sink(this.content.preview()); }\n}`,
    });
    expect(r!.flows).toHaveLength(1);
    expect(r!.flows[0]!.source.description).toContain(`URL query parameter 'html'`);
    expect(r!.flows[0]!.confidence).toBe('high');
  });

  it('tracks class fields written in one method and read in another', async () => {
    const [r] = await traceSink({
      'a.ts': `${SINK}${ROUTE}export class C {\n  html = '';\n  constructor(private route: ActivatedRoute) {}\n  init() { this.html = this.route.snapshot.queryParams['q']; }\n  render() { sink(this.html); }\n}`,
    });
    expect(r!.flows[0]!.source.description).toContain(`URL query parameter 'q'`);
    expect(r!.constants).toContain('');
  });

  it('terminates on cyclic call graphs', async () => {
    const [r] = await traceSink({
      'a.ts': `${SINK}function a(x: string): string { return x ? b(x) : location.hash; }\nfunction b(y: string): string { return a(y); }\nsink(a('z'));`,
    });
    expect(r!.flows.some((f) => f.source.description === 'location.hash')).toBe(true);
  });

  it('follows object literal properties precisely when the type is known', async () => {
    const [r] = await traceSink({ 'a.ts': `${SINK}const cfg = { safe: 'x', bad: location.hash };\nsink(cfg.safe);\nsink(cfg.bad);` });
    expect(r!.flows).toHaveLength(0);
  });
});

describe('taint engine: messages, storage, sanitizers', () => {
  it('recognizes MessageEvent.data by type and destructuring', async () => {
    const [a, b] = await traceSink({
      'a.ts': `${SINK}window.addEventListener('message', (e: MessageEvent) => sink(e.data.html));\nwindow.addEventListener('message', ({ data }: MessageEvent) => sink(data));`,
    });
    expect(a!.flows[0]!.source.kind).toBe('message');
    expect(b!.flows[0]!.source.kind).toBe('message');
  });

  it('honours context-specific sanitizers and rejects trust bypass as a sanitizer', async () => {
    const results = await traceSink({
      'a.ts': `${SINK}import { DomSanitizer, SecurityContext } from '@angular/platform-browser';\nimport DOMPurify from 'dompurify';\nexport class C {\n  constructor(private s: DomSanitizer) {}\n  run() {\n    sink(this.s.sanitize(SecurityContext.HTML, location.hash));\n    sink(DOMPurify.sanitize(location.hash));\n    sink(this.s.bypassSecurityTrustHtml(location.hash));\n    sink(encodeURIComponent(location.hash));\n  }\n}`,
    });
    expect(results[0]!.flows).toHaveLength(0);
    expect(results[0]!.sanitized[0]!.reason).toContain('SecurityContext.HTML');
    expect(results[1]!.sanitized[0]!.reason).toBe('DOMPurify.sanitize()');
    expect(results[2]!.flows).toHaveLength(1);
    expect(results[2]!.flows[0]!.steps.some((s) => s.kind === 'trust-bypass')).toBe(true);
    // URL encoding is not an HTML sanitizer: the flow is kept, with one approximation (medium confidence).
    expect(results[3]!.flows).toHaveLength(1);
    expect(results[3]!.flows[0]!.confidence).toBe('medium');
    expect(results[3]!.flows[0]!.approximations.join()).toMatch(/not HTML-escaped/);
  });

  it('models server request headers (Host / X-Forwarded-*) and Express query values as sources', async () => {
    const results = await traceSink({
      'a.ts': `${SINK}import type { Request } from 'express';\nexport function h(req: Request, r: globalThis.Request, other: { headers: { host: string } }) {\n  sink(req.headers.host);\n  sink(req.get('x-forwarded-host'));\n  sink(req.hostname);\n  sink(r.headers.get('host'));\n  sink(req.query['next']);\n  sink(other.headers.host);\n  sink(req.headers['user-agent']);\n}`,
    }, 'generic');
    expect(results.slice(0, 4).map((r) => r.flows[0]?.source.kind)).toEqual(['request-header', 'request-header', 'request-header', 'request-header']);
    expect(results[4]!.flows[0]!.source.kind).toBe('url');
    expect(results[5]!.flows).toHaveLength(0);
    expect(results[6]!.flows).toHaveLength(0);
  });

  it('models Express body / path / cookies and untyped (req, res) handler parameters', async () => {
    const results = await traceSink({
      'a.ts': `${SINK}import type { Request } from 'express';
export function h(req: Request) { sink(req.body.name); sink(req.path); sink(req.cookies['sid']); }
declare const app: { post(p: string, f: (req: any, res: any) => void): void };
app.post('/x', (req, res) => { sink(req.body); sink(res); });
export function notAHandler(req: { body: string }, other: unknown) { sink(req.body); sink(other); }`,
    }, 'generic');
    expect(results.map((r) => r.flows[0]?.source.kind)).toEqual(['user-input', 'url', 'cookie', 'user-input', undefined, undefined, undefined]);
  });

  it('does not crash on receiver types named like Object.prototype members', async () => {
    // `Object.prototype.toString.call(v)`: the receiver's type origin is named `toString`.
    const [r] = await traceSink({ 'a.ts': `${SINK}export function f() { sink(Object.prototype.toString.call(location.hash)); }` }, 'generic');
    expect(r).toBeDefined();
  });

  it('does not treat the own origin (location.origin / host / protocol) as attacker-controlled', async () => {
    const [origin, host, href] = await traceSink({ 'a.ts': `${SINK}export function f() {\n  sink(window.location.origin);\n  sink(location.host + '/x');\n  sink(location.href);\n}` }, 'generic');
    expect(origin!.flows).toHaveLength(0);
    expect(host!.flows).toHaveLength(0);
    expect(href!.flows).toHaveLength(1);
  });

  it('treats encodeURIComponent() as a sanitizer for URL contexts only, and encodeURI() for none', async () => {
    const SRC = `${SINK}export function run() {\n  sink(encodeURIComponent(location.hash));\n  sink(encodeURI(location.hash));\n}`;
    const [url, urlRaw] = await traceSink({ 'a.ts': SRC }, 'url');
    expect(url!.flows).toHaveLength(0);
    expect(url!.sanitized[0]!.reason).toBe('encodeURIComponent()');
    expect(urlRaw!.flows).toHaveLength(1);
    const [html, htmlRaw] = await traceSink({ 'a.ts': SRC }, 'html');
    expect(html!.flows).toHaveLength(1);
    expect(htmlRaw!.flows).toHaveLength(1);
  });

  it('does not treat an HTML sanitizer as safe for URL sinks', async () => {
    const [r] = await traceSink({
      'a.ts': `${SINK}import DOMPurify from 'dompurify';\nsink(DOMPurify.sanitize(location.hash));`,
    }, 'url');
    expect(r!.flows).toHaveLength(1);
  });

  it('numeric conversion neutralizes taint', async () => {
    const [r] = await traceSink({ 'a.ts': `${SINK}sink(Number(location.hash));` });
    expect(r!.constant).toBe(true);
  });

  it('models storage reads as low-trust sources', async () => {
    const [r] = await traceSink({ 'a.ts': `${SINK}sink(localStorage.getItem('draft'));` });
    expect(r!.flows[0]!.source.kind).toBe('storage');
    expect(r!.flows[0]!.confidence).toBe('low');
  });
});

describe('taint engine: RxJS and signals', () => {
  const rx = `import { map, switchMap, tap, filter } from 'rxjs';\nimport { of } from 'rxjs';\n`;

  it('follows queryParamMap through map() and subscribe()', async () => {
    const [r] = await traceSink({
      'a.ts': `${SINK}${ROUTE}${rx}export class C {\n  private route = inject(ActivatedRoute);\n  ngOnInit() {\n    this.route.queryParamMap.pipe(tap(() => {}), map(p => p.get('next') ?? '/')).subscribe(url => sink(url));\n  }\n}`,
    });
    expect(r!.flows).toHaveLength(1);
    expect(r!.flows[0]!.source.description).toBe('ActivatedRoute.queryParamMap');
    expect(r!.flows[0]!.steps.map((s) => s.kind)).toContain('reactive');
  });

  it('follows switchMap into HttpClient responses (medium trust)', async () => {
    const [r] = await traceSink({
      'a.ts': `${SINK}${ROUTE}${rx}import { HttpClient } from '@angular/common/http';\nexport class C {\n  private route = inject(ActivatedRoute);\n  private http = inject(HttpClient);\n  load() {\n    this.route.params.pipe(switchMap(p => this.http.get<{ body: string }>('/api/page/' + p['id'])), map(r => r.body)).subscribe(b => sink(b));\n  }\n}`,
    });
    expect(r!.flows[0]!.source.kind).toBe('http-response');
  });

  it('does not invent flows for of() constants', async () => {
    const [r] = await traceSink({ 'a.ts': `${SINK}${rx}of('<b>ok</b>').pipe(map(v => v.toUpperCase())).subscribe(v => sink(v));` });
    expect(r!.flows).toHaveLength(0);
    expect(r!.constant).toBe(true);
  });

  it('reports unsupported operators instead of guessing', async () => {
    const [r] = await traceSink({ 'a.ts': `${SINK}import { scan } from 'rxjs';\n${ROUTE}export class C { r = inject(ActivatedRoute); go() { this.r.fragment.pipe(scan((a: string, b) => a + b, '')).subscribe(v => sink(v)); } }` });
    expect(r!.flows).toHaveLength(0);
    expect(r!.unresolved[0]!.reason).toMatch(/unsupported: RxJS operator scan/);
  });

  it('follows signal(), set(), computed() and toSignal()', async () => {
    const [a, b, c] = await traceSink({
      'a.ts': `${SINK}${ROUTE}import { signal, computed } from '@angular/core';\nimport { toSignal } from '@angular/core/rxjs-interop';\nexport class C {\n  private route = inject(ActivatedRoute);\n  html = signal('');\n  wrapped = computed(() => '<p>' + this.html() + '</p>');\n  frag = toSignal(this.route.fragment);\n  init() { this.html.set(window.name); }\n  render() { sink(this.html()); sink(this.wrapped()); sink(this.frag()); }\n}`,
    });
    expect(a!.flows[0]!.source.kind).toBe('window-name');
    expect(b!.flows[0]!.source.kind).toBe('window-name');
    expect(c!.flows[0]!.source.description).toBe('ActivatedRoute.fragment');
  });

  it('reports component inputs as unresolved (parent-supplied)', async () => {
    const [r] = await traceSink({ 'a.ts': `${SINK}import { input } from '@angular/core';\nexport class C { html = input<string>(); go() { sink(this.html()); } }` });
    expect(r!.unresolved[0]!.reason).toMatch(/parent binding/);
  });

  it('ignores user functions that merely share a signal factory name', async () => {
    const [r] = await traceSink({ 'a.ts': `${SINK}function signal<T>(v: T) { return () => v; }\nconst s = signal(location.hash);\nsink(s());` });
    // A local `signal` is a plain function: the value flows through its closure return, not the signal model.
    expect(r!.flows.every((f) => !f.steps.some((st) => st.kind === 'signal'))).toBe(true);
  });
});

describe('taint engine: templates and limits', () => {
  it('treats [(ngModel)] bindings as user input sources', async () => {
    const [r] = await traceSink({
      'a.ts': `${SINK}import { Component } from '@angular/core';\n@Component({ selector: 'x', template: '<textarea [(ngModel)]="draft"></textarea>' })\nexport class C { draft = ''; preview() { sink(this.draft); } }`,
    });
    expect(r!.flows[0]!.source.kind).toBe('user-input');
    expect(r!.flows[0]!.steps[0]!.location.file).toMatch(/a\.ts$/);
  });

  it('marks traces that exceed maxDepth as truncated', async () => {
    const chain = Array.from({ length: 60 }, (_, i) => `const v${i + 1} = v${i};`).join('\n');
    const [r] = await traceSink({ 'a.ts': `${SINK}const v0 = location.hash;\n${chain}\nsink(v60);` });
    expect(r!.truncated).toBe(true);
    expect(r!.flows).toHaveLength(0);
  });
});
