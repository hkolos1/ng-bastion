import { describe, expect, it } from 'vitest';
import { resolveConfig } from '@ngbastion/config';
import { defineRule } from '@ngbastion/plugin-api';
import { scan } from '../src/index.js';
import { ROOT, traceSink } from './helpers.js';

const SINK = 'declare function sink(v: unknown): void;\n';
const RX = `import { Subject, BehaviorSubject, of, from, defer, firstValueFrom, map, switchMap, catchError, startWith, filter, take } from 'rxjs';\n`;
const ROUTE = `import { ActivatedRoute } from '@angular/router';\nimport { inject, signal, linkedSignal } from '@angular/core';\nimport { toObservable } from '@angular/core/rxjs-interop';\n`;

const kinds = (r: Awaited<ReturnType<typeof traceSink>>[number]) => r.flows.map((f) => f.source.kind);

describe('values: language constructs', () => {
  it('follows getters, for-of loops, array methods and object spread', async () => {
    const [getter, loop, joined, spread] = await traceSink({
      'a.ts': `${SINK}class C { get html() { return location.hash; } }\nsink(new C().html);
for (const part of location.search.split('&')) { sink(part); }
sink([window.name, 'x'].join(','));
const base = { a: 1 }; sink({ ...base, extra: document.URL });`,
    });
    expect(kinds(getter!)).toEqual(['url']);
    expect(kinds(loop!)).toEqual(['url']);
    expect(loop!.flows[0]!.approximations).toContain('collection element (element-insensitive)');
    expect(kinds(joined!)).toEqual(['window-name']);
    expect(kinds(spread!)).toEqual(['url']);
  });

  it('follows promises: then(), await and Promise.resolve()', async () => {
    const [then, awaited, resolved] = await traceSink({
      'a.ts': `${SINK}fetch('/api').then((r) => r.text()).then((t) => sink(t));
async function load() { const r = await fetch('/x'); const body = await r.json(); sink(body.html); }
sink(Promise.resolve(location.hash));
export { load };`,
    });
    expect(kinds(then!)).toEqual(['http-response']);
    expect(kinds(awaited!)).toEqual(['http-response']);
    expect(kinds(resolved!)).toEqual(['url']);
  });

  it('marks caught exceptions, constructed objects and interface methods as unresolved', async () => {
    const [caught, built, iface] = await traceSink({
      'a.ts': `${SINK}interface Renderer { render(): string }
try { JSON.parse('x'); } catch (e) { sink(e); }
class Widget {} sink(new Widget());
export function f(r: Renderer) { sink(r.render()); }`,
    });
    expect(caught!.unresolved[0]!.reason).toBe('caught exception');
    expect(built!.unresolved[0]!.reason).toMatch(/constructed value/);
    expect(iface!.unresolved[0]!.reason).toMatch(/declared on an interface/);
  });

  it('propagates through unmodeled library calls with reduced confidence', async () => {
    const [r] = await traceSink({ 'a.ts': `${SINK}import { marked } from 'marked';\nsink(marked.parse(location.hash));` });
    expect(r!.flows[0]!.confidence).toBe('medium');
    expect(r!.flows[0]!.approximations[0]).toMatch(/unmodeled call/);
  });

  it('treats Math, Date and numeric operators as non-tainted', async () => {
    const [math, date, arith] = await traceSink({ 'a.ts': `${SINK}sink(Math.max(location.hash.length, 1)); sink(new Date(location.hash)); sink(location.hash.length * 2);` });
    for (const r of [math, date, arith]) expect(r!.flows).toHaveLength(0);
  });

  it('honours configured trusted sanitizers (file#name) and ignores same-named functions elsewhere', async () => {
    const files = {
      'src/sanitize.ts': `export function cleanHtml(v: string) { return v.replace(/</g, ''); }`,
      'src/other.ts': `export function cleanHtml(v: string) { return v; }`,
      'src/use.ts': `${SINK}import { cleanHtml } from './sanitize';\nimport { cleanHtml as fake } from './other';\nsink(cleanHtml(location.hash));\nsink(fake(location.hash));`,
    };
    const results: { flows: number; sanitized: number }[] = [];
    const config = await resolveConfig({ extends: [], rules: { T1: 'error' }, minConfidence: 'low', trustedSanitizers: ['src/sanitize.ts#cleanHtml'] }, { cwd: ROOT });
    await scan({
      cwd: ROOT, config, files, rules: [defineRule({
        meta: { id: 'T1', name: 't', category: 'test', defaultSeverity: 'low', docs: { description: '', rationale: '', patterns: [], limitations: [], falsePositives: [], remediation: '', example: { unsafe: '', safe: '' } } },
        analyze(ctx) {
          for (const c of ctx.index.calls) {
            if (c.expression.getText() === 'sink') {
              const r = ctx.taint.trace(c.arguments[0]!, { context: 'html' });
              results.push({ flows: r.flows.length, sanitized: r.sanitized.length });
            }
          }
          return [];
        },
      })],
    });
    expect(results).toEqual([{ flows: 0, sanitized: 1 }, { flows: 1, sanitized: 0 }]);
  });
});

describe('observables and signals', () => {
  it('follows Subject.next() / BehaviorSubject initial values / asObservable()', async () => {
    const [r] = await traceSink({
      'a.ts': `${SINK}${RX}export class Bus {\n  private s = new BehaviorSubject<string>('init');\n  readonly msg$ = this.s.asObservable();\n  push() { this.s.next(window.name); }\n  listen() { this.msg$.subscribe((m) => sink(m)); }\n}`,
    });
    expect(kinds(r!)).toEqual(['window-name']);
    expect(r!.constants).toContain('init');
  });

  it('models of/from/defer, startWith, catchError and passthrough operators', async () => {
    const [a, b, c] = await traceSink({
      'a.ts': `${SINK}${RX}${ROUTE}export class C {
  r = inject(ActivatedRoute);
  go() {
    this.r.fragment.pipe(filter(Boolean), take(1), startWith('x'), catchError(() => of(window.name))).subscribe((v) => sink(v));
    defer(() => from([location.hash])).subscribe((v) => sink(v));
    firstValueFrom(this.r.queryParams.pipe(map((p) => p['q']))).then((q) => sink(q));
  }
}`,
    });
    expect(kinds(a!).sort()).toEqual(['url', 'window-name']);
    expect(a!.constants).toContain('x');
    expect(kinds(b!)).toEqual(['url']);
    expect(kinds(c!)).toEqual(['url']);
  });

  it('follows switchMap into project methods that return observables', async () => {
    const [r] = await traceSink({
      'a.ts': `${SINK}${RX}${ROUTE}import { HttpClient } from '@angular/common/http';
export class Api { private http = inject(HttpClient); page(id: string) { return this.http.get<string>('/pages/' + id); } }
export class C { r = inject(ActivatedRoute); api = inject(Api);
  go() { this.r.paramMap.pipe(switchMap((p) => this.api.page(p.get('id') ?? ''))).subscribe((html) => sink(html)); } }`,
    });
    expect(kinds(r!)).toEqual(['http-response']);
  });

  it('reads fields of inject()-ed services without framework types', async () => {
    const [r] = await traceSink({
      'a.ts': `${SINK}${ROUTE}export class Store { html = location.hash; }\nexport class C { private store = inject(Store); show() { sink(this.store.html); } }`,
    });
    expect(kinds(r!)).toEqual(['url']);
  });

  it('follows signal.update(), linkedSignal() and toObservable()', async () => {
    const [upd, linked, obs] = await traceSink({
      'a.ts': `${SINK}${RX}${ROUTE}export class C {
  html = signal('');
  copy = linkedSignal(() => this.html() + '!');
  stream$ = toObservable(this.html);
  grow() { this.html.update((v) => v + location.hash); }
  a() { sink(this.html()); sink(this.copy()); this.stream$.subscribe((v) => sink(v)); }
}`,
    });
    expect(kinds(upd!)).toEqual(['url']);
    expect(kinds(linked!)).toEqual(['url']);
    expect(kinds(obs!)).toEqual(['url']);
  });

  it('reports unsupported observable factories honestly', async () => {
    const [r] = await traceSink({ 'a.ts': `${SINK}${RX}import { interval } from 'rxjs';\ninterval(10).pipe(map((n) => String(n))).subscribe((v) => sink(v));` });
    expect(r!.flows).toHaveLength(0);
    expect(r!.unresolved[0]!.reason).toMatch(/unsupported: observable factory interval/);
  });
});

describe('templates and callbacks', () => {
  it('treats (input) handlers that pass $event.target.value as user input', async () => {
    const [r] = await traceSink({
      'a.ts': `${SINK}import { Component } from '@angular/core';
@Component({ selector: 'x', template: '<input (input)="search($any($event.target).value)"><input (input)="q = $any($event.target).value">' })
export class C { q = ''; search(term: string) { sink(term); } show() { sink(this.q); } }`,
    });
    expect(kinds(r!)).toEqual(['user-input']);
    expect(r!.flows[0]!.source.description).toMatch(/template user input → search\(\)/);
  });

  it('resolves callbacks passed by reference (subscribe(this.handle))', async () => {
    const [r] = await traceSink({
      'a.ts': `${SINK}${ROUTE}export class C { r = inject(ActivatedRoute); init() { this.r.fragment.subscribe(this.handle.bind(this)); } handle(f: string | null) { sink(f); } }`,
    });
    expect(kinds(r!)).toEqual(['url']);
  });

  it('labels parameters of framework-invoked handlers', async () => {
    const [r] = await traceSink({
      'a.ts': `${SINK}import { HostListener } from '@angular/core';\nexport class C { @HostListener('click', ['$event.detail']) onClick(d: string) { sink(d); } }`,
    });
    expect(r!.unresolved[0]!.reason).toMatch(/framework-invoked handler/);
  });
});

describe('source catalogue', () => {
  it('recognizes Angular router/forms/common sources and browser sources with their trust levels', async () => {
    const results = await traceSink({
      'a.ts': `${SINK}import { Router, ActivatedRoute } from '@angular/router';
import { Location } from '@angular/common';
import { FormControl } from '@angular/forms';
import { inject } from '@angular/core';
export class C {
  router = inject(Router); loc = inject(Location); ctl = new FormControl(''); route = inject(ActivatedRoute);
  go() {
    sink(this.router.url);
    sink(this.loc.path());
    sink(this.ctl.value);
    sink(this.route.snapshot.fragment);
    sink(this.route.snapshot.params['id']);
    sink(document.cookie);
    sink(document.referrer);
    sink(localStorage['draft']);
    this.ctl.valueChanges.subscribe((v) => sink(v));
  }
}`,
    });
    expect(results.map((r) => r.flows[0]?.source.kind)).toEqual(['url', 'url', 'user-input', 'url', 'url', 'cookie', 'referrer', 'storage', 'user-input']);
    expect(results.map((r) => r.flows[0]?.confidence)).toEqual(['high', 'high', 'medium', 'high', 'high', 'low', 'medium', 'low', 'medium']);
  });
});

describe('scalability regressions', () => {
  it('follows combineLatest/forkJoin tuples and merge() inputs', async () => {
    const [tuple, merged] = await traceSink({
      'a.ts': `${SINK}${ROUTE}import { combineLatest, merge, of } from 'rxjs';
export class C { r = inject(ActivatedRoute);
  go() {
    combineLatest([of('x'), this.r.fragment]).subscribe(([a, b]) => sink(b));
    merge(of('static'), this.r.queryParams).subscribe((v) => sink(v));
  } }`,
    });
    expect(kinds(tuple!)).toEqual(['url']);
    expect(tuple!.flows[0]!.approximations.some((a) => a.includes('combineLatest'))).toBe(true);
    expect(kinds(merged!)).toEqual(['url']);
  });

  it('follows diamond-shaped field dependencies without hitting limits', async () => {
    const fields = Array.from({ length: 16 }, (_, i) => i === 0
      ? '  f0 = location.hash;'
      : `  f${i} = this.f${i - 1} + this.f${Math.max(0, i - 2)};`).join('\n');
    const [r] = await traceSink({ 'a.ts': `${SINK}export class Diamond {\n${fields}\n  go() { sink(this.f15); }\n}` });
    expect(r!.truncated).toBe(false);
    expect(kinds(r!)).toEqual(['url']);
  });
});
