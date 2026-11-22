#!/usr/bin/env node
// Measures scan time on generated Angular-style workspaces of increasing size.
// Usage: node scripts/benchmark.mjs [components...]   (requires `pnpm build`)
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadConfig } from '../packages/config/dist/index.js';
import { scan } from '../packages/core/dist/index.js';
import { builtinRules } from '../packages/rules/dist/index.js';

const sizes = process.argv.slice(2).map(Number).filter(Boolean);
const COUNTS = sizes.length ? sizes : [50, 200, 800];

function component(i) {
  // Every 10th component contains a real source→sink flow through a service.
  const vulnerable = i % 10 === 0;
  return {
    [`src/app/f${i}/f${i}.service.ts`]: `import { Injectable, inject } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { map } from 'rxjs';
@Injectable({ providedIn: 'root' })
export class F${i}Service {
  private route = inject(ActivatedRoute);
  private http = inject(HttpClient);
  title(): string { return ${vulnerable ? `this.route.snapshot.queryParamMap.get('t${i}') ?? ''` : `'Feature ${i}'`}; }
  items() { return this.http.get<{ name: string }[]>('/api/f${i}').pipe(map((r) => r.map((x) => x.name))); }
}
`,
    [`src/app/f${i}/f${i}.component.ts`]: `import { Component, ElementRef, computed, inject, signal } from '@angular/core';
import { F${i}Service } from './f${i}.service';
@Component({ selector: 'app-f${i}', template: \`@if (open()) { <h2 [innerHTML]="heading()"></h2> } @for (n of names(); track n) { <li>{{ n }}</li> }\` })
export class F${i}Component {
  private svc = inject(F${i}Service);
  private el = inject<ElementRef<HTMLElement>>(ElementRef);
  readonly open = signal(true);
  readonly names = signal<string[]>([]);
  readonly heading = computed(() => '<b>' + this.svc.title() + '</b>');
  ngOnInit() { this.svc.items().subscribe((n) => this.names.set(n)); }
  render() { this.el.nativeElement.innerHTML = this.heading(); }
}
`,
  };
}

const results = [];
for (const n of COUNTS) {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'ngb-bench-'));
  const files = Object.assign({}, ...Array.from({ length: n }, (_, i) => component(i)));
  files['tsconfig.json'] = JSON.stringify({ compilerOptions: { experimentalDecorators: true, strict: true, target: 'ES2022', module: 'ESNext', moduleResolution: 'Bundler' }, include: ['src/**/*.ts'] });
  for (const [f, c] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
    writeFileSync(path.join(dir, f), c);
  }
  const { config } = await loadConfig({ cwd: dir, overrides: { minConfidence: 'low' } });
  const t0 = performance.now();
  const r = await scan({ cwd: dir, config, rules: builtinRules });
  const ms = performance.now() - t0;
  const expected = Math.ceil(n / 10);
  const ngb003 = r.findings.filter((f) => f.ruleId === 'NGB003').length;
  results.push({ components: n, files: r.stats.filesAnalyzed, ms: Math.round(ms), traces: r.stats.traces, truncated: r.stats.truncatedTraces, ngb003, expected, rssMb: Math.round(process.memoryUsage().rss / 1e6) });
  rmSync(dir, { recursive: true, force: true });
}
console.table(results);
console.log(`node ${process.version} · ${os.cpus()[0]?.model ?? 'unknown cpu'} · ${os.platform()}`);
