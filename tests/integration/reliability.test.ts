import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { resolveConfig } from '@ngbastion/config';
import { scan } from '@ngbastion/core';
import { builtinRules } from '@ngbastion/rules';

const tmp = mkdtempSync(path.join(os.tmpdir(), 'ngb-rel-'));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

function disk(files: Record<string, string>): string {
  const dir = mkdtempSync(path.join(tmp, 'ws-'));
  for (const [name, content] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    writeFileSync(path.join(dir, name), content);
  }
  return dir;
}

async function run(cwd: string, files?: Record<string, string>, limits?: Record<string, number>) {
  const config = await resolveConfig({ minConfidence: 'low', ...(limits ? { limits } : {}) }, { cwd });
  return scan({ cwd, config, rules: builtinRules, ...(files ? { files } : {}) });
}

const ANGULAR_JSON = JSON.stringify({ version: 1, projects: { app: { root: '', sourceRoot: 'src', architect: { build: { options: { tsConfig: 'tsconfig.json', index: 'src/index.html' } } } } } });

describe('reliability', () => {
  it('reports syntax errors as diagnostics and still analyzes the rest', async () => {
    const r = await run('/virtual/r1', {
      'src/broken.ts': 'export function (( { const x = ;',
      'src/ok.ts': 'export function f(el: HTMLElement) { el.innerHTML = location.hash; }',
    });
    expect(r.diagnostics.find((d) => d.code === 'parse-error')!.file).toBe('src/broken.ts');
    expect(r.findings.some((f) => f.ruleId === 'NGB003')).toBe(true);
  });

  it('warns about missing external templates and malformed templates', async () => {
    const r = await run('/virtual/r2', {
      'src/a.ts': `import { Component } from '@angular/core';
@Component({ selector: 'a', templateUrl: './missing.html' }) export class A {}
@Component({ selector: 'b', template: '<div><span></div' }) export class B {}`,
    });
    const codes = r.diagnostics.map((d) => d.code);
    expect(codes).toContain('template-not-found');
    expect(codes).toContain('template-parse-error');
  });

  it('fails clearly on an invalid angular.json and a missing project directory', async () => {
    const bad = await run(disk({ 'angular.json': '{ "projects": ', 'src/a.ts': '' }));
    expect(bad.diagnostics.find((d) => d.code === 'workspace-invalid')!.level).toBe('error');
    const missing = await run(path.join(tmp, 'nope'));
    expect(missing.diagnostics[0]!.code).toBe('workspace-not-found');
  });

  it('warns for Angular versions outside the tested range', async () => {
    const r = await run(disk({
      'angular.json': ANGULAR_JSON,
      'package.json': JSON.stringify({ dependencies: { '@angular/core': '^17.3.0' } }),
      'tsconfig.json': '{ "include": ["src/**/*.ts"] }',
      'src/a.ts': 'export const a = 1;',
    }));
    expect(r.diagnostics.find((d) => d.code === 'angular-version-unsupported')!.message).toContain('17.3.0');
  });

  it('reports unresolvable imports and falls back to declaration-based identification', async () => {
    const r = await run(disk({
      'angular.json': ANGULAR_JSON,
      'tsconfig.json': '{ "compilerOptions": { "experimentalDecorators": true }, "include": ["src/**/*.ts"] }',
      'src/a.ts': `import { DomSanitizer } from '@angular/platform-browser';
import { helper } from './does-not-exist';
export class A { constructor(private s: DomSanitizer) {} x = this.s.bypassSecurityTrustHtml(location.hash + helper()); }`,
    }));
    expect(r.diagnostics.find((d) => d.code === 'unresolved-imports')!.message).toMatch(/@angular\/platform-browser/);
    expect(r.findings.find((f) => f.ruleId === 'NGB001')!.confidence).toBe('high');
  });

  it('terminates on circular imports and recursive functions', async () => {
    const r = await run('/virtual/r3', {
      'src/a.ts': `import { b } from './b';\nexport function a(x: string): string { return x.length > 3 ? b(x) : x; }`,
      'src/b.ts': `import { a } from './a';\nexport function b(y: string): string { return a(y.slice(1)); }\nexport function sink(el: HTMLElement) { el.innerHTML = a(location.hash); }`,
    });
    expect(r.findings.filter((f) => f.ruleId === 'NGB003')).toHaveLength(1);
  });

  it('handles large files within a reasonable time', async () => {
    const body = Array.from({ length: 4000 }, (_, i) => `export function f${i}(el: HTMLElement, v: string) { const x${i} = v + '${i}'; el.textContent = x${i}; }`).join('\n');
    const started = Date.now();
    const r = await run('/virtual/r4', { 'src/big.ts': `${body}\nexport function bad(el: HTMLElement) { el.innerHTML = location.hash; }` });
    expect(r.findings.filter((f) => f.ruleId === 'NGB003')).toHaveLength(1);
    expect(Date.now() - started).toBeLessThan(20_000);
  });

  it('surfaces analysis limits instead of silently dropping paths', async () => {
    const chain = Array.from({ length: 30 }, (_, i) => `const v${i + 1} = v${i};`).join('\n');
    const r = await run('/virtual/r5', { 'src/a.ts': `export function f(el: HTMLElement) {\nconst v0 = location.hash;\n${chain}\nel.innerHTML = v30;\n}` }, { maxDepth: 10 });
    expect(r.diagnostics.find((d) => d.code === 'analysis-incomplete')!.level).toBe('warning');
    expect(r.stats.truncatedTraces).toBeGreaterThan(0);
  });

  it('respects exclusions for files and directories', async () => {
    const config = await resolveConfig({ minConfidence: 'low', exclude: ['src/legacy/**', '**/*.gen.ts'] }, { cwd: '/virtual/r6' });
    const r = await scan({
      cwd: '/virtual/r6', config, rules: builtinRules, files: {
        'src/legacy/old.ts': 'export function f(el: HTMLElement) { el.innerHTML = location.hash; }',
        'src/x.gen.ts': 'export function g(el: HTMLElement) { el.innerHTML = location.hash; }',
        'src/a.spec.ts': 'export function h(el: HTMLElement) { el.innerHTML = location.hash; }',
        'src/app.ts': 'export const ok = 1;',
      },
    });
    expect(r.findings).toEqual([]);
    expect(r.stats.filesAnalyzed).toBe(1);
  });
});
