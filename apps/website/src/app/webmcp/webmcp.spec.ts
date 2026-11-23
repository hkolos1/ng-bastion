import { createEnvironmentInjector, EnvironmentInjector } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { vi } from 'vitest';
import { analyzeSnippet } from './analysis';
import { explainRule, getRules, rules, searchRules } from './catalog';
import { inspect } from './inspect';
import { generateReport } from './report';
import { provideNgBastionTools } from './tools';
import * as client from './worker-client';

describe('generated rule catalog', () => {
  it('paginates all canonical rules in stable order and combines filters', () => {
    expect(getRules({}).total).toBe(100);
    expect(getRules({ offset: 10, limit: 2 }).rules.map(r => r.id)).toEqual(['NGB011', 'NGB012']);
    const page = getRules({ category: 'sensitive-data', severity: 'high' });
    expect(page.rules.some(r => r.id === 'NGB018')).toBe(true);
    expect(page.rules.every(r => r.category === 'sensitive-data' && r.severity === 'high')).toBe(true);
    expect(() => getRules({ limit: 26 })).toThrow();
    expect(() => getRules({ category: [] })).toThrow();
  });
  it('uses original descriptions, examples, references and no inferred autofix', () => {
    for (const rule of rules) {
      expect(explainRule({ ruleId: rule.id.toLowerCase() })).toMatchObject({ ...rule.docs,
        autofix: null, documentation: '/rules/' + rule.id.toLowerCase() + '/' });
    }
    expect(explainRule({ ruleId: 'NGB999' }).status).toBe('unknown_rule');
  });
  it('ranks keywords case-insensitively within filters and enforces bounds', () => {
    const args = { query: 'hardcoded frontend secrets', severity: 'high', limit: 1 };
    const hits = searchRules(args);
    expect(hits.rules.map(r => r.id)).toEqual(['NGB018']);
    expect(searchRules({ ...args, query: args.query.toUpperCase() })).toEqual(hits);
    expect(() => searchRules({ query: ' ' })).toThrow();
    expect(() => searchRules({ query: 'Angular', limit: 26 })).toThrow();
  });
});

describe('snippet adapter and renderer', () => {
  beforeEach(() => { vi.spyOn(client, 'runWorker').mockImplementation(async input => inspect(input)); });
  afterEach(() => vi.restoreAllMocks());
  const code = "\nconst clientSecret = 'BlueFern-84-Orbit-27';";
  it('reports a real literal location, redacts credentials, and preserves scanner severity', async () => {
    const result = await analyzeSnippet({ code });
    if (result.status !== 'ok') throw new Error('Expected a finding');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'NGB018', severity: 'high',
      location: { file: 'snippet.ts', line: 2, column: 22 } });
    expect(result.rulesExecuted).toEqual(['NGB018']);
    expect(result.rulesSkipped).toHaveLength(99);
    expect(await analyzeSnippet({ code })).toMatchObject({ findings: result.findings });
    const report = generateReport({ analysisId: result.analysisId });
    expect(report.html).toContain('data-severity="high"');
    expect(JSON.stringify(result) + report.html).not.toContain('BlueFern-84-Orbit-27');
  });
  it('encodes user-controlled property names in a report and rejects supplied HTML', async () => {
    const r = await analyzeSnippet({ code: "const config = {'<b>password':'BlueFern-84-Orbit-27'};" });
    if (r.status !== 'ok') throw new Error('Expected success');
    const report = generateReport({ analysisId: r.analysisId });
    expect(report.html).toContain('&lt;b&gt;password');
    expect(report.html).not.toContain('<b>password');
    expect(() => generateReport({ html: '<iframe>' })).toThrow();
    expect(generateReport({ analysisId: 'expired' }).status).toBe('unknown_analysis');
  });
  it('expires older reports after four more successful analyses', async () => {
    const first = await analyzeSnippet({ code });
    if (first.status !== 'ok') throw new Error('Expected success');
    for (let i = 0; i < 4; i++) await analyzeSnippet({ code });
    expect(generateReport({ analysisId: first.analysisId }).status).toBe('unknown_analysis');
  });
  it('distinguishes zero findings, parse errors, resource limits and unsupported checks', async () => {
    expect(await analyzeSnippet({ code: 'const title = "hello";' })).toMatchObject({ status: 'ok', findings: [] });
    expect(await analyzeSnippet({ code: 'const =;' })).toMatchObject({ status: 'error' });
    expect(await analyzeSnippet({ code: code.repeat(51) })).toMatchObject({ status: 'error' });
    expect(await analyzeSnippet({ code, ruleIds: ['NGB001'] })).toMatchObject({ status: 'unsupported', rulesExecuted: [], rulesSkipped: ['NGB001'] });
    expect(await analyzeSnippet({ code, language: 'html' })).toMatchObject({ status: 'unsupported' });
    for (const args of [{ code: '' }, { code, language: {} }, { code: 'x'.repeat(32769) }, { code, filename: '../a.ts' }, { code, ruleIds: ['other'] }]) {
      expect(await analyzeSnippet(args)).toMatchObject({ status: 'error' });
    }
  });
});

describe('Angular application provider', () => {
  const parent = () => TestBed.inject(EnvironmentInjector);
  afterEach(() => Reflect.deleteProperty(document, 'modelContext'));
  it('delegates handlers and ties exactly six registrations to the root injector lifetime', async () => {
    const registerTool = vi.fn();
    Object.defineProperty(document, 'modelContext', { configurable: true, value: { registerTool } });
    const root = createEnvironmentInjector([provideNgBastionTools()], parent());
    const route = createEnvironmentInjector([], root);
    route.destroy();
    const calls = registerTool.mock.calls;
    expect(new Set(calls.map(([t]) => t.name)).size).toBe(6);
    expect(calls).toHaveLength(6);
    for (const [, options] of calls) expect(options.signal.aborted).toBe(false);
    const invoke = (name: string, args: object) => calls.find(([t]) => t.name === 'ngbastion_' + name)![0].execute(args, {});
    expect(await invoke('get_rules', { limit: 1 })).toMatchObject({ total: 100 });
    expect(await invoke('explain_rule', { ruleId: 'NGB018' })).toMatchObject({ id: 'NGB018' });
    expect(await invoke('search_rules', { query: '' })).toMatchObject({ status: 'error' });
    expect(await invoke('analyze_snippet', { code: '' })).toMatchObject({ status: 'error' });
    expect(await invoke('generate_report', { analysisId: 'expired' })).toMatchObject({ status: 'unknown_analysis' });
    expect(await invoke('get_installation', {})).toMatchObject({ package: 'ngbastion' });
    root.destroy();
    for (const [, options] of calls) expect(options.signal.aborted).toBe(true);
  });
  it('initializes and tears down without WebMCP', () => {
    expect(() => createEnvironmentInjector([provideNgBastionTools()], parent()).destroy()).not.toThrow();
  });
});
