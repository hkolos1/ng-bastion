import { describe, expect, it } from 'vitest';
import { findings, scanFiles } from './helpers.js';

const html = (csp: string) => `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="${csp}">
</head>
<body><app-root></app-root></body>
</html>`;
const app = { 'src/main.ts': 'export const x = 1;' };

describe('NGB019 unsafe CSP / Trusted Types', () => {
  it("reports 'unsafe-inline' and 'unsafe-eval' in an index.html meta policy", async () => {
    const res = await findings('NGB019', { ...app, 'src/index.html': html("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'none'") });
    expect(res.map((f) => f.message)).toEqual([
      expect.stringContaining("'unsafe-inline'"),
      expect.stringContaining("'unsafe-eval'"),
    ]);
    expect(res[0]!.location.file).toBe('src/index.html');
    expect(res[0]!.location.line).toBe(5);
    expect(res.every((f) => f.severity === 'medium' && f.confidence === 'high')).toBe(true);
  });

  it('reports permissive Trusted Types and wildcard script sources from server code and hosting config', async () => {
    const res = await findings('NGB019', {
      'server.ts': `declare const res: { setHeader(n: string, v: string): void };
res.setHeader('Content-Security-Policy', "script-src 'self' https:; object-src 'none'; trusted-types * ; require-trusted-types-for 'script'");`,
      'firebase.json': JSON.stringify({ hosting: { headers: [{ source: '**', headers: [{ key: 'Content-Security-Policy', value: "script-src *; object-src 'self'" }] }] } }, null, 2),
    });
    const msgs = res.map((f) => f.message).join('\n');
    expect(msgs).toMatch(/overly broad sources \(https:\)/);
    expect(msgs).toMatch(/trusted-types allows any policy name/);
    expect(msgs).toMatch(/firebase\.json.*overly broad sources \(\*\)/);
    expect(msgs).toMatch(/object-src is not restricted/);
  });

  it('safe equivalent: a strict nonce policy with Trusted Types produces no finding', async () => {
    expect(await findings('NGB019', { ...app, 'src/index.html': html("script-src 'nonce-r4nd0m' 'strict-dynamic' https:; object-src 'none'; base-uri 'self'; require-trusted-types-for 'script'; trusted-types angular") })).toEqual([]);
  });

  it('does not claim CSP is missing when none is observable (diagnostic only)', async () => {
    const result = await scanFiles({ ...app, 'src/index.html': '<html><head></head><body></body></html>' }, ['NGB019']);
    expect(result.findings).toEqual([]);
    expect(result.diagnostics.some((d) => d.code === 'csp-not-assessed')).toBe(true);
  });

  it('recognizes angular.json autoCsp as an observed policy', async () => {
    const result = await scanFiles({ ...app, 'angular.json': JSON.stringify({ projects: { web: { architect: { build: { options: { security: { autoCsp: true } } } } } } }) }, ['NGB019']);
    expect(result.findings).toEqual([]);
    expect(result.diagnostics.some((d) => d.code === 'csp-not-assessed')).toBe(false);
  });

  it('false-positive regression: report-only policies and unrelated meta tags are ignored', async () => {
    expect(await findings('NGB019', {
      ...app,
      'src/index.html': `<meta name="description" content="script-src 'unsafe-inline'"><meta http-equiv="Content-Security-Policy-Report-Only" content="script-src 'unsafe-inline'">`,
    })).toEqual([]);
  });
});
