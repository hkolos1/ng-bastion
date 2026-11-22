import { defineRule, type AnalysisContext, type RuleFinding, type SourceLocation } from '@ngbastion/plugin-api';
import { relative } from '../shared/common.js';
import { evaluateCsp, parseCsp } from '../shared/csp.js';

interface ObservedPolicy {
  value: string;
  location: SourceLocation;
  origin: string;
}

const HEADER = 'content-security-policy';

function lineLocation(file: string, text: string, index: number, length: number): SourceLocation {
  const before = text.slice(0, index).split(/\r?\n/);
  const line = before.length;
  const column = before[before.length - 1]!.length + 1;
  return { file, line, column, endLine: line, endColumn: column + length };
}

function fromIndexHtml(ctx: AnalysisContext): ObservedPolicy[] {
  const file = ctx.project.indexHtml;
  const text = file && ctx.readFile(file);
  if (!file || !text) return [];
  const out: ObservedPolicy[] = [];
  for (const m of text.matchAll(/<meta\b[^>]*>/gi)) {
    const tag = m[0];
    if (!/http-equiv\s*=\s*["']?content-security-policy["'\s>]/i.test(tag)) continue;
    const content = /content\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(tag);
    if (content) out.push({ value: content[1] ?? content[2] ?? '', location: lineLocation(file, text, m.index, tag.length), origin: `<meta> in ${relative(ctx, file)}` });
  }
  return out;
}

function autoCspEnabled(ctx: AnalysisContext): boolean {
  const p = ctx.project.angularProject as Record<string, Record<string, Record<string, unknown>>> | undefined;
  const build = (p?.architect ?? p?.targets)?.build as { options?: { security?: { autoCsp?: unknown } }; configurations?: Record<string, { security?: { autoCsp?: unknown } }> } | undefined;
  if (!build) return false;
  const configs = Object.values(build.configurations ?? {});
  return build.options?.security?.autoCsp === true || configs.some((c) => c.security?.autoCsp === true);
}

function fromTypeScript(ctx: AnalysisContext): { policies: ObservedPolicy[]; dynamic: number } {
  const t = ctx.ts;
  const policies: ObservedPolicy[] = [];
  let dynamic = 0;
  for (const lit of ctx.index.stringLiterals) {
    if (lit.text.toLowerCase() !== HEADER) continue;
    const p = lit.parent;
    let valueExpr;
    if (t.isCallExpression(p) && p.arguments[0] === lit) valueExpr = p.arguments[1];
    else if (t.isPropertyAssignment(p) && p.name === lit) valueExpr = p.initializer;
    if (!valueExpr) continue;
    const value = ctx.symbols.constantString(valueExpr);
    if (value === undefined) dynamic++;
    else policies.push({ value, location: ctx.location(valueExpr), origin: `header set in ${relative(ctx, lit.getSourceFile().fileName)}` });
  }
  return { policies, dynamic };
}

function fromHostingConfig(ctx: AnalysisContext): ObservedPolicy[] {
  const out: ObservedPolicy[] = [];
  for (const file of ['firebase.json', 'vercel.json', 'staticwebapp.config.json'].flatMap((g) => ctx.findFiles(g))) {
    const text = ctx.readFile(file);
    if (!text) continue;
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      continue;
    }
    const add = (value: string) => {
      const idx = text.indexOf(JSON.stringify(value));
      out.push({ value, location: lineLocation(file, text, Math.max(0, idx), value.length), origin: relative(ctx, file) });
    };
    const walk = (v: unknown): void => {
      if (Array.isArray(v)) v.forEach(walk);
      else if (v && typeof v === 'object') {
        const o = v as Record<string, unknown>;
        if (typeof o.key === 'string' && o.key.toLowerCase() === HEADER && typeof o.value === 'string') add(o.value);
        for (const [k, x] of Object.entries(o)) {
          if (k.toLowerCase() === HEADER && typeof x === 'string') add(x);
          else walk(x);
        }
      }
    };
    walk(json);
  }
  for (const file of ctx.findFiles('**/_headers')) {
    const text = ctx.readFile(file);
    if (!text) continue;
    for (const m of text.matchAll(/^[ \t]*Content-Security-Policy:[ \t]*(.+)$/gim)) {
      out.push({ value: m[1]!.trim(), location: lineLocation(file, text, m.index, m[0].length), origin: relative(ctx, file) });
    }
  }
  return out;
}

export const ngb019 = defineRule({
  meta: {
    id: 'NGB019',
    name: 'Unsafe CSP / Trusted Types policy',
    category: 'security-config',
    defaultSeverity: 'medium',
    cwe: ['CWE-693'],
    docs: {
      description:
        'Evaluates Content Security Policies that are statically visible in the repository — `<meta http-equiv="Content-Security-Policy">` in the project index.html, constant header values set in TypeScript (e.g. an SSR `server.ts`), and hosting configs (`firebase.json`, `vercel.json`, `staticwebapp.config.json`, `_headers`) — and reports risky directives. When no policy is observable, it emits a `csp-not-assessed` diagnostic instead of a finding.',
      rationale:
        'A strict CSP with Trusted Types is the main browser-side mitigation if an XSS bug slips through. `unsafe-inline` without nonces, `unsafe-eval`, wildcard script sources or permissive Trusted Types settings remove most of that protection.',
      patterns: [
        "script-src (or default-src fallback) with 'unsafe-inline' and no nonce/hash",
        "'unsafe-eval'; '*', 'http:', 'https:', 'data:', 'blob:' script sources (host sources are tolerated with 'strict-dynamic' + nonce/hash)",
        "missing object-src 'none' (low)",
        "trusted-types with '*' or 'allow-duplicates' (medium); 'angular#unsafe-bypass' and trusted-types without require-trusted-types-for (informational)",
        'angular.json `security.autoCsp: true` is recognized as an observed, hash-based policy',
      ],
      limitations: [
        'Production HTTP response headers (CDN, reverse proxy, server config outside the repo) cannot be seen; their absence is reported as "not assessed", never as missing CSP.',
        'Structured header builders (e.g. helmet `contentSecurityPolicy.directives`) and dynamically built header strings are not evaluated; dynamic values produce an informational diagnostic.',
        'Report-only policies are ignored because they do not enforce anything.',
      ],
      falsePositives: [
        "A meta CSP that is replaced by a stricter header at deploy time is still reported; prefer keeping one source of truth.",
      ],
      remediation:
        "Enable Angular `security.autoCsp` or serve a nonce-based policy: `script-src 'nonce-…' 'strict-dynamic'; object-src 'none'; base-uri 'self'; require-trusted-types-for 'script'; trusted-types angular`. Remove 'unsafe-eval' and 'unsafe-inline'.",
      example: {
        unsafe: `<meta http-equiv="Content-Security-Policy" content="script-src 'self' 'unsafe-inline' 'unsafe-eval'">`,
        safe: `"security": { "autoCsp": true }   // angular.json build options`,
      },
      references: [
        { title: 'Angular — Content security policy', url: 'https://angular.dev/best-practices/security#content-security-policy' },
        { title: 'Angular — Enforcing Trusted Types', url: 'https://angular.dev/best-practices/security#enforcing-trusted-types' },
      ],
    },
  },
  analyze(ctx) {
    const ts = fromTypeScript(ctx);
    const policies = [...fromIndexHtml(ctx), ...ts.policies, ...fromHostingConfig(ctx)];
    if (ts.dynamic) {
      ctx.diagnostic({ code: 'csp-dynamic', level: 'info', message: `NGB019: ${ts.dynamic} Content-Security-Policy header value(s) are built dynamically and were not evaluated` });
    }
    if (!policies.length) {
      if (!autoCspEnabled(ctx) && !ts.dynamic) {
        ctx.diagnostic({
          code: 'csp-not-assessed',
          level: 'info',
          message: `NGB019: no Content-Security-Policy is visible in project '${ctx.project.name}' (index.html, server code, hosting config). CSP may still be set by your server or CDN; it was not assessed.`,
        });
      }
      return [];
    }
    const findings: RuleFinding[] = [];
    for (const p of policies) {
      for (const issue of evaluateCsp(parseCsp(p.value))) {
        findings.push({
          location: p.location,
          message: `Content-Security-Policy (${p.origin}): ${issue.message}.`,
          confidence: issue.confidence,
          severity: issue.severity,
          evidenceKind: 'pattern',
          evidence: [`policy: ${p.value.slice(0, 200)}`],
        });
      }
    }
    return findings;
  },
});
