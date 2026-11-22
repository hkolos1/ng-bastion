import type { Confidence, Severity } from '@ngbastion/plugin-api';

export type Csp = Map<string, string[]>;

/** Parses a CSP header value. Directive names are lowercased; the first occurrence wins (per spec). */
export function parseCsp(policy: string): Csp {
  const csp: Csp = new Map();
  for (const part of policy.split(';')) {
    const [name, ...values] = part.trim().split(/\s+/);
    if (!name) continue;
    const key = name.toLowerCase();
    if (!csp.has(key)) csp.set(key, values);
  }
  return csp;
}

export interface CspIssue {
  message: string;
  severity: Severity;
  confidence: Confidence;
}

const lower = (xs: string[] | undefined) => xs?.map((x) => x.toLowerCase());

/** Risky patterns in an enforced policy. */
export function evaluateCsp(csp: Csp): CspIssue[] {
  const issues: CspIssue[] = [];
  const def = lower(csp.get('default-src'));
  const script = lower(csp.get('script-src')) ?? def;
  if (!script) {
    issues.push({ message: "policy has neither script-src nor default-src, so it does not restrict scripts", severity: 'medium', confidence: 'high' });
  } else {
    const nonceOrHash = script.some((s) => /^'(nonce-|sha256-|sha384-|sha512-)/.test(s));
    const strictDynamic = script.includes("'strict-dynamic'");
    const src = csp.has('script-src') ? 'script-src' : 'default-src';
    if (script.includes("'unsafe-inline'") && !nonceOrHash) {
      issues.push({ message: `${src} allows 'unsafe-inline' without a nonce or hash; injected inline scripts will run`, severity: 'medium', confidence: 'high' });
    }
    if (script.includes("'unsafe-eval'")) {
      issues.push({ message: `${src} allows 'unsafe-eval' (string-to-code execution)`, severity: 'medium', confidence: 'high' });
    }
    const broad = script.filter((s) => s === '*' || s === 'http:' || s === 'https:' || s === 'data:' || s === 'blob:');
    if (broad.length && !(strictDynamic && nonceOrHash && !broad.includes('data:'))) {
      issues.push({ message: `${src} allows scripts from overly broad sources (${broad.join(' ')})`, severity: 'medium', confidence: 'high' });
    }
  }
  const object = lower(csp.get('object-src')) ?? def;
  if (!object || !object.includes("'none'")) {
    issues.push({ message: "object-src is not restricted to 'none' (plugins can load scripts)", severity: 'low', confidence: 'high' });
  }
  const tt = lower(csp.get('trusted-types'));
  if (tt) {
    if (tt.includes('*') || tt.includes("'allow-duplicates'")) {
      issues.push({ message: `trusted-types allows ${tt.includes('*') ? 'any policy name (*)' : "'allow-duplicates'"}, weakening policy control`, severity: 'medium', confidence: 'high' });
    }
    if (tt.includes('angular#unsafe-bypass')) {
      issues.push({ message: "trusted-types permits 'angular#unsafe-bypass', so bypassSecurityTrust* values are accepted as trusted", severity: 'info', confidence: 'high' });
    }
    if (!csp.has('require-trusted-types-for')) {
      issues.push({ message: "trusted-types policies are declared but not enforced (missing require-trusted-types-for 'script')", severity: 'info', confidence: 'high' });
    }
  }
  return issues;
}
