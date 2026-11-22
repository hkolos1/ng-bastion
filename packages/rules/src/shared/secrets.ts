import type { Confidence, Severity } from '@ngbastion/plugin-api';
import { words } from './sensitivity.js';

export interface SecretPattern {
  name: string;
  re: RegExp;
  severity: Severity;
  confidence: Confidence;
}

/**
 * Formats of private credentials. Publishable / public identifiers (Stripe `pk_…`,
 * Google/Firebase `AIza…` browser keys, OAuth client IDs) are deliberately absent.
 */
export const SECRET_PATTERNS: SecretPattern[] = [
  { name: 'Stripe live secret key', re: /^(sk|rk)_live_[A-Za-z0-9]{16,}$/, severity: 'critical', confidence: 'high' },
  { name: 'Stripe test secret key', re: /^(sk|rk)_test_[A-Za-z0-9]{16,}$/, severity: 'low', confidence: 'high' },
  { name: 'AWS access key ID', re: /^(AKIA|ASIA)[A-Z0-9]{16}$/, severity: 'high', confidence: 'medium' },
  { name: 'GitHub token', re: /^(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}$|^github_pat_[A-Za-z0-9_]{40,}$/, severity: 'critical', confidence: 'high' },
  { name: 'Slack token', re: /^xox[baprs]-[A-Za-z0-9-]{10,}$/, severity: 'high', confidence: 'high' },
  { name: 'Private key (PEM)', re: /-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/, severity: 'critical', confidence: 'high' },
  { name: 'OpenAI API key', re: /^sk-(proj-)?[A-Za-z0-9_-]{32,}$/, severity: 'high', confidence: 'medium' },
  { name: 'Anthropic API key', re: /^sk-ant-[A-Za-z0-9_-]{32,}$/, severity: 'critical', confidence: 'high' },
  { name: 'SendGrid API key', re: /^SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}$/, severity: 'high', confidence: 'high' },
  { name: 'npm access token', re: /^npm_[A-Za-z0-9]{36}$/, severity: 'high', confidence: 'high' },
  { name: 'JSON Web Token', re: /^eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/, severity: 'high', confidence: 'medium' },
];

/** Names whose value is expected to be private. */
const SECRET_NAME = /(secret|password|passwd|privatekey|clientsecret|apisecret|secretkey|accesstoken|authtoken|refreshtoken|signingkey|encryptionkey|awssecretaccesskey)$/;
/** Names that mark a value as public by design. */
const PUBLIC_NAME = /(public|publishable|clientid|siteid|sitekey|measurementid|appid|projectid|tenantid|dsn)/;

export function secretName(name: string): boolean {
  const joined = words(name).join('');
  return SECRET_NAME.test(joined) && !PUBLIC_NAME.test(joined);
}

const PLACEHOLDER = /^(change[-_ ]?me|replace[-_ ]?me|x{3,}|\*{3,}|todo|tbd|none|null|undefined|n\/a|secret|password)$|^<.*>$|^\$\{.*\}$|^%.*%$|^\{\{.*\}\}$|your[-_ ]|example|dummy|placeholder|sample|^test|fake|mock|redacted/i;

export function isPlaceholder(value: string): boolean {
  return PLACEHOLDER.test(value.trim()) || /^(.)\1*$/.test(value);
}

/** Shannon entropy in bits per character. */
export function entropy(value: string): number {
  const counts = new Map<string, number>();
  for (const c of value) counts.set(c, (counts.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Never print a secret: keep four characters and the length. */
export function redact(value: string): string {
  return `${value.slice(0, 4)}…(${value.length} chars)`;
}

export interface SecretMatch {
  kind: string;
  severity?: Severity;
  confidence: Confidence;
}

/** Classifies a literal value, optionally with the name it is assigned to. */
export function classifySecret(value: string, name?: string): SecretMatch | undefined {
  const v = value.trim();
  if (v.length < 8) return undefined;
  for (const p of SECRET_PATTERNS) {
    if (p.re.test(v)) return { kind: p.name, severity: p.severity, confidence: p.confidence };
  }
  if (!name || !secretName(name) || isPlaceholder(v) || v.length < 16 || /\s/.test(v) || /^(https?:|\/|\.)/.test(v)) return undefined;
  const h = entropy(v);
  if (h < 3) return undefined;
  return { kind: `high-entropy value assigned to '${name}'`, confidence: h >= 4 ? 'medium' : 'low' };
}
