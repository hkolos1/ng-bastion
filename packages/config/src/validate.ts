import { CONFIDENCES, SEVERITIES } from '@ngbastion/plugin-api';
import type { NgBastionConfig } from './types.js';

const LEVELS = ['error', 'warn', 'off'];
const LIMIT_KEYS = ['maxDepth', 'maxCallSites', 'maxFileHops', 'maxVisitedNodes', 'maxPathsPerSink', 'maxTimeMs'];
const TOP_KEYS = [
  '$schema', 'extends', 'rules', 'include', 'exclude', 'projects', 'failOn', 'minConfidence',
  'limits', 'trustedSanitizers', 'plugins', 'exceptions', 'policy',
];

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const list = (values: readonly string[]) => values.map((v) => `'${v}'`).join(' | ');

/**
 * Validates an untrusted config object. Returns human-readable errors with
 * property paths; an empty array means the value is a valid NgBastionConfig.
 */
export function validateConfig(value: unknown): string[] {
  const errors: string[] = [];
  const err = (path: string, msg: string) => errors.push(`${path}: ${msg}`);
  const stringArray = (path: string, v: unknown) => {
    if (!Array.isArray(v) || v.some((x) => typeof x !== 'string' || x.length === 0)) {
      err(path, 'expected an array of non-empty strings');
    }
  };

  if (!isObject(value)) return ['config: expected an object'];
  for (const key of Object.keys(value)) {
    if (!TOP_KEYS.includes(key)) err(key, `unknown property (allowed: ${TOP_KEYS.slice(1).join(', ')})`);
  }
  for (const key of ['extends', 'include', 'exclude', 'projects', 'trustedSanitizers', 'plugins'] as const) {
    if (value[key] !== undefined) stringArray(key, value[key]);
  }
  if (value.failOn !== undefined && !(value.failOn === 'none' || SEVERITIES.includes(value.failOn as never))) {
    err('failOn', `expected ${list([...SEVERITIES, 'none'])}`);
  }
  if (value.minConfidence !== undefined && !CONFIDENCES.includes(value.minConfidence as never)) {
    err('minConfidence', `expected ${list(CONFIDENCES)}`);
  }

  if (value.rules !== undefined) {
    if (!isObject(value.rules)) err('rules', 'expected an object keyed by rule id');
    else {
      for (const [id, setting] of Object.entries(value.rules)) {
        const path = `rules.${id}`;
        if (!/^[A-Z][A-Z0-9_-]*\d+$/.test(id)) err(path, 'rule ids look like NGB001');
        if (typeof setting === 'string') {
          if (!LEVELS.includes(setting)) err(path, `expected ${list(LEVELS)} or an object`);
        } else if (isObject(setting)) {
          for (const k of Object.keys(setting)) {
            if (!['level', 'severity', 'options'].includes(k)) err(`${path}.${k}`, 'unknown property');
          }
          if (setting.level !== undefined && !LEVELS.includes(setting.level as string)) {
            err(`${path}.level`, `expected ${list(LEVELS)}`);
          }
          if (setting.severity !== undefined && !SEVERITIES.includes(setting.severity as never)) {
            err(`${path}.severity`, `expected ${list(SEVERITIES)}`);
          }
          if (setting.options !== undefined && !isObject(setting.options)) err(`${path}.options`, 'expected an object');
        } else err(path, `expected ${list(LEVELS)} or an object`);
      }
    }
  }

  if (value.limits !== undefined) {
    if (!isObject(value.limits)) err('limits', 'expected an object');
    else {
      for (const [k, v] of Object.entries(value.limits)) {
        if (!LIMIT_KEYS.includes(k)) err(`limits.${k}`, `unknown limit (allowed: ${LIMIT_KEYS.join(', ')})`);
        else if (typeof v !== 'number' || !Number.isInteger(v) || v <= 0) err(`limits.${k}`, 'expected a positive integer');
      }
    }
  }

  if (value.exceptions !== undefined) {
    if (!Array.isArray(value.exceptions)) err('exceptions', 'expected an array');
    else {
      value.exceptions.forEach((e, i) => {
        const path = `exceptions[${i}]`;
        if (!isObject(e)) return err(path, 'expected an object');
        for (const k of Object.keys(e)) {
          if (!['rule', 'files', 'justification', 'expires', 'fingerprint', 'line'].includes(k)) {
            err(`${path}.${k}`, 'unknown property');
          }
        }
        if (typeof e.rule !== 'string' || !e.rule) err(`${path}.rule`, 'required rule id');
        if (e.files === undefined) err(`${path}.files`, 'required: narrow the exception to specific files');
        else stringArray(`${path}.files`, e.files);
        if (typeof e.justification !== 'string' || e.justification.trim().length < 10) {
          err(`${path}.justification`, 'required: explain why the finding is accepted (at least 10 characters)');
        }
        if (e.expires !== undefined && (typeof e.expires !== 'string' || !isIsoDate(e.expires))) {
          err(`${path}.expires`, 'expected an ISO date YYYY-MM-DD');
        }
        if (e.fingerprint !== undefined && typeof e.fingerprint !== 'string') err(`${path}.fingerprint`, 'expected a string');
        if (e.line !== undefined && (!Number.isInteger(e.line) || (e.line as number) < 1)) {
          err(`${path}.line`, 'expected a positive integer');
        }
      });
    }
  }

  if (value.policy !== undefined) {
    const p = value.policy;
    if (!isObject(p)) err('policy', 'expected an object');
    else {
      for (const k of Object.keys(p)) {
        if (!['name', 'mandatoryRules', 'maxFailOn', 'allowInlineSuppressions', 'requireExceptionExpiry', 'maxExceptionDays'].includes(k)) {
          err(`policy.${k}`, 'unknown property');
        }
      }
      if (p.name !== undefined && typeof p.name !== 'string') err('policy.name', 'expected a string');
      if (p.mandatoryRules !== undefined) stringArray('policy.mandatoryRules', p.mandatoryRules);
      if (p.maxFailOn !== undefined && !SEVERITIES.includes(p.maxFailOn as never)) {
        err('policy.maxFailOn', `expected ${list(SEVERITIES)}`);
      }
      for (const k of ['allowInlineSuppressions', 'requireExceptionExpiry'] as const) {
        if (p[k] !== undefined && typeof p[k] !== 'boolean') err(`policy.${k}`, 'expected a boolean');
      }
      if (p.maxExceptionDays !== undefined && (!Number.isInteger(p.maxExceptionDays) || (p.maxExceptionDays as number) < 1)) {
        err('policy.maxExceptionDays', 'expected a positive integer');
      }
    }
  }
  return errors;
}

export function isIsoDate(s: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(`${s}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().startsWith(s);
}

export function assertConfig(value: unknown): asserts value is NgBastionConfig {
  const errors = validateConfig(value);
  if (errors.length) throw new Error(errors.join('\n'));
}
