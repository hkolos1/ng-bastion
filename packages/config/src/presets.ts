import type { AnalysisLimits, NgBastionConfig, RuleLevel } from './types.js';

/** Must match `builtinRules` in @ngbastion/rules (asserted by its registry test). */
export const BUILTIN_RULE_IDS = Array.from({ length: 50 }, (_, i) => `NGB${String(i + 1).padStart(3, '0')}`);

export const DEFAULT_LIMITS: AnalysisLimits = {
  maxDepth: 40,
  maxCallSites: 25,
  maxFileHops: 12,
  maxVisitedNodes: 20_000,
  maxPathsPerSink: 5,
  maxTimeMs: 120_000,
};

/** Context-dependent or heuristic rules: enabled as warnings in `recommended`. */
const RECOMMENDED_WARN = ['NGB008', 'NGB010', 'NGB019', 'NGB022', 'NGB027', 'NGB028', 'NGB030', 'NGB033', 'NGB037', 'NGB044', 'NGB045'];

const all = (level: RuleLevel) => Object.fromEntries(BUILTIN_RULE_IDS.map((id) => [id, level]));

/**
 * Built-in presets. Rule selections are explicit so documentation can list them.
 * - recommended: every rule enabled; context-dependent or heuristic rules only warn (never fail the gate).
 *   Gate on high+ findings; hide low-confidence findings.
 * - strict: every rule is an error, gate on medium+, show low-confidence findings.
 * - enterprise: strict reporting plus a governance policy (mandatory rules, expiring exceptions,
 *   no inline suppressions).
 * - payments: recommended plus payment/credential rules as mandatory errors and low-confidence
 *   findings visible. It does NOT certify PCI DSS compliance.
 */
export const PRESETS: Record<string, NgBastionConfig> = {
  recommended: {
    rules: { ...all('error'), ...Object.fromEntries(RECOMMENDED_WARN.map((id) => [id, 'warn' as const])) },
    exclude: ['**/*.spec.ts', '**/*.test.ts', '**/e2e/**', '**/cypress/**', '**/playwright/**'],
    failOn: 'high',
    minConfidence: 'medium',
  },
  strict: {
    rules: all('error'),
    exclude: ['**/*.spec.ts', '**/*.test.ts', '**/e2e/**', '**/cypress/**', '**/playwright/**'],
    failOn: 'medium',
    minConfidence: 'low',
  },
  enterprise: {
    extends: ['strict'],
    failOn: 'high',
    minConfidence: 'medium',
    policy: {
      name: 'ngbastion:enterprise',
      mandatoryRules: ['NGB001', 'NGB002', 'NGB003', 'NGB004', 'NGB005', 'NGB007', 'NGB011', 'NGB013', 'NGB014', 'NGB015', 'NGB016', 'NGB018', 'NGB020'],
      maxFailOn: 'high',
      allowInlineSuppressions: false,
      requireExceptionExpiry: true,
      maxExceptionDays: 180,
    },
  },
  payments: {
    extends: ['recommended'],
    rules: { NGB013: 'error', NGB014: 'error', NGB015: 'error', NGB016: 'error', NGB017: 'error', NGB018: 'error' },
    minConfidence: 'low',
    policy: {
      name: 'ngbastion:payments',
      mandatoryRules: ['NGB013', 'NGB015', 'NGB016', 'NGB017', 'NGB018'],
      requireExceptionExpiry: true,
    },
  },
};
