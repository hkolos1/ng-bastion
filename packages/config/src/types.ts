import type { Confidence, Severity } from '@ngbastion/plugin-api';

export type RuleLevel = 'error' | 'warn' | 'off';

export type RuleSetting =
  | RuleLevel
  | {
      level?: RuleLevel;
      /** Overrides the rule's default severity for all its findings. */
      severity?: Severity;
      options?: Record<string, unknown>;
    };

export interface AnalysisLimits {
  /** Maximum backward propagation steps per trace. */
  maxDepth: number;
  /** Maximum call sites followed when a parameter has no binding context. */
  maxCallSites: number;
  /** Maximum distinct files a single trace may cross. */
  maxFileHops: number;
  /** Maximum expression nodes visited per trace. */
  maxVisitedNodes: number;
  /** Maximum flows reported per sink. */
  maxPathsPerSink: number;
  /** Wall-clock budget for the whole analysis phase of one project. */
  maxTimeMs: number;
}

export interface ExceptionEntry {
  rule: string;
  /** Globs relative to the workspace root. Required; `**` alone is rejected. */
  files: string[];
  justification: string;
  /** ISO date (YYYY-MM-DD). After this day the exception stops applying. */
  expires?: string;
  /** Restrict to one finding by its stable fingerprint. */
  fingerprint?: string;
  /** Restrict to a 1-based line. */
  line?: number;
}

export interface PolicyConfig {
  name?: string;
  /** Rules projects may not disable or downgrade to `warn`. */
  mandatoryRules?: string[];
  /** The loosest allowed `failOn` threshold (e.g. `high` forbids `critical` and `none`). */
  maxFailOn?: Severity;
  allowInlineSuppressions?: boolean;
  requireExceptionExpiry?: boolean;
  maxExceptionDays?: number;
}

export interface NgBastionConfig {
  /** Presets (`recommended`, `strict`, `enterprise`, `payments`), relative files or installed packages. */
  extends?: string[];
  rules?: Record<string, RuleSetting>;
  /** Extra globs that restrict analyzed files (relative to workspace root). */
  include?: string[];
  exclude?: string[];
  /** angular.json project names to scan (default: all). */
  projects?: string[];
  failOn?: Severity | 'none';
  minConfidence?: Confidence;
  limits?: Partial<AnalysisLimits>;
  /** Project functions trusted as HTML/URL sanitizers, as `path/to/file.ts#functionName` or `functionName`. */
  trustedSanitizers?: string[];
  /** Plugin modules (package names or relative paths). Plugins run as trusted code. */
  plugins?: string[];
  exceptions?: ExceptionEntry[];
  policy?: PolicyConfig;
}

export interface ResolvedRuleSetting {
  level: RuleLevel;
  severity?: Severity;
  options: Record<string, unknown>;
}

export interface ResolvedException extends ExceptionEntry {
  /** Config file (or preset) that declared it. */
  source: string;
}

export interface ResolvedPolicy {
  sources: string[];
  mandatoryRules: Map<string, string>;
  maxFailOn?: Severity;
  allowInlineSuppressions: boolean;
  requireExceptionExpiry: boolean;
  maxExceptionDays?: number;
}

export interface ConfigDiagnostic {
  code: 'config-invalid' | 'config-not-found' | 'policy-violation' | 'exception-invalid' | 'unknown-rule';
  level: 'error' | 'warning';
  message: string;
  file?: string;
}

export interface ResolvedPlugin {
  specifier: string;
  /** Directory the specifier is resolved from. */
  from: string;
}

export interface ResolvedConfig {
  rules: Record<string, ResolvedRuleSetting>;
  include: string[];
  exclude: string[];
  projects: string[];
  failOn: Severity | 'none';
  minConfidence: Confidence;
  limits: AnalysisLimits;
  trustedSanitizers: string[];
  plugins: ResolvedPlugin[];
  exceptions: ResolvedException[];
  policy: ResolvedPolicy;
  /** Config files and presets, in application order. */
  sources: string[];
  diagnostics: ConfigDiagnostic[];
}
