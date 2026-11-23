/**
 * @ngbastion/plugin-api — the versioned contract between the NgBastion engine
 * and security rules (built-in or third-party).
 *
 * SECURITY BOUNDARY: rules are ordinary JavaScript executed in the scanner's
 * Node.js process. This contract is NOT a sandbox. A configured plugin can read
 * files, open network connections and do anything the scanning user can do.
 * Only load plugins you trust.
 */
import type * as ts from 'typescript';

/** Bumped on every breaking change to the rule contract. */
export const PLUGIN_API_VERSION = 1;

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';

/** Ascending order. */
export const SEVERITIES: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
/** Ascending order. */
export const CONFIDENCES: readonly Confidence[] = ['low', 'medium', 'high'];

export const severityRank = (s: Severity): number => SEVERITIES.indexOf(s);
export const confidenceRank = (c: Confidence): number => CONFIDENCES.indexOf(c);

export function lowerConfidence(c: Confidence, steps = 1): Confidence {
  return CONFIDENCES[Math.max(0, confidenceRank(c) - steps)]!;
}
export function minConfidence(a: Confidence, b: Confidence): Confidence {
  return confidenceRank(a) <= confidenceRank(b) ? a : b;
}
export function maxConfidence(a: Confidence, b: Confidence): Confidence {
  return confidenceRank(a) >= confidenceRank(b) ? a : b;
}

export type RuleCategory =
  | 'angular-xss'
  | 'cross-window'
  | 'navigation-auth'
  | 'sensitive-data'
  | 'security-config'
  | 'ssr'
  | 'cryptography'
  | 'supply-chain';

export interface RuleDocs {
  /** One paragraph: what the rule checks. */
  description: string;
  /** Why the pattern matters. */
  rationale: string;
  /** Exact patterns the implementation recognizes. */
  patterns: string[];
  /** Patterns the implementation does not see (false-negative sources). */
  limitations: string[];
  /** Known situations that can still produce a finding that is not exploitable. */
  falsePositives: string[];
  remediation: string;
  example: { unsafe: string; safe: string };
  references?: { title: string; url: string }[];
}

export interface RuleMetadata {
  /** Unique, stable identifier, e.g. `NGB001` or `ACME001`. */
  id: string;
  name: string;
  category: RuleCategory | (string & {});
  defaultSeverity: Severity;
  cwe?: string[];
  docs: RuleDocs;
}

/**
 * How a finding was established.
 * - `dataflow`: a supported source-to-sink path was traced.
 * - `pattern`: a confirmed code/config pattern that is risky by itself.
 * - `heuristic`: name- or shape-based evidence; treat with more skepticism.
 */
export type EvidenceKind = 'dataflow' | 'pattern' | 'heuristic';

export interface SourceLocation {
  /** Absolute path. Reporters relativize it. */
  file: string;
  /** 1-based. */
  line: number;
  /** 1-based. */
  column: number;
  endLine: number;
  endColumn: number;
}

export type TraceStepKind =
  | 'source'
  | 'assignment'
  | 'argument'
  | 'parameter'
  | 'return'
  | 'property'
  | 'transform'
  | 'reactive'
  | 'signal'
  | 'template'
  | 'trust-bypass'
  | 'sink';

export interface TraceStep {
  kind: TraceStepKind;
  location: SourceLocation;
  /** Symbol involved at this step, when one exists. */
  symbol?: string;
  description: string;
}

export type SourceKind =
  | 'url'
  | 'message'
  | 'window-name'
  | 'referrer'
  | 'user-input'
  | 'storage'
  | 'http-response'
  | 'cookie'
  /** Host / X-Forwarded-* request headers read by server-side (SSR) code. */
  | 'request-header';

export interface TaintSource {
  kind: SourceKind;
  description: string;
  /** How confidently the value is attacker-influenced. */
  trust: Confidence;
  location: SourceLocation;
  node: ts.Node;
}

export interface TaintFlow {
  source: TaintSource;
  /** Ordered source → sink. Contains only steps that were actually observed. */
  steps: TraceStep[];
  confidence: Confidence;
  /** Imprecise propagation steps taken (each lowers confidence). */
  approximations: string[];
}

export interface OriginNote {
  reason: string;
  location: SourceLocation;
}

/** Security context of a sink; sanitizers are only honoured for matching contexts. */
export type SinkContext = 'html' | 'url' | 'resource-url' | 'script' | 'code' | 'generic';

export interface TaintResult {
  flows: TaintFlow[];
  /** Origins the engine could not resolve (e.g. parameters with no visible callers). */
  unresolved: OriginNote[];
  /** Origins that passed a recognized sanitizer for the requested context. */
  sanitized: OriginNote[];
  /** True when every origin is a compile-time constant (nothing dynamic reaches the sink). */
  constant: boolean;
  /** Constant string values observed among origins. */
  constants: string[];
  /** Identifier / property names traversed (used as naming evidence). */
  names: string[];
  /** True when an analysis limit stopped exploration. */
  truncated: boolean;
}

export interface TaintAnalyzer {
  trace(expression: ts.Expression, options?: { context?: SinkContext }): TaintResult;
  /** If the expression itself is a modeled untrusted source, describe it. */
  sourceOf(expression: ts.Expression): TaintSource | undefined;
}

export interface TypeOrigin {
  /** npm package (`@angular/core`), `dom`, `lib`, or a project file path. */
  module: string;
  /** Type or symbol name, e.g. `DomSanitizer`, `Window`, `eval`. */
  name: string;
  /** How the origin was established; `declaration` = from import specifiers when types were unavailable. */
  resolvedBy: 'type-checker' | 'declaration';
}

export interface CalleeInfo {
  /** Function or method name. */
  name: string;
  /** Origin of the function itself (global function / imported function). */
  origin?: TypeOrigin;
  /** For method calls, origin of the receiver type. */
  receiver?: TypeOrigin;
  /** User-code declaration when the callee is defined in the project. */
  declaration?: ts.SignatureDeclaration;
}

export interface SymbolResolver {
  typeOrigin(expression: ts.Expression): TypeOrigin | undefined;
  callee(call: ts.CallExpression | ts.NewExpression): CalleeInfo | undefined;
  /** Evaluates compile-time constant strings (literals, const variables, enums, constant templates). */
  constantString(expression: ts.Expression): string | undefined;
  /** Resolves aliases and returns the first declaration of the expression's symbol. */
  declarationOf(expression: ts.Expression): ts.Declaration | undefined;
  /** Declared property names of the expression's type (type-aware). */
  propertyNames(expression: ts.Expression): string[];
}

export interface Guard {
  condition: ts.Expression;
  /** `true` when the guarded node runs only if `condition` is truthy. */
  whenTrue: boolean;
  kind: 'if' | 'early-exit' | 'conditional' | 'logical';
}

export interface FlowHelpers {
  /** Conditions that must hold for `node` to execute, innermost first, within the enclosing function. */
  guards(node: ts.Node): Guard[];
  enclosingFunction(node: ts.Node): ts.SignatureDeclaration | undefined;
  /** Function body for a callback / handler expression (resolves identifiers and `this.method`). */
  resolveFunction(expression: ts.Expression): ts.SignatureDeclaration | undefined;
}

export interface TemplateAttribute {
  name: string;
  /** Static value, or the expression source for bindings. */
  value: string;
  bound: boolean;
  location: SourceLocation;
}

export interface TemplateElement {
  name: string;
  attributes: TemplateAttribute[];
  location: SourceLocation;
}

export interface ComponentTemplate {
  /** Component class name. */
  component: string;
  classNode: ts.ClassDeclaration;
  /** File that contains the template (component file for inline templates). */
  file: string;
  inline: boolean;
  elements: TemplateElement[];
}

export interface CodeIndex {
  readonly calls: readonly ts.CallExpression[];
  readonly newExpressions: readonly ts.NewExpression[];
  /** `a.b = v`, `a[b] = v`, `x = v` and compound forms. */
  readonly assignments: readonly ts.BinaryExpression[];
  readonly classes: readonly ts.ClassDeclaration[];
  readonly stringLiterals: readonly (ts.StringLiteral | ts.NoSubstitutionTemplateLiteral)[];
  /** Call sites of a project function/method declaration. */
  callsTo(declaration: ts.SignatureDeclaration): readonly (ts.CallExpression | ts.NewExpression)[];
}

export interface ProjectInfo {
  name: string;
  /** Absolute project root. */
  root: string;
  /** Absolute workspace root. */
  workspaceRoot: string;
  angularVersion?: string;
  /** Absolute path of the configured index.html, when known. */
  indexHtml?: string;
  /** Raw parsed angular.json project entry, when available. */
  angularProject?: Readonly<Record<string, unknown>>;
}

export interface AnalysisDiagnostic {
  code: string;
  level: 'error' | 'warning' | 'info';
  message: string;
  file?: string;
}

export interface AnalysisContext {
  readonly apiVersion: number;
  readonly ts: typeof ts;
  readonly program: ts.Program;
  readonly checker: ts.TypeChecker;
  readonly project: ProjectInfo;
  /** Project source files in scope (exclusions applied, declaration files removed). */
  readonly sourceFiles: readonly ts.SourceFile[];
  readonly templates: readonly ComponentTemplate[];
  readonly index: CodeIndex;
  readonly taint: TaintAnalyzer;
  readonly symbols: SymbolResolver;
  readonly flow: FlowHelpers;
  /** Options configured for this rule. */
  readonly options: Readonly<Record<string, unknown>>;
  location(node: ts.Node): SourceLocation;
  /** Reads a non-TypeScript file inside the workspace (read-only). Returns undefined when missing or outside it. */
  readFile(absolutePath: string): string | undefined;
  /** Lists files in the project root matching a glob (relative to project root). */
  findFiles(glob: string): string[];
  /** Reports an analysis limitation or unsupported construct. */
  diagnostic(diagnostic: AnalysisDiagnostic): void;
}

export interface RuleFinding {
  /** Node to locate the finding. Either `node` or `location` is required. */
  node?: ts.Node;
  location?: SourceLocation;
  message: string;
  confidence: Confidence;
  /** Overrides the rule's default severity for this finding. */
  severity?: Severity;
  evidenceKind: EvidenceKind;
  /** Source-to-sink path, source first. Must contain only observed steps. */
  trace?: TraceStep[];
  /** Short human-readable facts supporting the finding. */
  evidence?: string[];
  /** Hide the source snippet in reports (used when the line may contain a secret). */
  redactSnippet?: boolean;
}

export interface SecurityRule {
  meta: RuleMetadata;
  analyze(context: AnalysisContext): RuleFinding[] | Promise<RuleFinding[]>;
}

export interface NgBastionPlugin {
  /** Plugin API version the plugin was built against. Must equal PLUGIN_API_VERSION. */
  apiVersion: number;
  name: string;
  rules: SecurityRule[];
}

/** Identity helpers that give authors type checking. */
export const defineRule = (rule: SecurityRule): SecurityRule => rule;
export const definePlugin = (plugin: NgBastionPlugin): NgBastionPlugin => plugin;
