import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import picomatch from 'picomatch';
import ts from 'typescript';
import {
  PLUGIN_API_VERSION,
  confidenceRank,
  severityRank,
  type AnalysisContext,
  type AnalysisDiagnostic,
  type Confidence,
  type EvidenceKind,
  type RuleMetadata,
  type SecurityRule,
  type Severity,
  type SourceLocation,
  type TraceStepKind,
} from '@ngbastion/plugin-api';
import type { ResolvedConfig, RuleLevel } from '@ngbastion/config';
import { fingerprintBase, hashIdentity, operationAnchor } from './fingerprint.js';
import { Index } from './code-index.js';
import { Flow } from './flow.js';
import { createInMemoryProgram, createProjectProgram } from './program.js';
import { Symbols } from './symbols.js';
import { TaintEngine } from './taint/engine.js';
import { extractTemplates } from './templates.js';
import { locationOf } from './util.js';
import {
  SUPPORTED_ANGULAR_MAJORS,
  discoverWorkspace,
  listFiles,
  type ProjectTarget,
  type Workspace,
} from './workspace.js';

// Read at runtime so `changeset version` is the single source of truth ('../package.json' works from src/ and dist/).
export const ENGINE_VERSION: string = (createRequire(import.meta.url)('../package.json') as { version: string }).version;

export interface RelativeLocation {
  file: string;
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
}

export interface FindingTraceStep extends RelativeLocation {
  kind: TraceStepKind;
  symbol?: string;
  description: string;
}

export interface Suppression {
  kind: 'inline' | 'exception';
  justification: string;
  source: string;
  expires?: string;
}

export interface Finding {
  /** Stable across unrelated edits (not tied to line numbers). */
  fingerprint: string;
  fingerprintV2?: string;
  ruleId: string;
  ruleName: string;
  category: string;
  severity: Severity;
  confidence: Confidence;
  evidenceKind: EvidenceKind;
  level: Exclude<RuleLevel, 'off'>;
  message: string;
  location: RelativeLocation;
  snippet?: string;
  trace?: FindingTraceStep[];
  evidence: string[];
  project: string;
  suppression?: Suppression;
}

export interface ScanDiagnostic extends AnalysisDiagnostic {
  project?: string;
}

export interface EnabledRule {
  meta: RuleMetadata;
  level: Exclude<RuleLevel, 'off'>;
  severity: Severity;
}

export interface ProjectSummary {
  name: string;
  root: string;
  kind: ProjectTarget['kind'];
  files: number;
  templates: number;
}

export interface ScanResult {
  tool: { name: 'NgBastion'; version: string; pluginApiVersion: number };
  /** Unique rule IDs completed in at least one project. Older results may omit coverage. */
  ruleCoverage?: { available: number; evaluated: string[] };
  comparisonCoverage?: { files: string[]; hidden: string[]; projectSettings?: string[] };
  /** Only simple expressions already loaded by the TypeScript program, indexed by exact trace region. */
  traceContext?: ReadonlyMap<string, string>;
  workspaceRoot: string;
  startedAt: string;
  durationMs: number;
  angularVersion?: string;
  projects: ProjectSummary[];
  rules: EnabledRule[];
  findings: Finding[];
  suppressed: Finding[];
  diagnostics: ScanDiagnostic[];
  stats: { filesAnalyzed: number; templatesAnalyzed: number; traces: number; truncatedTraces: number; hiddenBelowConfidence: number };
  gate: { failOn: Severity | 'none'; minConfidence: Confidence; failed: boolean; failingFindings: number };
}

export interface ScanOptions {
  cwd: string;
  config: ResolvedConfig;
  rules: SecurityRule[];
  /** Analyze these in-memory files (paths relative to `cwd`) instead of the disk workspace. */
  files?: Record<string, string>;
  /** Rule IDs that come from plugins (default level `error` when not configured). */
  pluginRuleIds?: ReadonlySet<string>;
  now?: Date;
  toolVersion?: string;
  captureTraceContext?: boolean;
}

const SUPPRESS_RE = /ngbastion-ignore(-next-line)?\s+([A-Z][A-Z0-9_-]*\d+(?:\s*,\s*[A-Z][A-Z0-9_-]*\d+)*)(?:\s+--\s*(.*?))?\s*(?:\*\/|-->)?\s*$/;

export async function scan(options: ScanOptions): Promise<ScanResult> {
  const started = Date.now();
  const now = options.now ?? new Date();
  const { config } = options;
  const root = path.resolve(options.cwd);
  const memory = options.files
    ? new Map(Object.entries(options.files).map(([k, v]) => [path.resolve(root, k), v]))
    : undefined;
  const diagnostics: ScanDiagnostic[] = config.diagnostics.map((d) => ({ code: d.code, level: d.level, message: d.message, ...(d.file ? { file: d.file } : {}) }));

  const observed = new Set<string>();
  const readFile = (file: string): string | undefined => {
    const abs = path.resolve(file);
    if (memory) {
      if (memory.has(abs)) observed.add(abs);
      return memory.get(abs);
    }
    if (!abs.startsWith(root + path.sep) && abs !== root) return undefined;
    try {
      if (!existsSync(abs)) return undefined;
      const content = readFileSync(abs, 'utf8');
      observed.add(abs);
      return content;
    } catch {
      return undefined;
    }
  };

  // ---- workspace
  let workspace: Workspace;
  if (memory) {
    const indexHtml = ['src/index.html', 'index.html'].map((f) => path.resolve(root, f)).find((f) => memory.has(f));
    workspace = { root, projects: [{ name: 'virtual', root, sourceRoot: root, kind: 'directory', ...(indexHtml ? { indexHtml } : {}) }], diagnostics: [] };
    const angularJson = memory.get(path.resolve(root, 'angular.json'));
    if (angularJson) {
      workspace.angularJson = path.resolve(root, 'angular.json');
      try {
        const first = Object.values((JSON.parse(angularJson) as { projects?: Record<string, Record<string, unknown>> }).projects ?? {})[0];
        if (first) workspace.projects[0]!.angularProject = first;
      } catch { /* invalid angular.json is reported by NGB019 when relevant */ }
    }
  } else {
    workspace = discoverWorkspace(root);
  }
  diagnostics.push(...workspace.diagnostics);

  if (workspace.angularVersion) {
    const major = Number.parseInt(workspace.angularVersion, 10);
    if (!SUPPORTED_ANGULAR_MAJORS.includes(major)) {
      diagnostics.push({ code: 'angular-version-unsupported', level: 'warning', message: `Angular ${workspace.angularVersion} is outside the tested range (${SUPPORTED_ANGULAR_MAJORS.join(', ')}); results may be incomplete` });
    }
  } else if (!memory && workspace.angularJson) {
    diagnostics.push({ code: 'angular-version-unknown', level: 'info', message: '@angular/core version could not be determined (dependencies not installed?)' });
  }

  let projects = workspace.projects;
  if (config.projects.length) {
    for (const name of config.projects) {
      if (!projects.some((p) => p.name === name)) {
        diagnostics.push({ code: 'project-not-found', level: 'error', message: `project '${name}' not found (available: ${projects.map((p) => p.name).join(', ') || 'none'})` });
      }
    }
    projects = projects.filter((p) => config.projects.includes(p.name));
  }

  // ---- rules
  const enabled: { rule: SecurityRule; level: Exclude<RuleLevel, 'off'>; severity?: Severity; options: Record<string, unknown> }[] = [];
  const known = new Set(options.rules.map((r) => r.meta.id));
  for (const id of Object.keys(config.rules)) {
    if (!known.has(id)) diagnostics.push({ code: 'unknown-rule', level: 'warning', message: `configured rule ${id} is not provided by NgBastion or any loaded plugin` });
  }
  for (const rule of options.rules) {
    const setting = config.rules[rule.meta.id];
    const level = setting?.level ?? (options.pluginRuleIds?.has(rule.meta.id) ? 'error' : 'off');
    if (level === 'off') continue;
    enabled.push({ rule, level, ...(setting?.severity ? { severity: setting.severity } : {}), options: setting?.options ?? {} });
  }

  const isExcluded = picomatch(config.exclude.length ? config.exclude : ['\0'], { dot: true });
  const isIncluded = config.include.length ? picomatch(config.include, { dot: true }) : () => true;
  const rel = (f: string) => path.relative(root, f).split(path.sep).join('/');
  /** Directory listings, shared by all rules and projects of this scan. */
  const listings = new Map<string, string[]>();

  const all: Finding[] = [];
  const evaluated = new Set<string>();
  const redactedRanges = new Map<string, number>();
  const summaries: ProjectSummary[] = [];
  let traces = 0;
  let truncatedTraces = 0;
  let timedOut = false;
  const unsupported = new Map<string, number>();
  const unresolvedModules = new Set<string>();
  let templatesAnalyzed = 0;
  const analyzedFiles = new Set<string>();
  const projectSettings: string[] = [];
  const traceFiles = new Map<string, ts.SourceFile>();
  const sensitiveFiles = new Set<string>();
  const linesByFile = new Map<string, string[]>();

  for (const target of projects) {
    const projectDiagnostics: WorkspaceDiagnosticSink = [];
    const program = memory
      ? createInMemoryProgram(Object.fromEntries([...memory].filter(([k]) => k.endsWith('.ts'))), root)
      : createProjectProgram(target, projectDiagnostics);
    diagnostics.push(...projectDiagnostics.map((d) => ({ ...d, project: target.name })));
    const settings = JSON.stringify([target.name, target.angularProject, program.getCompilerOptions()], (_key, value) =>
      typeof value === 'string' && path.isAbsolute(value) ? rel(value) : value);
    projectSettings.push(hashIdentity(settings));
    const checker = program.getTypeChecker();
    const inProject = (f: string) => {
      const abs = path.resolve(f);
      if (abs.includes(`${path.sep}node_modules${path.sep}`) || !abs.startsWith(root)) return false;
      const r = rel(abs);
      return isIncluded(r) && !isExcluded(r);
    };
    const sourceFiles = program.getSourceFiles().filter((sf) => !sf.isDeclarationFile && inProject(sf.fileName));
    for (const sf of sourceFiles) {
      analyzedFiles.add(sf.fileName);
      if (options.captureTraceContext) traceFiles.set(rel(sf.fileName), sf);
      const parseDiags = (sf as unknown as { parseDiagnostics?: ts.Diagnostic[] }).parseDiagnostics ?? [];
      if (parseDiags.length) {
        diagnostics.push({ code: 'parse-error', level: 'warning', project: target.name, file: rel(sf.fileName), message: `${parseDiags.length} syntax error(s) (first: ${ts.flattenDiagnosticMessageText(parseDiags[0]!.messageText, ' ')}); analysis of this file may be incomplete` });
      }
      for (const stmt of sf.statements) {
        if (ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier) && !checker.getSymbolAtLocation(stmt.moduleSpecifier)) {
          const spec = stmt.moduleSpecifier.text;
          if (!/\.(css|scss|html|json)$/.test(spec)) unresolvedModules.add(spec);
        }
      }
    }

    const symbols = new Symbols(checker, inProject);
    const index = new Index(sourceFiles, symbols);
    const flow = new Flow(symbols);
    const report = (d: AnalysisDiagnostic) => diagnostics.push({ ...d, project: target.name, ...(d.file ? { file: rel(d.file) } : {}) });
    const { templates, userInput } = extractTemplates(index.classes, symbols, readFile, report);
    templatesAnalyzed += templates.length;
    const engine = new TaintEngine(symbols, index, flow, config.limits, userInput, config.trustedSanitizers, Date.now());
    summaries.push({ name: target.name, root: rel(target.root) || '.', kind: target.kind, files: sourceFiles.length, templates: templates.length });

    const project = {
      name: target.name,
      root: target.root,
      workspaceRoot: root,
      ...(workspace.angularVersion ? { angularVersion: workspace.angularVersion } : {}),
      ...(target.indexHtml ? { indexHtml: target.indexHtml } : {}),
      ...(target.angularProject ? { angularProject: target.angularProject } : {}),
    };
    const filesUnder = (dir: string): string[] => {
      if (memory) return [...memory.keys()];
      let list = listings.get(dir);
      if (!list) listings.set(dir, (list = listFiles(dir, () => true)));
      return list;
    };
    const globIn = (dir: string, glob: string): string[] => {
      const match = picomatch(glob, { dot: true });
      return filesUnder(dir).filter((f) => (f.startsWith(dir + path.sep) || dir === root) && match(path.relative(dir, f).split(path.sep).join('/')) && !isExcluded(rel(f)));
    };
    const findFiles = (glob: string): string[] => globIn(target.root, glob);
    const findWorkspaceFiles = (glob: string): string[] => globIn(root, glob);

    for (const { rule, level, severity, options: ruleOptions } of enabled) {
      const context: AnalysisContext = {
        apiVersion: PLUGIN_API_VERSION,
        ts: ts as unknown as AnalysisContext['ts'],
        program,
        checker,
        project,
        sourceFiles,
        templates,
        index,
        taint: engine,
        symbols,
        flow,
        options: ruleOptions,
        location: (node) => locationOf(node),
        readFile,
        findFiles,
        findWorkspaceFiles,
        diagnostic: report,
      };
      let results;
      try {
        results = await rule.analyze(context);
        evaluated.add(rule.meta.id);
      } catch (e) {
        diagnostics.push({ code: 'rule-failed', level: 'error', project: target.name, message: `${rule.meta.id} failed: ${(e as Error).stack ?? String(e)}` });
        continue;
      }
      for (const r of results) {
        const loc: SourceLocation | undefined = r.location ?? (r.node ? locationOf(r.node) : undefined);
        if (!loc) continue;
        const fileRel = rel(loc.file);
        if (isExcluded(fileRel) || !isIncluded(fileRel)) continue;
        let lines = linesByFile.get(fileRel);
        if (!lines) {
          lines = readSourceText(loc.file, program, readFile)?.split(/\r?\n/);
          if (lines) linesByFile.set(fileRel, lines);
        }
        const line = lines?.[loc.line - 1];
        if (r.redactSnippet) {
          sensitiveFiles.add(fileRel);
          const start = JSON.stringify([fileRel, loc.line]);
          redactedRanges.set(start, Math.max(loc.endLine, redactedRanges.get(start) ?? loc.line));
        }
        all.push({
          fingerprint: '',
          fingerprintV2: fingerprintBase(rule.meta.id, fileRel,
            operationAnchor(r.node?.getText() ?? line ?? '', r.node),
            (r.trace ?? []).filter(step => step.kind === 'source' || step.kind === 'sink')
              .map(step => JSON.stringify([step.kind, rel(step.location.file), step.symbol ?? step.description]))),
          ruleId: rule.meta.id,
          ruleName: rule.meta.name,
          category: rule.meta.category,
          severity: severity ?? r.severity ?? rule.meta.defaultSeverity,
          confidence: r.confidence,
          evidenceKind: r.evidenceKind,
          level,
          message: r.message,
          location: { file: fileRel, line: loc.line, column: loc.column, endLine: loc.endLine, endColumn: loc.endColumn },
          ...(line !== undefined && !r.redactSnippet ? { snippet: line.trim().slice(0, 240) } : {}),
          ...(r.trace?.length ? { trace: r.trace.map((s) => ({ kind: s.kind, file: rel(s.location.file), line: s.location.line, column: s.location.column, endLine: s.location.endLine, endColumn: s.location.endColumn, description: s.description, ...(s.symbol ? { symbol: s.symbol } : {}) })) } : {}),
          evidence: r.evidence ?? [],
          project: target.name,
          ...(line !== undefined ? { _line: line } : {}),
        } as Finding);
      }
    }
    traces += engine.stats.traces;
    truncatedTraces += engine.stats.truncated;
    timedOut ||= engine.stats.timedOut;
    for (const [k, v] of engine.stats.unsupported) unsupported.set(k, (unsupported.get(k) ?? 0) + v);
  }

  // ---- diagnostics about analysis completeness
  if (truncatedTraces) {
    diagnostics.push({ code: 'analysis-incomplete', level: 'warning', message: `${truncatedTraces} of ${traces} data-flow traces stopped at an analysis limit (depth, visited nodes, file hops, call sites or paths); findings for those sinks may be incomplete. Raise 'limits' in the config to explore further.` });
  }
  if (timedOut) {
    diagnostics.push({ code: 'analysis-timeout', level: 'warning', message: `analysis exceeded limits.maxTimeMs (${config.limits.maxTimeMs} ms); remaining traces were cut short` });
  }
  if (unsupported.size) {
    const top = [...unsupported].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([k, v]) => `${k} (${v}×)`).join(', ');
    diagnostics.push({ code: 'unsupported-construct', level: 'info', message: `data flow was not followed through unsupported constructs: ${top}` });
  }
  if (unresolvedModules.size) {
    const sample = [...unresolvedModules].slice(0, 5).join(', ');
    diagnostics.push({ code: 'unresolved-imports', level: 'info', message: `${unresolvedModules.size} imported module(s) could not be resolved (e.g. ${sample}). Install dependencies for full type information; framework APIs are identified from import declarations meanwhile.` });
  }

  // ---- normalize: dedupe, fingerprint, suppressions, exceptions, confidence filter
  const seen = new Set<string>();
  const semanticOccurrences = new Map<string, number>();
  const hiddenIds: string[] = [];
  const occurrence = new Map<string, number>();
  const findings: Finding[] = [];
  const suppressed: Finding[] = [];
  let hidden = 0;
  const expiredReported = new Set<string>();
  const exceptionMatchers = config.exceptions.map((e) => ({ e, match: picomatch(e.files, { dot: true }) }));
  const today = now.toISOString().slice(0, 10);

  all.sort((a, b) => a.location.file.localeCompare(b.location.file) || a.location.line - b.location.line || a.location.column - b.location.column || a.ruleId.localeCompare(b.ruleId));
  const redactThrough = new Map<string, number>();
  for (const f of all) {
    // Findings are ordered by location. Honor all sensitive ranges before confidence filtering.
    const { file, line } = f.location;
    const end = redactedRanges.get(JSON.stringify([file, line]));
    if (end !== undefined) redactThrough.set(file, Math.max(end, redactThrough.get(file) ?? 0));
    if (line <= (redactThrough.get(file) ?? 0)) delete f.snippet;
    const key = `${f.ruleId}:${f.location.file}:${f.location.line}:${f.location.column}:${f.message}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const raw = f as Finding & { _line?: string };
    const norm = (raw._line ?? '').replace(/\s+/g, ' ').trim();
    delete raw._line;
    const base = `${f.ruleId}\0${f.location.file}\0${norm}`;
    const n = (occurrence.get(base) ?? 0) + 1;
    occurrence.set(base, n);
    f.fingerprint = createHash('sha256').update(`${base}\0${n}`).digest('hex').slice(0, 20);

    const semantic = f.fingerprintV2!;
    const ordinal = (semanticOccurrences.get(semantic) ?? 0) + 1;
    semanticOccurrences.set(semantic, ordinal);
    f.fingerprintV2 = hashIdentity([semantic, ordinal]);

    if (confidenceRank(f.confidence) < confidenceRank(config.minConfidence)) {
      hiddenIds.push(f.fingerprintV2);
      hidden++;
      continue;
    }

    const inline = inlineSuppression(f, linesByFile.get(f.location.file));
    if (inline) {
      if (!config.policy.allowInlineSuppressions) {
        diagnostics.push({ code: 'suppression-disallowed', level: 'warning', file: f.location.file, message: `inline suppression of ${f.ruleId} at line ${f.location.line} ignored: policy disallows inline suppressions` });
      } else if (!inline.justification) {
        diagnostics.push({ code: 'suppression-invalid', level: 'warning', file: f.location.file, message: `inline suppression of ${f.ruleId} at line ${f.location.line} ignored: add a justification after '--'` });
      } else {
        suppressed.push({ ...f, suppression: { kind: 'inline', justification: inline.justification, source: `${f.location.file}:${inline.line}` } });
        continue;
      }
    }

    const exc = exceptionMatchers.find(({ e, match }) =>
      e.rule === f.ruleId && match(f.location.file) && (!e.line || e.line === f.location.line) && (!e.fingerprint || (e.fingerprint === f.fingerprint || e.fingerprint === f.fingerprintV2)));
    if (exc) {
      if (exc.e.expires && exc.e.expires < today) {
        const k = `${exc.e.source}:${exc.e.rule}:${exc.e.files.join(',')}`;
        if (!expiredReported.has(k)) {
          expiredReported.add(k);
          diagnostics.push({ code: 'exception-expired', level: 'warning', file: exc.e.source, message: `exception for ${exc.e.rule} (${exc.e.files.join(', ')}) expired on ${exc.e.expires}; matching findings are reported again` });
        }
      } else {
        suppressed.push({ ...f, suppression: { kind: 'exception', justification: exc.e.justification, source: exc.e.source, ...(exc.e.expires ? { expires: exc.e.expires } : {}) } });
        continue;
      }
    }
    findings.push(f);
  }

  findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || confidenceRank(b.confidence) - confidenceRank(a.confidence)
    || a.location.file.localeCompare(b.location.file) || a.location.line - b.location.line);

  // Reports never contain absolute paths.
  const relPath = (f: string) => (path.isAbsolute(f) ? rel(f) : f);
  for (const d of diagnostics) if (d.file) d.file = relPath(d.file);
  for (const f of suppressed) if (f.suppression) f.suppression.source = relPath(f.suppression.source);

  const failing = config.failOn === 'none'
    ? []
    : findings.filter((f) => f.level === 'error' && severityRank(f.severity) >= severityRank(config.failOn as Severity));

  const traceContext = new Map<string, string>();
  if (options.captureTraceContext) {
    for (const finding of [...findings, ...suppressed]) {
      for (const step of finding.trace ?? []) {
        const source = traceFiles.get(step.file);
        if (!source || sensitiveFiles.has(step.file) || step.line !== step.endLine) continue;
        const start = source.getLineStarts()[step.line - 1];
        if (start === undefined || step.endColumn - step.column > 240) continue;
        const expression = source.text.slice(start + step.column - 1, start + step.endColumn - 1);
        // Additional trace excerpts contain only identifiers and simple member/call syntax.
        // Literals, comments, template text and unrelated neighboring source stay out of the report.
        if (/^[\p{L}_$][\p{L}\p{N}_$?.()[\] \t]*$/u.test(expression)) traceContext.set(traceLocationKey(step), expression);
      }
    }
  }

  return {
    tool: { name: 'NgBastion', version: options.toolVersion ?? ENGINE_VERSION, pluginApiVersion: PLUGIN_API_VERSION },
    workspaceRoot: root,
    ...(options.captureTraceContext ? { traceContext } : {}),
    comparisonCoverage: { projectSettings: projectSettings.sort(), files: [...new Set([...observed, ...analyzedFiles].map(rel))].sort(), hidden: hiddenIds },
    ruleCoverage: { available: known.size, evaluated: [...evaluated] },
    startedAt: new Date(started).toISOString(),
    durationMs: Date.now() - started,
    ...(workspace.angularVersion ? { angularVersion: workspace.angularVersion } : {}),
    projects: summaries,
    rules: enabled.map(({ rule, level, severity }) => ({ meta: rule.meta, level, severity: severity ?? rule.meta.defaultSeverity })),
    findings,
    suppressed,
    diagnostics,
    stats: { filesAnalyzed: analyzedFiles.size, templatesAnalyzed, traces, truncatedTraces, hiddenBelowConfidence: hidden },
    gate: { failOn: config.failOn, minConfidence: config.minConfidence, failed: failing.length > 0, failingFindings: failing.length },
  };
}

export function traceLocationKey(step: RelativeLocation) {
  return JSON.stringify([step.file, step.line, step.column, step.endLine, step.endColumn]);
}

type WorkspaceDiagnosticSink = { code: string; level: 'error' | 'warning' | 'info'; message: string; file?: string }[];

function readSourceText(file: string, program: ts.Program, readFile: (f: string) => string | undefined): string | undefined {
  return program.getSourceFile(file)?.text ?? readFile(file);
}

function inlineSuppression(f: Finding, lines: string[] | undefined): { justification?: string; line: number } | undefined {
  if (!lines) return undefined;
  const check = (lineNo: number, nextLine: boolean) => {
    const line = lines[lineNo - 1];
    const m = line && SUPPRESS_RE.exec(line);
    if (!m || Boolean(m[1]) !== nextLine) return undefined;
    const ids = m[2]!.split(',').map((s) => s.trim());
    if (!ids.includes(f.ruleId)) return undefined;
    const justification = m[3]?.trim();
    return { line: lineNo, ...(justification ? { justification } : {}) };
  };
  return check(f.location.line, false) ?? check(f.location.line - 1, true);
}
