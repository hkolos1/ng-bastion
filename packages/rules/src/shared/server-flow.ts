import type * as ts from 'typescript';
import type { AnalysisContext, RuleFinding, Severity, SinkContext, SourceKind, TaintFlow, TaintResult } from '@ngbastion/plugin-api';
import { flowEvidence, relative, sinkStep } from './common.js';

export interface TaintedValue {
  flow: TaintFlow;
  result: TaintResult;
}

/**
 * First traced flow into `expr` that does not pass through a call matching `sanitizers`
 * (checked against the descriptions of the observed trace steps, e.g. `through unmodeled call basename()`).
 */
export function taintedFlow(
  ctx: AnalysisContext,
  expr: ts.Expression,
  opts: { context?: SinkContext; kinds?: readonly SourceKind[]; sanitizers?: RegExp; skip?: (flow: TaintFlow) => boolean } = {},
): TaintedValue | undefined {
  const result = ctx.taint.trace(expr, { context: opts.context ?? 'generic' });
  const flow = result.flows.find((f) => (!opts.kinds || opts.kinds.includes(f.source.kind))
    && !(opts.sanitizers && f.steps.some((s) => opts.sanitizers!.test(s.description)))
    && !opts.skip?.(f));
  return flow ? { flow, result } : undefined;
}

/** Sources a remote client controls in server code (request query / params / body / cookies / headers). */
export const REQUEST_KINDS: readonly SourceKind[] = ['url', 'user-input', 'cookie', 'request-header', 'message'];

/** Source descriptions of server-side request data (as opposed to browser URLs). */
export const SERVER_SOURCE = /^(server request|request header|request\.)/;

const SW_FILE = /(^|[/\\])(sw|service-?worker|custom-sw|[\w-]+-sw|[\w-]+\.sw)\.(js|mjs|ts)$/i;

/**
 * Custom service-worker sources: project TypeScript files and JavaScript files (parsed syntactically,
 * no types) named like a service worker. The generated `ngsw-worker.js` and build output are ignored.
 */
export function serviceWorkerFiles(ctx: AnalysisContext): ts.SourceFile[] {
  const t = ctx.ts;
  const files = new Map<string, ts.SourceFile>();
  for (const sf of ctx.sourceFiles) if (SW_FILE.test(sf.fileName)) files.set(sf.fileName, sf);
  for (const f of ctx.findFiles('**/*.{js,mjs}')) {
    if (!SW_FILE.test(f) || /(^|\/)(dist|node_modules|\.angular|www|build)\//.test(relative(ctx, f)) || /ngsw-worker|safety-worker/.test(f) || files.has(f)) continue;
    const text = ctx.readFile(f);
    if (text) files.set(f, t.createSourceFile(f, text, t.ScriptTarget.Latest, true, t.ScriptKind.JS));
  }
  return [...files.values()];
}

/** `self.addEventListener('fetch', handler)` / `self.onfetch = handler` handlers (inline functions only). */
export function fetchHandlers(ctx: AnalysisContext, sf: ts.SourceFile): ts.FunctionLikeDeclaration[] {
  const t = ctx.ts;
  const out: ts.FunctionLikeDeclaration[] = [];
  const visit = (n: ts.Node): void => {
    let handler: ts.Node | undefined;
    if (t.isCallExpression(n) && t.isPropertyAccessExpression(n.expression) && n.expression.name.text === 'addEventListener'
      && n.arguments[0] && t.isStringLiteralLike(n.arguments[0]) && n.arguments[0].text === 'fetch') handler = n.arguments[1];
    if (t.isBinaryExpression(n) && t.isPropertyAccessExpression(n.left) && n.left.name.text === 'onfetch') handler = n.right;
    if (handler && (t.isArrowFunction(handler) || t.isFunctionExpression(handler))) out.push(handler);
    t.forEachChild(n, visit);
  };
  visit(sf);
  return out;
}

/** Calls `name(...)` / `x.name(...)` anywhere below `root`. */
export function callsNamed(ctx: AnalysisContext, root: ts.Node, names: readonly string[]): ts.CallExpression[] {
  const t = ctx.ts;
  const out: ts.CallExpression[] = [];
  const visit = (n: ts.Node): void => {
    if (t.isCallExpression(n)) {
      const c = n.expression;
      const name = t.isIdentifier(c) ? c.text : t.isPropertyAccessExpression(c) ? c.name.text : undefined;
      if (name && names.includes(name)) out.push(n);
    }
    t.forEachChild(n, visit);
  };
  visit(root);
  return out;
}

/** Standard data-flow finding for a traced value reaching `sink`. */
export function flowFinding(
  ctx: AnalysisContext,
  sink: ts.Node,
  tv: TaintedValue,
  what: string,
  message: string,
  extra: { severity?: Severity; evidence?: string[] } = {},
): RuleFinding {
  return {
    node: sink,
    message,
    confidence: tv.flow.confidence,
    evidenceKind: 'dataflow',
    trace: [...tv.flow.steps, sinkStep(ctx, sink, what)],
    evidence: [...flowEvidence(tv.flow), ...(extra.evidence ?? []), ...(tv.result.truncated ? ['trace hit an analysis limit; other paths may exist'] : [])],
    ...(extra.severity ? { severity: extra.severity } : {}),
  };
}
