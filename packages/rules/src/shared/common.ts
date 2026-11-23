import type * as ts from 'typescript';
import {
  lowerConfidence,
  type AnalysisContext,
  type CalleeInfo,
  type Confidence,
  type RuleFinding,
  type Severity,
  type SinkContext,
  type TaintFlow,
  type TaintResult,
  type TraceStep,
  type TypeOrigin,
} from '@ngbastion/plugin-api';

export const ANGULAR_SANITIZER_MODULES = ['@angular/platform-browser', '@angular/core'];

export function strip(ctx: Pick<AnalysisContext, 'ts'>, e: ts.Expression): ts.Expression {
  const t = ctx.ts;
  while (t.isParenthesizedExpression(e) || t.isAsExpression(e) || t.isNonNullExpression(e) || t.isTypeAssertionExpression(e) || t.isSatisfiesExpression(e)) e = e.expression;
  return e;
}

export function memberName(ctx: Pick<AnalysisContext, 'ts'>, e: ts.Expression): string | undefined {
  const t = ctx.ts;
  const x = strip(ctx, e);
  if (t.isPropertyAccessExpression(x)) return x.name.text;
  if (t.isElementAccessExpression(x) && t.isStringLiteralLike(x.argumentExpression)) return x.argumentExpression.text;
  return undefined;
}

export function receiverOf(ctx: AnalysisContext, e: ts.Expression): ts.Expression | undefined {
  const t = ctx.ts;
  const x = strip(ctx, e);
  return t.isPropertyAccessExpression(x) || t.isElementAccessExpression(x) ? x.expression : undefined;
}

export function is(origin: TypeOrigin | undefined, modules: string | readonly string[], ...names: string[]): boolean {
  if (!origin) return false;
  const mods = typeof modules === 'string' ? [modules] : modules;
  // The TypeChecker reports the package (`@angular/common`), imports name entry points (`@angular/common/http`).
  const matches = (m: string) => origin.module === m || (origin.resolvedBy === 'type-checker' && m.startsWith(`${origin.module}/`));
  return mods.some(matches) && (names.length === 0 || names.includes(origin.name));
}

const ELEMENT_RE = /^(HTML\w*Element|Element|SVG\w*Element|ShadowRoot|DocumentFragment)$/;

/**
 * Whether `expr` is a DOM element. `certain` is false when only the name
 * (`nativeElement` on an untyped ElementRef) suggests it.
 */
export function domElement(ctx: AnalysisContext, expr: ts.Expression): { certain: boolean } | undefined {
  const o = ctx.symbols.typeOrigin(expr);
  if (o && o.module === 'dom' && ELEMENT_RE.test(o.name)) return { certain: true };
  if (o && o.module === 'dom') return undefined;
  if (!o || o.name === 'any') {
    const text = strip(ctx, expr).getText();
    if (/\bnativeElement$/.test(text)) return { certain: false };
  }
  return undefined;
}

/** Global function (eval, setTimeout, …) from the TypeScript lib, not a project or package symbol. */
export function isGlobalCall(info: CalleeInfo | undefined, ...names: string[]): boolean {
  if (!info || !names.includes(info.name)) return false;
  if (info.declaration) return false;
  return !info.origin || info.origin.module === 'lib' || info.origin.module === 'dom';
}

/** Method call on a receiver of a known type; `certain` false when matched only by name. */
export function methodCall(
  ctx: AnalysisContext,
  call: ts.CallExpression,
  modules: string | readonly string[],
  types: string[],
  methods: string[],
): { certain: boolean; info: CalleeInfo } | undefined {
  const info = ctx.symbols.callee(call);
  if (!info || !methods.includes(info.name) || info.declaration) return undefined;
  if (is(info.receiver, modules, ...types)) return { certain: true, info };
  return undefined;
}

export interface SinkReport {
  ctx: AnalysisContext;
  sink: ts.Node;
  value: ts.Expression;
  context: SinkContext;
  /** e.g. `element.innerHTML assignment`. */
  sinkDescription: string;
  message: (flow: TaintFlow) => string;
  /** Message when nothing could be traced but the value is dynamic. Omit to stay silent. */
  unresolvedMessage?: string;
  /** Lower confidence when the sink itself was matched by name only. */
  sinkCertain?: boolean;
  severity?: (flow: TaintFlow | undefined) => Severity | undefined;
  extraEvidence?: string[];
}

export function sinkStep(ctx: AnalysisContext, node: ts.Node, description: string): TraceStep {
  return { kind: 'sink', location: ctx.location(node), description };
}

export function flowEvidence(flow: TaintFlow): string[] {
  return [
    `source: ${flow.source.description} (${flow.source.kind}, trust ${flow.source.trust})`,
    ...flow.approximations.map((a) => `approximation: ${a}`),
  ];
}

/** Standard source-to-sink reporting used by the taint-based rules. */
export function reportSink(r: SinkReport): RuleFinding[] {
  const result: TaintResult = r.ctx.taint.trace(r.value, { context: r.context });
  const penalty = r.sinkCertain === false ? 1 : 0;
  const extra = [...(r.extraEvidence ?? []), ...(r.sinkCertain === false ? ['sink matched by name; receiver type could not be resolved'] : [])];
  if (result.flows.length) {
    const flow = result.flows[0]!;
    const others = result.flows.slice(1).map((f) => `additional source: ${f.source.description}`);
    const severity = r.severity?.(flow);
    return [{
      node: r.sink,
      message: r.message(flow),
      confidence: lowerConfidence(flow.confidence, penalty),
      evidenceKind: 'dataflow',
      trace: [...flow.steps, sinkStep(r.ctx, r.sink, r.sinkDescription)],
      evidence: [...flowEvidence(flow), ...others, ...extra, ...(result.truncated ? ['trace hit an analysis limit; other paths may exist'] : [])],
      ...(severity ? { severity } : {}),
    }];
  }
  if (r.unresolvedMessage && !result.constant && !result.sanitized.length && result.unresolved.length) {
    const severity = r.severity?.(undefined);
    return [{
      node: r.sink,
      message: r.unresolvedMessage,
      confidence: 'low' as Confidence,
      evidenceKind: 'heuristic',
      evidence: [...result.unresolved.slice(0, 3).map((u) => `origin not resolved: ${u.reason}`), ...extra],
      ...(severity ? { severity } : {}),
    }];
  }
  return [];
}

/** Leading constant text of a string expression (template head, leftmost literal of `+`, const). */
export function constantPrefix(ctx: AnalysisContext, expr: ts.Expression): string | undefined {
  const t = ctx.ts;
  const e = strip(ctx, expr);
  const whole = ctx.symbols.constantString(e);
  if (whole !== undefined) return whole;
  if (t.isTemplateExpression(e)) return e.head.text || undefined;
  if (t.isBinaryExpression(e) && e.operatorToken.kind === t.SyntaxKind.PlusToken) return constantPrefix(ctx, e.left);
  if (t.isIdentifier(e)) {
    const d = ctx.symbols.declarationOf(e);
    if (d && t.isVariableDeclaration(d) && d.initializer && t.isVariableDeclarationList(d.parent) && d.parent.flags & t.NodeFlags.Const) {
      return constantPrefix(ctx, d.initializer);
    }
  }
  return undefined;
}

/** `https://host/…` — a fixed origin; dynamic parts can only change path/query. */
export function hasFixedOrigin(prefix: string | undefined): boolean {
  return !!prefix && /^https:\/\/[^/?#\s]+[/?#]/i.test(prefix);
}

/** Finds the property / variable a value is stored in (`this.x = v`, `x = v`, `const x = v`). */
export function storedName(ctx: AnalysisContext, node: ts.Node): string | undefined {
  const t = ctx.ts;
  let p = node.parent;
  while (p && (t.isParenthesizedExpression(p) || t.isAsExpression(p))) p = p.parent;
  if (!p) return undefined;
  if (t.isBinaryExpression(p) && p.right === node) return memberName(ctx, p.left) ?? (t.isIdentifier(p.left) ? p.left.text : undefined);
  if ((t.isVariableDeclaration(p) || t.isPropertyDeclaration(p) || t.isPropertyAssignment(p)) && t.isIdentifier(p.name)) return p.name.text;
  return undefined;
}

/** Template bindings that reference `name` (e.g. `[innerHTML]="name"`). */
export function templateBindingsOf(ctx: AnalysisContext, cls: ts.ClassDeclaration | undefined, name: string): string[] {
  const re = new RegExp(`(^|[^\\w$.])${name.replace(/[$]/g, '\\$')}(\\(\\))?([^\\w$]|$)`);
  return ctx.templates
    .filter((t) => !cls || t.classNode === cls)
    .flatMap((t) => t.elements.flatMap((el) => el.attributes
      .filter((a) => a.bound && re.test(a.value))
      .map((a) => `bound to <${el.name} [${a.name}]> at ${relative(ctx, a.location.file)}:${a.location.line}`)));
}

export function enclosingClass(ctx: AnalysisContext, node: ts.Node): ts.ClassDeclaration | undefined {
  for (let p = node.parent; p; p = p.parent) if (ctx.ts.isClassDeclaration(p)) return p;
  return undefined;
}

export function relative(ctx: AnalysisContext, file: string): string {
  const root = ctx.project.workspaceRoot;
  return file.startsWith(root) ? file.slice(root.length + 1) : file;
}

/** Project TypeScript/JavaScript sources, without JSON modules imported through `resolveJsonModule`. */
export function codeFiles(ctx: AnalysisContext): readonly ts.SourceFile[] {
  return ctx.sourceFiles.filter((sf) => !sf.fileName.endsWith('.json'));
}

/** Identifier bound to `import { name } from 'module'`. */
export function importedFrom(ctx: AnalysisContext, e: ts.Expression, module: string | readonly string[], name: string): boolean {
  const t = ctx.ts;
  if (!t.isIdentifier(e)) return false;
  // The unresolved (alias) symbol: `declarationOf` follows aliases into the package's declarations.
  const d = ctx.checker.getSymbolAtLocation(e)?.declarations?.[0];
  if (!d || !t.isImportSpecifier(d)) return false;
  const spec = d.parent.parent.parent.moduleSpecifier;
  const mods = typeof module === 'string' ? [module] : module;
  return t.isStringLiteral(spec) && mods.includes(spec.text) && (d.propertyName ?? d.name).text === name;
}
