import ts from 'typescript';
import {
  lowerConfidence,
  confidenceRank,
  type OriginNote,
  type SinkContext,
  type TaintAnalyzer,
  type TaintFlow,
  type TaintResult,
  type TaintSource,
  type TraceStep,
  type TraceStepKind,
} from '@ngbastion/plugin-api';
import type { AnalysisLimits } from '@ngbastion/config';
import type { Index } from '../code-index.js';
import type { Flow } from '../flow.js';
import { originIs, type Symbols } from '../symbols.js';
import type { TemplateUserInput } from '../templates.js';
import { locationOf, memberName, memberObject, nameOf, returnExpressions, shortText, skipOuter } from '../util.js';
import { matchMemberSource, matchObservableSource, matchSource, type SourceMatch } from './sources.js';

type Mode = 'value' | 'emitted';

type Binding =
  | { kind: 'expr'; exprs: ts.Expression[]; env: Env; mode: Mode }
  | { kind: 'emitted'; obs: ts.Expression; upto: number | undefined; env: Env };

let envIds = 0;
/** Environment with no parameter bindings. Shared so equivalent visits deduplicate. */
class Env {
  readonly id = ++envIds;
  readonly bindings = new Map<ts.ParameterDeclaration, Binding>();
  constructor(readonly parent?: Env) {}
  lookup(p: ts.ParameterDeclaration): Binding | undefined {
    for (let e: Env | undefined = this as Env; e; e = e.parent) {  
      const b = e.bindings.get(p);
      if (b) return b;
    }
    return undefined;
  }
}

const EMPTY_ENV = new Env();

interface Path {
  step?: TraceStep;
  approx?: string;
  parent?: Path;
  depth: number;
  hops: number;
  file: string;
}

interface TraceState {
  context: SinkContext;
  flows: TaintFlow[];
  flowKeys: Set<string>;
  unresolved: OriginNote[];
  sanitized: OriginNote[];
  constants: string[];
  constantLeaves: number;
  names: Set<string>;
  explored: Set<string>;
  visited: number;
  truncated: boolean;
}

const SIGNAL_MODULES = ['@angular/core', '@angular/core/rxjs-interop'];
const PASSTHROUGH_OPERATORS = new Set([
  'tap', 'filter', 'take', 'takeUntil', 'takeUntilDestroyed', 'takeWhile', 'first', 'last', 'distinctUntilChanged',
  'distinctUntilKeyChanged', 'debounceTime', 'throttleTime', 'auditTime', 'sampleTime', 'delay', 'shareReplay', 'share',
  'retry', 'finalize', 'skip', 'skipWhile', 'timeout', 'observeOn', 'subscribeOn', 'single',
]);
const MAP_OPERATORS = new Set(['map']);
const FLATTEN_OPERATORS = new Set(['switchMap', 'mergeMap', 'concatMap', 'exhaustMap', 'flatMap']);
const COMBINATORS = new Set(['combineLatest', 'forkJoin', 'zip', 'merge', 'concat', 'race']);
const VALUE_ADDING_OPERATORS = new Set(['startWith', 'defaultIfEmpty', 'endWith']);
const STRING_METHODS = new Set([
  'trim', 'trimStart', 'trimEnd', 'toLowerCase', 'toUpperCase', 'toLocaleLowerCase', 'toLocaleUpperCase', 'slice',
  'substring', 'substr', 'replace', 'replaceAll', 'concat', 'padStart', 'padEnd', 'normalize', 'at', 'charAt', 'split',
  'repeat', 'toString', 'valueOf', 'toWellFormed',
]);
const ARRAY_PASSTHROUGH = new Set(['join', 'slice', 'concat', 'flat', 'filter', 'reverse', 'sort', 'toSorted', 'toReversed', 'at', 'find', 'findLast', 'pop', 'shift', 'values']);
const RECEIVER_PASSTHROUGH: Record<string, Set<string>> = {
  URLSearchParams: new Set(['get', 'getAll', 'toString']),
  URL: new Set(['toString', 'toJSON']),
  Response: new Set(['json', 'text', 'blob', 'arrayBuffer', 'formData']),
};
const GLOBAL_PASSTHROUGH = new Set(['String', 'decodeURIComponent', 'decodeURI', 'atob', 'btoa', 'unescape', 'structuredClone']);
const NUMERIC = new Set(['Number', 'parseInt', 'parseFloat', 'Boolean', 'isNaN', 'isFinite']);

export interface TaintStats {
  traces: number;
  truncated: number;
  unsupported: Map<string, number>;
  timedOut: boolean;
}

/**
 * Demand-driven backward taint analysis.
 *
 * `trace(expr)` walks from a sink argument back through assignments, parameters
 * (via call sites or bound arguments), returns, class properties, template
 * bindings, selected RxJS operators and Angular signals until it reaches modeled
 * sources, constants, recognized sanitizers or something it cannot resolve.
 * Every limit hit is surfaced as `truncated` — results are never silently cut.
 */
export class TaintEngine implements TaintAnalyzer {
  private readonly cache = new Map<string, TaintResult>();
  private state!: TraceState;
  private readonly deadline: number;
  readonly stats: TaintStats = { traces: 0, truncated: 0, unsupported: new Map(), timedOut: false };

  constructor(
    private readonly symbols: Symbols,
    private readonly index: Index,
    private readonly flow: Flow,
    private readonly limits: AnalysisLimits,
    private readonly templateInput: Map<ts.ClassDeclaration, TemplateUserInput>,
    private readonly trustedSanitizers: string[] = [],
    startedAt = Date.now(),
  ) {
    this.deadline = startedAt + limits.maxTimeMs;
  }

  sourceOf(expression: ts.Expression): TaintSource | undefined {
    const m = matchSource(expression, this.symbols);
    return m ? { ...m, location: locationOf(expression), node: expression } : undefined;
  }

  trace(expression: ts.Expression, options: { context?: SinkContext } = {}): TaintResult {
    const context = options.context ?? 'generic';
    const key = `${expression.getSourceFile().fileName}:${expression.pos}:${expression.end}:${context}`;
    const cached = this.cache.get(key);
    if (cached) return cached;
    this.stats.traces++;
    this.state = {
      context, flows: [], flowKeys: new Set(), unresolved: [], sanitized: [], constants: [], constantLeaves: 0,
      names: new Set(), explored: new Set(), visited: 0, truncated: false,
    };
    const file = expression.getSourceFile().fileName;
    this.visit(expression, EMPTY_ENV, { depth: 0, hops: 0, file });
    const s = this.state;
    if (s.truncated) this.stats.truncated++;
    const result: TaintResult = {
      flows: s.flows.sort((a, b) => confidenceRank(b.confidence) - confidenceRank(a.confidence)),
      unresolved: dedupeNotes(s.unresolved),
      sanitized: dedupeNotes(s.sanitized),
      constant: !s.flows.length && !s.unresolved.length && !s.sanitized.length && !s.truncated,
      constants: [...new Set(s.constants)],
      names: [...s.names],
      truncated: s.truncated,
    };
    this.cache.set(key, result);
    return result;
  }

  // ---------------------------------------------------------------- leaves

  private extend(path: Path, kind: TraceStepKind, node: ts.Node, description: string, symbol?: string): Path {
    const file = node.getSourceFile().fileName;
    const step: TraceStep = { kind, location: locationOf(node), description, ...(symbol ? { symbol } : {}) };
    return { step, parent: path, depth: path.depth + 1, hops: path.hops + (file !== path.file ? 1 : 0), file };
  }

  private approx(path: Path, reason: string): Path {
    return { ...path, approx: reason, parent: path, step: undefined } as Path;
  }

  private addSource(match: SourceMatch, node: ts.Node, path: Path) {
    const s = this.state;
    const location = locationOf(node);
    const key = `${location.file}:${location.line}:${location.column}:${match.kind}`;
    if (s.flowKeys.has(key)) return;
    if (s.flows.length >= this.limits.maxPathsPerSink) {
      s.truncated = true;
      return;
    }
    s.flowKeys.add(key);
    const steps: TraceStep[] = [];
    const approximations: string[] = [];
    for (let p: Path | undefined = path; p; p = p.parent) {
      if (p.step) steps.push(p.step);
      if (p.approx) approximations.push(p.approx);
    }
    const sourceStep: TraceStep = { kind: 'source', location, description: match.description };
    const dedup = steps.filter((st, i) => i === 0 || !sameLoc(st, steps[i - 1]!));
    const confidence = lowerConfidence(match.trust, Math.min(2, new Set(approximations).size));
    s.flows.push({
      source: { ...match, location, node },
      steps: [sourceStep, ...dedup.filter((st) => !sameLoc(st, sourceStep))],
      confidence,
      approximations: [...new Set(approximations)].reverse(),
    });
  }

  private unresolved(reason: string, node: ts.Node) {
    if (this.state.unresolved.length < 20) this.state.unresolved.push({ reason, location: locationOf(node) });
  }

  private constant(value?: string) {
    this.state.constantLeaves++;
    if (value !== undefined && this.state.constants.length < 20) this.state.constants.push(value);
  }

  private readonly unsupportedNodes = new Set<string>();
  private unsupported(what: string, node: ts.Node) {
    const key = nodeKey(node);
    if (!this.unsupportedNodes.has(key)) {
      this.unsupportedNodes.add(key);
      this.stats.unsupported.set(what, (this.stats.unsupported.get(what) ?? 0) + 1);
    }
    this.unresolved(`unsupported: ${what}`, node);
  }

  private budget(node: ts.Node, path: Path, key: string): boolean {
    const s = this.state;
    if (s.explored.has(key)) return false;
    s.explored.add(key);
    if (++s.visited > this.limits.maxVisitedNodes || path.depth > this.limits.maxDepth || path.hops > this.limits.maxFileHops) {
      s.truncated = true;
      return false;
    }
    if (Date.now() > this.deadline) {
      this.stats.timedOut = true;
      s.truncated = true;
      return false;
    }
    void node;
    return true;
  }

  private visitAny(expr: ts.Expression, env: Env, path: Path, mode: Mode) {
    if (mode === 'value') this.visit(expr, env, path);
    else this.visitEmitted(expr, env, path, undefined);
  }

  // ---------------------------------------------------------------- values

  private visit(expression: ts.Expression, env: Env, path: Path): void {
    const e = skipOuter(expression);
    if (!this.budget(e, path, `v:${nodeKey(e)}:${env.id}`)) return;

    const src = matchSource(e, this.symbols);
    if (src) return this.addSource(src, e, path);

    if (ts.isStringLiteralLike(e)) return this.constant(e.text);
    if (ts.isNumericLiteral(e) || ts.isBigIntLiteral(e) || ts.isRegularExpressionLiteral(e)
      || e.kind === ts.SyntaxKind.TrueKeyword || e.kind === ts.SyntaxKind.FalseKeyword
      || e.kind === ts.SyntaxKind.NullKeyword || e.kind === ts.SyntaxKind.ThisKeyword
      || ts.isArrowFunction(e) || ts.isFunctionExpression(e) || ts.isClassExpression(e)
      || ts.isTypeOfExpression(e) || ts.isVoidExpression(e) || ts.isDeleteExpression(e)
      || ts.isPrefixUnaryExpression(e) || ts.isPostfixUnaryExpression(e)) {
      return this.constant();
    }
    if (ts.isTemplateExpression(e)) {
      this.constant(e.head.text);
      const p = this.extend(path, 'transform', e, 'interpolated into a template literal');
      for (const span of e.templateSpans) this.visit(span.expression, env, p);
      return;
    }
    if (ts.isBinaryExpression(e)) return this.visitBinary(e, env, path);
    if (ts.isConditionalExpression(e)) {
      this.visit(e.whenTrue, env, path);
      this.visit(e.whenFalse, env, path);
      return;
    }
    if (ts.isAwaitExpression(e)) return this.visit(e.expression, env, path);
    if (ts.isIdentifier(e)) return this.visitIdentifier(e, env, path, 'value');
    if (ts.isPropertyAccessExpression(e) || ts.isElementAccessExpression(e)) return this.visitMember(e, env, path, 'value');
    if (ts.isCallExpression(e)) return this.visitCall(e, env, path);
    if (ts.isNewExpression(e)) return this.visitNew(e, env, path);
    if (ts.isArrayLiteralExpression(e)) {
      const p = this.approx(path, 'array element (element-insensitive)');
      for (const el of e.elements) this.visit(ts.isSpreadElement(el) ? el.expression : el, env, p);
      if (!e.elements.length) this.constant();
      return;
    }
    if (ts.isObjectLiteralExpression(e)) return this.visitObjectLiteral(e, env, path);
    if (ts.isTaggedTemplateExpression(e)) return this.unsupported('tagged template', e);
    this.unsupported(`expression kind ${ts.SyntaxKind[e.kind]}`, e);
  }

  private visitObjectLiteral(e: ts.ObjectLiteralExpression, env: Env, path: Path) {
    let any = false;
    for (const p of e.properties) {
      const name = nameOf(p);
      if (ts.isPropertyAssignment(p)) {
        any = true;
        this.visit(p.initializer, env, this.extend(path, 'property', p, `stored in object property '${name ?? '?'}'`, name));
      } else if (ts.isShorthandPropertyAssignment(p)) {
        any = true;
        this.visit(p.name, env, this.extend(path, 'property', p, `stored in object property '${p.name.text}'`, p.name.text));
      } else if (ts.isSpreadAssignment(p)) {
        any = true;
        this.visit(p.expression, env, this.approx(path, 'object spread'));
      }
    }
    if (!any) this.constant();
  }

  private visitBinary(e: ts.BinaryExpression, env: Env, path: Path) {
    const k = e.operatorToken.kind;
    if (k === ts.SyntaxKind.PlusToken) {
      const p = this.extend(path, 'transform', e, 'string concatenation');
      this.visit(e.left, env, p);
      this.visit(e.right, env, p);
    } else if (k === ts.SyntaxKind.QuestionQuestionToken || k === ts.SyntaxKind.BarBarToken) {
      this.visit(e.left, env, path);
      this.visit(e.right, env, path);
    } else if (k === ts.SyntaxKind.AmpersandAmpersandToken || k === ts.SyntaxKind.CommaToken
      || k === ts.SyntaxKind.EqualsToken || k === ts.SyntaxKind.QuestionQuestionEqualsToken || k === ts.SyntaxKind.BarBarEqualsToken) {
      this.visit(e.right, env, path);
    } else if (k === ts.SyntaxKind.PlusEqualsToken) {
      this.visit(e.left, env, path);
      this.visit(e.right, env, path);
    } else this.constant(); // comparisons and arithmetic yield booleans / numbers
  }

  private visitIdentifier(id: ts.Identifier, env: Env, path: Path, mode: Mode) {
    if (id.text === 'undefined') return this.constant();
    let raw: ts.Symbol | undefined;
    try {
      // `{ x }`: the name resolves to the property; the value is the variable `x`.
      raw = ts.isShorthandPropertyAssignment(id.parent) && id.parent.name === id
        ? this.symbols.checker.getShorthandAssignmentValueSymbol(id.parent)
        : this.symbols.checker.getSymbolAtLocation(id);
    } catch {
      raw = undefined;
    }
    const sym = this.symbols.resolveAlias(raw);
    if (!sym) return this.unresolved(`unresolved identifier '${id.text}'`, id);
    const decl = sym.valueDeclaration ?? sym.declarations?.[0];
    if (!decl) return this.unresolved(`unresolved identifier '${id.text}'`, id);
    if (ts.isImportSpecifier(decl) || ts.isImportClause(decl) || ts.isNamespaceImport(decl)) {
      return this.unresolved(`'${id.text}' is imported from a module that could not be resolved`, id);
    }
    this.addName(id.text);
    this.visitDeclaration(decl, sym, id, env, path, mode);
  }

  private addName(name: string) {
    if (this.state.names.size < 60) this.state.names.add(name);
  }

  private visitDeclaration(decl: ts.Declaration, sym: ts.Symbol, ref: ts.Node, env: Env, path: Path, mode: Mode) {
    const name = sym.name;
    if (!this.symbols.isProjectNode(decl)) {
      if (mode === 'emitted') return this.unresolved(`external observable '${name}'`, ref);
      return this.unresolved(`external value '${name}'`, ref);
    }
    // `import data from './x.json'`: build-time project data, a constant.
    if (ts.isSourceFile(decl) && decl.fileName.endsWith('.json')) return this.constant();
    if (ts.isParameter(decl)) return this.visitParameter(decl, env, path, mode);
    if (ts.isBindingElement(decl)) return this.visitBindingElement(decl, env, path, mode);
    if (ts.isVariableDeclaration(decl)) {
      const list = decl.parent;
      if (ts.isCatchClause(list)) return this.unresolved('caught exception', decl);
      if (ts.isVariableDeclarationList(list) && (ts.isForOfStatement(list.parent) || ts.isForInStatement(list.parent))) {
        const iter = list.parent.expression;
        return this.visit(iter, env, this.approx(this.extend(path, 'assignment', decl, `iterated from ${shortText(iter, 40)}`, name), 'collection element (element-insensitive)'));
      }
      let found = false;
      if (decl.initializer) {
        found = true;
        this.visitAny(decl.initializer, env, this.extend(path, 'assignment', decl, `assigned to '${name}'`, name), mode);
      }
      for (const rhs of this.index.writesTo(sym)) {
        found = true;
        this.visitAny(rhs, env, this.extend(path, 'assignment', rhs.parent, `assigned to '${name}'`, name), mode);
      }
      if (mode === 'emitted') found = this.visitSubjectWrites(sym, path) || found;
      if (!found) this.unresolved(`'${name}' has no visible assignment`, decl);
      return;
    }
    if (ts.isPropertyDeclaration(decl) || ts.isPropertyAssignment(decl) || ts.isShorthandPropertyAssignment(decl)
      || ts.isGetAccessorDeclaration(decl) || ts.isPropertySignature(decl)) {
      return this.visitProperty(decl, sym, ref, path, mode);
    }
    if (ts.isFunctionDeclaration(decl) || ts.isMethodDeclaration(decl) || ts.isClassDeclaration(decl)
      || ts.isEnumDeclaration(decl) || ts.isEnumMember(decl)) {
      if (ts.isEnumMember(decl) && decl.initializer) return this.visit(decl.initializer, env, path);
      return this.constant();
    }
    this.unsupported(`declaration kind ${ts.SyntaxKind[decl.kind]}`, ref);
  }

  private visitProperty(decl: ts.Declaration, sym: ts.Symbol, ref: ts.Node, path: Path, mode: Mode) {
    const name = sym.name;
    const env = EMPTY_ENV;
    const p = this.extend(path, 'property', ref, `read from property '${name}'`, name);
    let found = false;
    if ((ts.isPropertyDeclaration(decl) || ts.isPropertyAssignment(decl)) && decl.initializer) {
      found = true;
      this.visitAny(decl.initializer, env, p, mode);
    } else if (ts.isShorthandPropertyAssignment(decl)) {
      found = true;
      this.visitIdentifier(decl.name, env, p, mode);
    } else if (ts.isGetAccessorDeclaration(decl)) {
      for (const r of returnExpressions(decl)) {
        found = true;
        this.visitAny(r, env, this.extend(p, 'return', r, `returned from getter '${name}'`), mode);
      }
    }
    for (const rhs of this.index.writesTo(sym)) {
      found = true;
      this.visitAny(rhs, env, this.extend(p, 'assignment', rhs.parent, `assigned to property '${name}'`, name), mode);
    }
    if (mode === 'emitted') found = this.visitSubjectWrites(sym, p) || found;
    const cls = decl.parent && ts.isClassDeclaration(decl.parent) ? decl.parent : undefined;
    const fromTemplate = cls && this.templateInput.get(cls)?.properties.get(name);
    for (const loc of fromTemplate ?? []) {
      found = true;
      const step: TraceStep = { kind: 'template', location: loc, description: `bound to user input in the template of ${cls!.name?.text ?? 'component'}`, symbol: name };
      this.addSourceAt({ kind: 'user-input', description: `template user input → '${name}'`, trust: 'medium' }, loc, { step, parent: p, depth: p.depth + 1, hops: p.hops, file: loc.file }, decl);
    }
    if (!found) {
      this.unresolved(ts.isPropertySignature(decl)
        ? `property '${name}' is declared on an interface/type; its values are not tracked`
        : `property '${name}' has no visible assignment`, ref);
    }
  }

  /** Template-originated sources have a location outside the TypeScript AST. */
  private addSourceAt(match: SourceMatch, loc: TraceStep['location'], path: Path, node: ts.Node) {
    const before = this.state.flows.length;
    this.addSource(match, node, path);
    const flow = this.state.flows[before];
    if (flow) {
      flow.source.location = loc;
      flow.steps[0] = { kind: 'source', location: loc, description: match.description };
      flow.steps = flow.steps.filter((st, i) => i === 0 || !sameLoc(st, flow.steps[0]!));
    }
  }

  private visitBindingElement(be: ts.BindingElement, env: Env, path: Path, mode: Mode) {
    const pattern = be.parent;
    const container = pattern.parent;
    const prop = be.propertyName && (ts.isIdentifier(be.propertyName) || ts.isStringLiteral(be.propertyName))
      ? be.propertyName.text
      : ts.isIdentifier(be.name) ? be.name.text : undefined;
    const isArray = ts.isArrayBindingPattern(pattern);
    const p = this.extend(path, 'assignment', be, `destructured${prop && !isArray ? ` property '${prop}'` : ''}`, prop);
    if (ts.isVariableDeclaration(container) && container.initializer) {
      const init = skipOuter(container.initializer);
      if (!isArray) {
        const src = matchMemberSource(init, prop, this.symbols);
        if (src) return this.addSource(src, be, p);
        if (ts.isObjectLiteralExpression(init)) {
          const member = init.properties.find((m) => nameOf(m) === prop);
          if (member && ts.isPropertyAssignment(member)) return this.visitAny(member.initializer, env, p, mode);
        }
      }
      return this.visitAny(container.initializer, env, p, mode);
    }
    if (ts.isParameter(container)) {
      if (!isArray) {
        const o = this.symbols.typeOrigin(pattern as unknown as ts.Expression);
        if (prop === 'data' && originIs(o, 'dom', 'MessageEvent')) {
          return this.addSource({ kind: 'message', description: 'MessageEvent.data (destructured)', trust: 'high' }, be, p);
        }
      }
      return this.visitParameter(container, env, p, mode);
    }
    this.unsupported('nested destructuring', be);
  }

  private visitMember(e: ts.PropertyAccessExpression | ts.ElementAccessExpression, env: Env, path: Path, mode: Mode) {
    const name = memberName(e);
    if (name === 'length') return this.constant();
    if (name) this.addName(name);
    let sym = this.symbols.symbolAt(e);
    let decl = sym?.valueDeclaration ?? sym?.declarations?.[0];
    if (!sym && name) {
      // `inject(Service).field` while framework types are unavailable: use the declared class.
      const member = this.symbols.declaredClass(e.expression)?.members.find((m) => nameOf(m) === name);
      const msym = member?.name && this.symbols.checker.getSymbolAtLocation(member.name);
      if (member && msym) {
        sym = msym;
        decl = member;
      }
    }
    // Fields of interface / type-literal DTOs carry the taint of their container unless written explicitly.
    if (sym && decl && this.symbols.isProjectNode(decl) && ts.isPropertySignature(decl) && mode === 'value' && !this.index.writesTo(sym).length) {
      return this.visit(e.expression, env, this.extend(path, 'property', e, `property '${name ?? '?'}'`, name));
    }
    if (sym && decl && this.symbols.isProjectNode(decl)) return this.visitDeclaration(decl, sym, e, env, path, mode);
    if (mode === 'emitted') {
      if (name === 'asObservable') return this.visitEmitted(e.expression, env, path, undefined);
      return this.unresolved(`observable property '${name ?? '?'}' is not modeled`, e);
    }
    const p = this.extend(path, 'property', e, `property '${name ?? '[computed]'}'`, name);
    if (decl) return this.visit(e.expression, env, p); // property of a library type (URL, Location, …)
    // Untyped object: try a local object literal first, then fall back to field-insensitive propagation.
    const obj = skipOuter(e.expression);
    const objDecl = ts.isIdentifier(obj) ? this.symbols.declarationOf(obj) : undefined;
    if (name && objDecl && ts.isVariableDeclaration(objDecl) && objDecl.initializer && ts.isObjectLiteralExpression(skipOuter(objDecl.initializer))) {
      const member = (skipOuter(objDecl.initializer) as ts.ObjectLiteralExpression).properties.find((m) => nameOf(m) === name);
      if (member && ts.isPropertyAssignment(member)) return this.visit(member.initializer, env, p);
    }
    this.visit(e.expression, env, p); // container taint flows to its fields
  }

  // ---------------------------------------------------------------- parameters & callbacks

  private visitParameter(param: ts.ParameterDeclaration, env: Env, path: Path, mode: Mode) {
    const pname = ts.isIdentifier(param.name) ? param.name.text : '{…}';
    const bound = env.lookup(param);
    if (bound) {
      if (bound.kind === 'expr') {
        for (const x of bound.exprs) this.visitAny(x, bound.env, this.extend(path, 'argument', x, `passed as '${pname}'`, pname), mode);
        if (!bound.exprs.length) this.constant();
      } else {
        this.visitEmittedValue(bound.obs, bound.env, path, bound.upto, mode, param);
      }
      return;
    }
    const fn = param.parent as ts.SignatureDeclaration;
    const idx = fn.parameters.indexOf(param);
    const fnName = nameOf(fn) ?? (ts.isVariableDeclaration(fn.parent) ? nameOf(fn.parent) : undefined) ?? 'callback';
    let found = false;

    // Inline callbacks: `obs.subscribe(v => …)`, `.pipe(map(v => …))`, `.then(v => …)`, `arr.map(v => …)`.
    let holder: ts.Node = fn.parent;
    while (ts.isParenthesizedExpression(holder)) holder = holder.parent;
    if ((ts.isArrowFunction(fn) || ts.isFunctionExpression(fn))) {
      if ((ts.isCallExpression(holder) || ts.isNewExpression(holder)) && holder.arguments?.some((a) => skipOuter(a) === fn)) {
        found = this.callbackContext(holder, idx, env, path, mode, param) || found;
        if (found) return;
      }
      // `subscribe({ next: v => … })`
      if (ts.isPropertyAssignment(holder) && nameOf(holder) === 'next' && ts.isObjectLiteralExpression(holder.parent)
        && ts.isCallExpression(holder.parent.parent) && memberName(holder.parent.parent.expression) === 'subscribe') {
        return void this.callbackContext(holder.parent.parent, idx, env, path, mode, param);
      }
    }
    for (const use of this.index.callbackUses(fn)) found = this.callbackContext(use.call, idx, env, path, mode, param) || found;

    const cls = ts.isMethodDeclaration(fn) && ts.isClassDeclaration(fn.parent) ? fn.parent : undefined;
    for (const t of (cls && this.templateInput.get(cls)?.methodArgs.get(fnName)) ?? []) {
      if (t.argIndex !== idx) continue;
      found = true;
      const step: TraceStep = { kind: 'template', location: t.location, description: `template passes user input to ${fnName}()`, symbol: pname };
      this.addSourceAt({ kind: 'user-input', description: `template user input → ${fnName}()`, trust: 'medium' }, t.location, { step, parent: path, depth: path.depth + 1, hops: path.hops, file: t.location.file }, param);
    }

    const calls = this.index.callsTo(fn);
    if (calls.length > this.limits.maxCallSites) this.state.truncated = true;
    for (const call of calls.slice(0, this.limits.maxCallSites)) {
      const args = call.arguments ?? [];
      const selected = param.dotDotDotToken ? args.slice(idx) : args[idx] ? [args[idx]!] : [];
      const callerEnv = EMPTY_ENV;
      for (const a of selected) {
        found = true;
        const arg = ts.isSpreadElement(a) ? a.expression : a;
        this.visitAny(arg, callerEnv, this.extend(path, 'argument', call, `passed as '${pname}' to ${fnName}()`, pname), mode);
      }
      if (!selected.length && param.initializer) {
        found = true;
        this.visitAny(param.initializer, callerEnv, path, mode);
      }
    }
    if (found) return;
    if (ts.isConstructorDeclaration(fn)) return this.unresolved(`constructor parameter '${pname}' (provided by dependency injection)`, param);
    const decorated = ts.canHaveDecorators(fn) && (ts.getDecorators(fn)?.length ?? 0) > 0;
    this.unresolved(decorated
      ? `parameter '${pname}' of framework-invoked handler ${fnName}()`
      : `parameter '${pname}' of ${fnName}() has no visible callers`, param);
  }

  /** Value a callback parameter receives, given the call the callback is passed to. Returns false when not modeled. */
  private callbackContext(call: ts.CallExpression | ts.NewExpression, paramIndex: number, env: Env, path: Path, mode: Mode, param: ts.ParameterDeclaration): boolean {
    const callee = skipOuter(call.expression);
    const method = ts.isIdentifier(callee) ? callee.text : memberName(callee);
    const recv = memberObject(callee);
    if (!method) return false;
    if (method === 'subscribe' && recv && paramIndex === 0) {
      this.visitEmittedValue(recv, env, this.extend(path, 'reactive', call, 'emitted to subscribe()'), undefined, mode, param);
      return true;
    }
    // Operator inside `source.pipe(op1, op2, …)`.
    const pipe = call.parent;
    if (ts.isCallExpression(call) && ts.isIdentifier(callee) && ts.isCallExpression(pipe) && memberName(pipe.expression) === 'pipe'
      && (MAP_OPERATORS.has(method) || FLATTEN_OPERATORS.has(method) || PASSTHROUGH_OPERATORS.has(method)) && paramIndex === 0) {
      const at = pipe.arguments.indexOf(call);
      this.visitEmittedValue(pipe, env, path, at, mode, param);
      return true;
    }
    if (method === 'then' && recv && paramIndex === 0) {
      this.visitAny(recv, env, this.extend(path, 'reactive', call, 'resolved value passed to then()'), mode);
      return true;
    }
    if (['map', 'forEach', 'filter', 'find', 'some', 'every', 'flatMap', 'findLast'].includes(method) && recv && paramIndex === 0
      && !ts.isIdentifier(callee)) {
      this.visit(recv, env, this.approx(this.extend(path, 'transform', call, `element passed to ${method}()`), 'collection element (element-insensitive)'));
      return true;
    }
    if (method === 'update' && recv && paramIndex === 0 && this.signalDeclaration(recv)) {
      this.visitSignal(recv, env, path);
      return true;
    }
    return false;
  }

  /** Value emitted by `obs` (optionally only the first `upto` pipe operators), consumed as value or observable. */
  private visitEmittedValue(obs: ts.Expression, env: Env, path: Path, upto: number | undefined, mode: Mode, param: ts.ParameterDeclaration) {
    if (mode === 'value') return this.visitEmitted(obs, env, path, upto);
    this.unresolved(`observable passed through callback parameter '${nameOf(param) ?? '?'}'`, param);
  }

  // ---------------------------------------------------------------- calls

  private visitCall(call: ts.CallExpression, env: Env, path: Path) {
    const callee = skipOuter(call.expression);
    const info = this.symbols.callee(call);
    const name = info?.name;
    const recv = memberObject(callee);
    const arg0 = call.arguments[0];

    const sanitizer = this.matchSanitizer(call, info);
    if (sanitizer) {
      if (sanitizer === 'numeric') return this.constant();
      if (sanitizer.contexts.includes(this.state.context)) {
        this.state.sanitized.push({ reason: sanitizer.description, location: locationOf(call) });
        return;
      }
      if (arg0) {
        const p = this.extend(path, 'transform', call, `${sanitizer.description} (not a sanitizer for this context)`);
        // URL encoding is not HTML escaping: `'` ( ) ! * survive and break out of single-quoted attributes.
        return this.visit(sanitizer.valueArg ?? arg0, env, sanitizer.partial ? this.approx(p, sanitizer.partial) : p);
      }
    }
    if (name?.startsWith('bypassSecurityTrust') && arg0) {
      return this.visit(arg0, env, this.extend(path, 'trust-bypass', call, `marked as trusted by ${name}() (no sanitization)`));
    }
    if (call.arguments.length === 0 && this.signalDeclaration(callee)) return this.visitSignal(callee, env, path);
    if (name === 'asReadonly' && recv && this.signalDeclaration(recv)) return this.visitSignal(recv, env, path);

    if (name && (name === 'firstValueFrom' || name === 'lastValueFrom') && arg0 && (!info?.origin || info.origin.module === 'rxjs')) {
      return this.visitEmitted(arg0, env, this.extend(path, 'reactive', call, `awaited via ${name}()`), undefined);
    }

    const libFn = !recv && (!info?.origin || info.origin.module === 'lib' || info.origin.module === 'dom');
    if (name && libFn && GLOBAL_PASSTHROUGH.has(name) && arg0) {
      return this.visit(arg0, env, this.extend(path, 'transform', call, `transformed by ${name}()`));
    }
    if (recv && name) {
      const ro = this.symbols.typeOrigin(recv);
      if (ro && (ro.module === 'lib' || ro.module === 'dom')) {
        if (ro.name === 'JSON' && (name === 'parse' || name === 'stringify') && arg0) {
          return this.visit(arg0, env, this.extend(path, 'transform', call, `transformed by JSON.${name}()`));
        }
        if (ro.name === 'Math') return this.constant();
        if (ro.name === 'Promise' && name === 'resolve' && arg0) return this.visit(arg0, env, path);
        if ((ro.name === 'ObjectConstructor' || ro.name === 'Object') && ['assign', 'values', 'entries', 'freeze', 'fromEntries'].includes(name)) {
          const p = this.approx(path, `Object.${name}() (field-insensitive)`);
          for (const a of call.arguments) this.visit(a, env, p);
          return;
        }
        if (RECEIVER_PASSTHROUGH[ro.name]?.has(name)) {
          return this.visit(recv, env, this.extend(path, 'transform', call, `${ro.name}.${name}()`));
        }
      }
      if (STRING_METHODS.has(name) && this.isStringLike(recv)) {
        const p = this.extend(path, 'transform', call, `transformed by .${name}()`);
        this.visit(recv, env, p);
        if (name === 'replace' || name === 'replaceAll') {
          if (call.arguments[1]) this.visit(call.arguments[1], env, p);
        } else if (name === 'concat') for (const a of call.arguments) this.visit(a, env, p);
        return;
      }
      if (this.isArrayLike(recv)) {
        if (ARRAY_PASSTHROUGH.has(name)) {
          const p = this.extend(path, 'transform', call, `.${name}()`);
          this.visit(recv, env, p);
          if (name === 'concat') for (const a of call.arguments) this.visit(a, env, p);
          return;
        }
        if ((name === 'map' || name === 'flatMap') && arg0) {
          const fn = this.flow.resolveFunction(arg0);
          if (fn) return this.visitReturns(fn, [[recv]], env, this.extend(path, 'transform', call, `.${name}()`), 'value');
        }
      }
      if (name === 'then' && arg0) {
        const fn = this.flow.resolveFunction(arg0);
        if (fn) return this.visitReturns(fn, [[recv]], env, this.extend(path, 'reactive', call, 'then()'), 'value');
      }
      if ((name === 'catch' || name === 'finally') && this.isPromiseLike(recv)) return this.visit(recv, env, path);
      if ((name === 'toString' || name === 'valueOf') && call.arguments.length === 0) {
        return this.visit(recv, env, this.extend(path, 'transform', call, `.${name}()`));
      }
    }

    if (info?.declaration) {
      return this.visitReturns(info.declaration, call.arguments.map((a) => [a]), env, this.extend(path, 'return', call, `returned from ${name}()`, name), 'value');
    }
    // ParamMap / URLSearchParams / Map style lookups: the result derives from the container.
    if (recv && (name === 'get' || name === 'getAll')) {
      const key = call.arguments[0] ? this.symbols.constantString(call.arguments[0]) : undefined;
      return this.visit(recv, env, this.extend(path, 'transform', call, `${name}(${key ? `'${key}'` : '…'}) lookup`));
    }
    const decl = this.symbols.declarationOf(callee);
    if (decl && this.symbols.isProjectNode(decl) && (ts.isMethodSignature(decl) || ts.isPropertySignature(decl))) {
      return this.unresolved(`${name}() is declared on an interface; implementation not resolved`, call);
    }
    // Unmodeled library call: propagate from arguments with reduced confidence.
    if (call.arguments.length) {
      const p = this.approx(this.extend(path, 'transform', call, `through unmodeled call ${name ?? shortText(callee, 30)}()`), `unmodeled call ${name ?? '?'}()`);
      for (const a of call.arguments) this.visit(a, env, p);
      if (recv) this.visit(recv, env, p);
      return;
    }
    if (recv && name) {
      return this.visit(recv, env, this.approx(this.extend(path, 'transform', call, `.${name}()`), `unmodeled method ${name}()`));
    }
    this.unresolved(`return value of ${name ?? shortText(callee, 30)}()`, call);
  }

  private visitNew(e: ts.NewExpression, env: Env, path: Path) {
    const o = this.symbols.typeOrigin(e);
    const arg0 = e.arguments?.[0];
    if (o && (o.module === 'dom' || o.module === 'lib') && ['URL', 'URLSearchParams', 'String'].includes(o.name) && arg0) {
      return this.visit(arg0, env, this.extend(path, 'transform', e, `new ${o.name}()`));
    }
    if (o && (o.module === 'dom' || o.module === 'lib') && ['Date', 'RegExp', 'Map', 'Set', 'Error', 'Number'].includes(o.name)) return this.constant();
    this.unresolved(`constructed value new ${shortText(e.expression, 30)}()`, e);
  }

  private visitReturns(fn: ts.SignatureDeclaration, args: ts.Expression[][], env: Env, path: Path, mode: Mode) {
    const lexical = ts.isArrowFunction(fn) || ts.isFunctionExpression(fn) ? env : undefined;
    // Parameterless callees add no bindings: reuse the environment so equivalent visits deduplicate.
    const callee = fn.parameters.length ? new Env(lexical) : (lexical ?? EMPTY_ENV);
    fn.parameters.forEach((p, i) => {
      const exprs = p.dotDotDotToken ? args.slice(i).flat() : args[i] ?? (p.initializer ? [p.initializer] : []);
      callee.bindings.set(p, { kind: 'expr', exprs, env, mode: 'value' });
    });
    const returns = returnExpressions(fn);
    if (!returns.length) return this.constant();
    for (const r of returns) this.visitAny(r, callee, path, mode);
  }

  private matchSanitizer(call: ts.CallExpression, info: ReturnType<Symbols['callee']>):
    { description: string; contexts: SinkContext[]; valueArg?: ts.Expression; partial?: string } | 'numeric' | undefined {
    if (!info) return undefined;
    const { name, receiver, origin } = info;
    const recvExpr = memberObject(skipOuter(call.expression));
    if (!recvExpr && NUMERIC.has(name) && (!origin || origin.module === 'lib')) return 'numeric';
    if (name === 'sanitize' && originIs(receiver, ['@angular/platform-browser', '@angular/core'], 'DomSanitizer', 'Sanitizer')) {
      const ctxArg = call.arguments[0];
      const ctxName = ctxArg ? memberName(ctxArg) ?? this.symbols.constantString(ctxArg) : undefined;
      const map: Record<string, SinkContext[]> = { HTML: ['html'], '1': ['html'], URL: ['url'], '4': ['url'], RESOURCE_URL: ['resource-url'], '5': ['resource-url'], SCRIPT: ['script'], '3': ['script'] };
      const valueArg = call.arguments[1];
      return { description: `DomSanitizer.sanitize(SecurityContext.${ctxName ?? '?'})`, contexts: map[ctxName ?? ''] ?? [], ...(valueArg ? { valueArg } : {}) };
    }
    if (name === 'sanitize' && recvExpr && (['dompurify', 'isomorphic-dompurify'].includes(receiver?.module ?? '')
      || (ts.isIdentifier(skipOuter(recvExpr)) && (skipOuter(recvExpr) as ts.Identifier).text === 'DOMPurify'))) {
      return { description: 'DOMPurify.sanitize()', contexts: ['html'] };
    }
    if (!recvExpr && name === 'encodeURIComponent' && (!origin || origin.module === 'lib')) {
      // URL contexts only. It is NOT HTML escaping (see `partial`).
      return { description: 'encodeURIComponent()', contexts: ['url', 'resource-url'], partial: 'URL-encoded (encodeURIComponent) but not HTML-escaped' };
    }
    if (!recvExpr && name === 'encodeURI' && (!origin || origin.module === 'lib')) {
      // Keeps `:` and `/`, so `javascript:` URLs pass; not an HTML escape either.
      return { description: 'encodeURI()', contexts: [], partial: 'URL-encoded (encodeURI) but not HTML-escaped or scheme-validated' };
    }
    if (info.declaration && this.trustedSanitizers.length) {
      const fnName = nameOf(info.declaration) ?? (ts.isVariableDeclaration(info.declaration.parent) ? nameOf(info.declaration.parent) : undefined);
      const file = info.declaration.getSourceFile().fileName.replace(/\\/g, '/');
      const trusted = this.trustedSanitizers.some((t) => {
        const [f, n] = t.includes('#') ? t.split('#') as [string, string] : [undefined, t];
        return n === fnName && (!f || file.endsWith(f.replace(/^\.\//, '')));
      });
      if (trusted) return { description: `trusted sanitizer ${fnName}() (configured)`, contexts: ['html', 'url', 'resource-url', 'script', 'code'] };
    }
    return undefined;
  }

  // ---------------------------------------------------------------- signals

  private signalDeclaration(expr: ts.Expression, depth = 0): { factory: string; init: ts.CallExpression; sym: ts.Symbol } | undefined {
    if (depth > 5) return undefined;
    const e = skipOuter(expr);
    if (!ts.isIdentifier(e) && !ts.isPropertyAccessExpression(e)) return undefined;
    const sym = this.symbols.symbolAt(e);
    const decl = sym?.valueDeclaration;
    if (!sym || !decl || !(ts.isPropertyDeclaration(decl) || ts.isVariableDeclaration(decl)) || !decl.initializer) return undefined;
    const init = skipOuter(decl.initializer);
    if (!ts.isCallExpression(init)) {
      return ts.isIdentifier(init) || ts.isPropertyAccessExpression(init) ? this.signalDeclaration(init, depth + 1) : undefined;
    }
    const callee = skipOuter(init.expression);
    const base = ts.isPropertyAccessExpression(callee) ? skipOuter(callee.expression) : callee;
    if (!ts.isIdentifier(base)) return undefined;
    const factory = ts.isPropertyAccessExpression(callee) ? `${base.text}.${callee.name.text}` : base.text;
    if (!['signal', 'computed', 'toSignal', 'linkedSignal', 'input', 'input.required', 'model', 'model.required'].includes(factory)) return undefined;
    const imp = this.symbols.importOrigin(base);
    if (imp ? !SIGNAL_MODULES.includes(imp.module) : this.symbols.declarationOf(base) && this.symbols.isProjectNode(this.symbols.declarationOf(base)!)) return undefined;
    return { factory, init, sym };
  }

  private visitSignal(expr: ts.Expression, env: Env, path: Path) {
    const sig = this.signalDeclaration(expr);
    if (!sig) return this.unresolved('signal declaration not found', expr);
    const { factory, init, sym } = sig;
    const p = this.extend(path, 'signal', expr, `read from signal '${sym.name}'`, sym.name);
    const fresh = EMPTY_ENV;
    const a0 = init.arguments[0];
    switch (factory) {
      case 'signal':
        if (a0) this.visit(a0, fresh, p);
        else this.constant();
        for (const c of this.index.methodCallsOn(sym)) {
          const m = memberName(c.expression);
          if (m === 'set' && c.arguments[0]) this.visit(c.arguments[0], EMPTY_ENV, this.extend(p, 'signal', c, `written via ${sym.name}.set()`));
          if (m === 'update' && c.arguments[0]) {
            const fn = this.flow.resolveFunction(c.arguments[0]);
            if (fn) for (const r of returnExpressions(fn)) this.visit(r, EMPTY_ENV, this.extend(p, 'signal', c, `written via ${sym.name}.update()`));
          }
        }
        return;
      case 'computed':
      case 'linkedSignal': {
        const fnArg = a0 && ts.isObjectLiteralExpression(skipOuter(a0))
          ? (skipOuter(a0) as ts.ObjectLiteralExpression).properties.find((m) => nameOf(m) === 'computation')
          : a0;
        const fn = fnArg && this.flow.resolveFunction(ts.isPropertyAssignment(fnArg) ? fnArg.initializer : fnArg as ts.Expression);
        if (!fn) return this.unresolved(`${factory}() computation not resolved`, init);
        for (const r of returnExpressions(fn)) this.visit(r, fresh, this.extend(p, 'signal', r, `computed in ${sym.name}`));
        return;
      }
      case 'toSignal': {
        if (a0) this.visitEmitted(a0, fresh, this.extend(p, 'signal', init, 'converted by toSignal()'), undefined);
        const opts = init.arguments[1] && skipOuter(init.arguments[1]);
        const initial = opts && ts.isObjectLiteralExpression(opts) ? opts.properties.find((m) => nameOf(m) === 'initialValue') : undefined;
        if (initial && ts.isPropertyAssignment(initial)) this.visit(initial.initializer, fresh, p);
        return;
      }
      default:
        this.unresolved(`signal '${sym.name}' is a component ${factory.split('.')[0]}(); its value is supplied by the parent binding`, expr);
    }
  }

  // ---------------------------------------------------------------- observables

  private visitSubjectWrites(sym: ts.Symbol, path: Path): boolean {
    const decl = sym.valueDeclaration;
    const init = decl && (ts.isPropertyDeclaration(decl) || ts.isVariableDeclaration(decl)) && decl.initializer ? skipOuter(decl.initializer) : undefined;
    if (!init || !ts.isNewExpression(init)) return false;
    const cls = skipOuter(init.expression);
    if (!ts.isIdentifier(cls) || !['Subject', 'BehaviorSubject', 'ReplaySubject', 'AsyncSubject', 'EventEmitter'].includes(cls.text)) return false;
    let found = false;
    if (cls.text === 'BehaviorSubject' && init.arguments?.[0]) {
      found = true;
      this.visit(init.arguments[0], EMPTY_ENV, path);
    }
    for (const c of this.index.methodCallsOn(sym)) {
      const m = memberName(c.expression);
      if ((m === 'next' || m === 'emit') && c.arguments[0]) {
        found = true;
        this.visit(c.arguments[0], EMPTY_ENV, this.extend(path, 'reactive', c, `pushed via ${sym.name}.${m}()`));
      }
    }
    return found;
  }

  private visitEmitted(obs: ts.Expression, env: Env, path: Path, upto: number | undefined): void {
    const e = skipOuter(obs);
    if (!this.budget(e, path, `e:${nodeKey(e)}:${upto ?? 'all'}:${env.id}`)) return;
    const src = matchObservableSource(e, this.symbols);
    if (src) return this.addSource(src, e, path);

    if (ts.isIdentifier(e)) return this.visitIdentifier(e, env, path, 'emitted');
    if (ts.isPropertyAccessExpression(e) || ts.isElementAccessExpression(e)) return this.visitMember(e, env, path, 'emitted');
    if (!ts.isCallExpression(e)) return this.unsupported(`observable expression ${ts.SyntaxKind[e.kind]}`, e);

    const callee = skipOuter(e.expression);
    const name = ts.isIdentifier(callee) ? callee.text : memberName(callee);
    const recv = memberObject(callee);

    if (name === 'pipe' && recv) {
      const ops = e.arguments;
      const n = upto ?? ops.length;
      if (n === 0) return this.visitEmitted(recv, env, path, undefined);
      const op = skipOuter(ops[n - 1]!);
      const opName = ts.isCallExpression(op) && ts.isIdentifier(skipOuter(op.expression)) ? (skipOuter(op.expression) as ts.Identifier).text : undefined;
      if (!opName || !ts.isCallExpression(op)) return this.unsupported('non-call pipe operator', op);
      if (PASSTHROUGH_OPERATORS.has(opName)) return this.visitEmitted(e, env, path, n - 1);
      if (VALUE_ADDING_OPERATORS.has(opName)) {
        for (const a of op.arguments) this.visit(a, env, path);
        return this.visitEmitted(e, env, path, n - 1);
      }
      if (opName === 'catchError') {
        this.visitEmitted(e, env, path, n - 1);
        const fn = op.arguments[0] && this.flow.resolveFunction(op.arguments[0]);
        if (fn) for (const r of returnExpressions(fn)) this.visitEmitted(r, new Env(env), path, undefined);
        return;
      }
      if (MAP_OPERATORS.has(opName) || FLATTEN_OPERATORS.has(opName)) {
        const a0 = op.arguments[0];
        const p = this.extend(path, 'reactive', op, `transformed by ${opName}()`);
        if (a0 && ts.isPropertyAccessExpression(skipOuter(a0)) && shortText(a0) === 'JSON.parse') return this.visitEmitted(e, env, p, n - 1);
        const fn = a0 && this.flow.resolveFunction(a0);
        if (!fn) return this.unsupported(`${opName}() with an unresolved projection`, op);
        const inner = new Env(ts.isArrowFunction(fn) || ts.isFunctionExpression(fn) ? env : undefined);
        if (fn.parameters[0]) inner.bindings.set(fn.parameters[0], { kind: 'emitted', obs: e, upto: n - 1, env });
        const returns = returnExpressions(fn);
        if (!returns.length) return this.constant();
        for (const r of returns) {
          if (MAP_OPERATORS.has(opName)) this.visit(r, inner, p);
          else this.visitEmitted(r, inner, p, undefined);
        }
        return;
      }
      return this.unsupported(`RxJS operator ${opName}()`, op);
    }
    if (name === 'asObservable' && recv) return this.visitEmitted(recv, env, path, undefined);
    if (ts.isIdentifier(callee)) {
      if (name === 'of') {
        for (const a of e.arguments) this.visit(a, env, path);
        if (!e.arguments.length) this.constant();
        return;
      }
      if (name === 'from' && e.arguments[0]) return this.visit(e.arguments[0], env, this.approx(path, 'from() element'));
      if (name && COMBINATORS.has(name) && e.arguments.length) {
        // combineLatest([a, b]) / forkJoin({ a, b }) / merge(a, b): emitted values derive from every input.
        const inputs = e.arguments.flatMap((a) => {
          const x = skipOuter(a);
          if (ts.isArrayLiteralExpression(x)) return [...x.elements];
          if (ts.isObjectLiteralExpression(x)) return x.properties.flatMap((m) => (ts.isPropertyAssignment(m) ? [m.initializer] : ts.isShorthandPropertyAssignment(m) ? [m.name] : []));
          return [a];
        });
        const tuple = name === 'combineLatest' || name === 'forkJoin' || name === 'zip';
        const p = this.extend(path, 'reactive', e, `combined by ${name}()`);
        for (const input of inputs) this.visitEmitted(input as ts.Expression, env, tuple ? this.approx(p, `${name}() tuple element (element-insensitive)`) : p, undefined);
        return;
      }
      if (name === 'toObservable' && e.arguments[0]) return this.visitSignal(e.arguments[0], env, this.extend(path, 'signal', e, 'converted by toObservable()'));
      if (name === 'defer' && e.arguments[0]) {
        const fn = this.flow.resolveFunction(e.arguments[0]);
        if (fn) for (const r of returnExpressions(fn)) this.visitEmitted(r, env, path, undefined);
        return;
      }
    }
    const info = this.symbols.callee(e);
    if (info?.declaration) {
      return this.visitReturns(info.declaration, e.arguments.map((a) => [a]), env, this.extend(path, 'return', e, `observable returned from ${info.name}()`, info.name), 'emitted');
    }
    this.unsupported(`observable factory ${name ?? shortText(callee, 30)}()`, e);
  }

  // ---------------------------------------------------------------- types

  private typeOf(e: ts.Expression): ts.Type | undefined {
    try {
      return this.symbols.checker.getTypeAtLocation(e);
    } catch {
      return undefined;
    }
  }

  private isStringLike(e: ts.Expression): boolean {
    const t = this.typeOf(e);
    if (!t) return false;
    if (t.flags & (ts.TypeFlags.Any | ts.TypeFlags.Unknown)) return true;
    const nn = this.symbols.checker.getNonNullableType(t);
    if (nn.flags & ts.TypeFlags.StringLike) return true;
    return nn.isUnion() && nn.types.every((x) => !!(x.flags & ts.TypeFlags.StringLike));
  }

  private isArrayLike(e: ts.Expression): boolean {
    const t = this.typeOf(e);
    if (!t) return false;
    if (t.flags & ts.TypeFlags.Any) return true;
    const checker = this.symbols.checker;
    return checker.isArrayType(checker.getNonNullableType(t)) || checker.isTupleType(checker.getNonNullableType(t));
  }

  private isPromiseLike(e: ts.Expression): boolean {
    const t = this.typeOf(e);
    return !!t && (!!(t.flags & ts.TypeFlags.Any) || t.getSymbol()?.name === 'Promise');
  }
}

function nodeKey(n: ts.Node): string {
  return `${n.getSourceFile().fileName}:${n.getStart()}:${n.end}:${n.kind}`;
}

function sameLoc(a: TraceStep, b: TraceStep): boolean {
  return a.location.file === b.location.file && a.location.line === b.location.line && a.location.column === b.location.column;
}

function dedupeNotes(notes: OriginNote[]): OriginNote[] {
  const seen = new Set<string>();
  return notes.filter((n) => {
    const k = `${n.reason}@${n.location.file}:${n.location.line}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}
