import ts from 'typescript';
import type { CodeIndex } from '@ngbastion/plugin-api';
import type { Symbols } from './symbols.js';
import { ASSIGNMENT_OPERATORS, skipOuter } from './util.js';

export interface CallbackUse {
  call: ts.CallExpression | ts.NewExpression;
  argIndex: number;
}

/**
 * One traversal over all in-scope files. Rules and the taint engine query
 * these lists instead of re-walking the AST. Symbol-keyed maps are built lazily.
 */
export class Index implements CodeIndex {
  readonly calls: ts.CallExpression[] = [];
  readonly newExpressions: ts.NewExpression[] = [];
  readonly assignments: ts.BinaryExpression[] = [];
  readonly classes: ts.ClassDeclaration[] = [];
  readonly stringLiterals: (ts.StringLiteral | ts.NoSubstitutionTemplateLiteral)[] = [];
  nodeCount = 0;

  private callsByDecl?: Map<ts.Node, (ts.CallExpression | ts.NewExpression)[]>;
  private callbackRefs?: Map<ts.Node, CallbackUse[]>;
  private writesBySymbol?: Map<ts.Symbol, ts.Expression[]>;
  private methodCallsBySymbol?: Map<ts.Symbol, ts.CallExpression[]>;

  constructor(readonly files: readonly ts.SourceFile[], private readonly symbols: Symbols) {
    const visit = (n: ts.Node): void => {
      this.nodeCount++;
      if (ts.isCallExpression(n)) this.calls.push(n);
      else if (ts.isNewExpression(n)) this.newExpressions.push(n);
      else if (ts.isBinaryExpression(n) && ASSIGNMENT_OPERATORS.has(n.operatorToken.kind)) this.assignments.push(n);
      else if (ts.isClassDeclaration(n)) this.classes.push(n);
      else if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) this.stringLiterals.push(n);
      ts.forEachChild(n, visit);
    };
    for (const f of files) visit(f);
  }

  callsTo(declaration: ts.SignatureDeclaration): readonly (ts.CallExpression | ts.NewExpression)[] {
    if (!this.callsByDecl) {
      this.callsByDecl = new Map();
      this.callbackRefs = new Map();
      for (const call of [...this.calls, ...this.newExpressions]) {
        const decl = this.symbols.functionDeclaration(call.expression);
        if (decl) push(this.callsByDecl, decl, call);
        // Constructors: `new Foo(x)` → Foo's constructor.
        if (ts.isNewExpression(call)) {
          const cls = this.symbols.declarationOf(call.expression);
          const ctor = cls && ts.isClassDeclaration(cls) ? cls.members.find(ts.isConstructorDeclaration) : undefined;
          if (ctor) push(this.callsByDecl, ctor, call);
        }
        call.arguments?.forEach((arg, argIndex) => {
          let a = skipOuter(arg);
          if (ts.isCallExpression(a) && ts.isPropertyAccessExpression(a.expression) && a.expression.name.text === 'bind') {
            a = skipOuter(a.expression.expression);
          }
          if (ts.isIdentifier(a) || ts.isPropertyAccessExpression(a)) {
            const fn = this.symbols.functionDeclaration(a);
            if (fn) push(this.callbackRefs!, fn, { call, argIndex });
          }
        });
      }
    }
    return this.callsByDecl.get(declaration) ?? [];
  }

  /** Calls that receive `declaration` as a callback argument by reference (`subscribe(this.onData)`). */
  callbackUses(declaration: ts.SignatureDeclaration): readonly CallbackUse[] {
    this.callsTo(declaration);
    return this.callbackRefs!.get(declaration) ?? [];
  }

  /** Right-hand sides assigned to a variable or property symbol anywhere in scope. */
  writesTo(symbol: ts.Symbol): readonly ts.Expression[] {
    if (!this.writesBySymbol) {
      this.writesBySymbol = new Map();
      for (const a of this.assignments) {
        const sym = this.symbols.symbolAt(skipOuter(a.left));
        if (sym) push(this.writesBySymbol, sym, a.right);
      }
    }
    return this.writesBySymbol.get(symbol) ?? [];
  }

  /** Method calls on a symbol, e.g. `this.state.set(v)` / `subject.next(v)`, keyed by the receiver symbol. */
  methodCallsOn(symbol: ts.Symbol): readonly ts.CallExpression[] {
    if (!this.methodCallsBySymbol) {
      this.methodCallsBySymbol = new Map();
      for (const call of this.calls) {
        const callee = skipOuter(call.expression);
        if (!ts.isPropertyAccessExpression(callee)) continue;
        const sym = this.symbols.symbolAt(skipOuter(callee.expression));
        if (sym) push(this.methodCallsBySymbol, sym, call);
      }
    }
    return this.methodCallsBySymbol.get(symbol) ?? [];
  }
}

function push<K, V>(map: Map<K, V[]>, key: K, value: V) {
  const list = map.get(key);
  if (list) list.push(value);
  else map.set(key, [value]);
}
