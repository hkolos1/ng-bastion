import ts from 'typescript';
import type { CalleeInfo, SymbolResolver, TypeOrigin } from '@ngbastion/plugin-api';
import { isFunctionLike, packageOfFile, skipOuter } from './util.js';

/**
 * Type-aware symbol identification with a declaration-based fallback.
 *
 * When the scanned project's dependencies are installed, origins come from the
 * TypeChecker (`resolvedBy: 'type-checker'`). When they are not (e.g. a fresh
 * clone without node_modules), the resolver follows type annotations,
 * `inject(X)` calls and import declarations to recover the module specifier
 * (`resolvedBy: 'declaration'`). Unrelated symbols with the same name from a
 * different module never match.
 */
export class Symbols implements SymbolResolver {
  constructor(
    readonly checker: ts.TypeChecker,
    private readonly isProjectFile: (fileName: string) => boolean,
  ) {}

  resolveAlias(symbol: ts.Symbol | undefined): ts.Symbol | undefined {
    let s = symbol;
    for (let i = 0; s && s.flags & ts.SymbolFlags.Alias && i < 10; i++) {
      try {
        const next = this.checker.getAliasedSymbol(s);
        if (!next || next === s || next.flags & ts.SymbolFlags.Alias && next.name === 'unknown') break;
        if (!next.declarations?.length) return s;
        s = next;
      } catch {
        break;
      }
    }
    return s;
  }

  symbolAt(node: ts.Node): ts.Symbol | undefined {
    let target: ts.Node = node;
    if (ts.isPropertyAccessExpression(node)) target = node.name;
    else if (ts.isElementAccessExpression(node)) target = node.argumentExpression;
    let sym: ts.Symbol | undefined;
    try {
      sym = this.checker.getSymbolAtLocation(target);
      if (!sym && ts.isShorthandPropertyAssignment(node.parent) && node.parent.name === node) {
        sym = this.checker.getShorthandAssignmentValueSymbol(node.parent);
      }
    } catch {
      return undefined;
    }
    return this.resolveAlias(sym);
  }

  declarationOf(expression: ts.Expression): ts.Declaration | undefined {
    const sym = this.symbolAt(skipOuter(expression));
    return sym?.valueDeclaration ?? sym?.declarations?.[0];
  }

  isProjectNode(node: ts.Node): boolean {
    const sf = node.getSourceFile();
    return !sf.isDeclarationFile && this.isProjectFile(sf.fileName);
  }

  private moduleOf(decl: ts.Node): string {
    const fileName = decl.getSourceFile().fileName;
    return packageOfFile(fileName) ?? fileName;
  }

  /** Import specifier origin of an identifier, resolvable even when the module itself is not. */
  importOrigin(identifier: ts.Identifier): TypeOrigin | undefined {
    let sym: ts.Symbol | undefined;
    try {
      sym = this.checker.getSymbolAtLocation(identifier);
    } catch {
      return undefined;
    }
    const decl = sym?.declarations?.[0];
    if (!decl) return undefined;
    if (ts.isImportSpecifier(decl)) {
      const spec = decl.parent.parent.parent.moduleSpecifier;
      if (ts.isStringLiteral(spec)) return { module: spec.text, name: (decl.propertyName ?? decl.name).text, resolvedBy: 'declaration' };
    }
    if (ts.isImportClause(decl) || ts.isNamespaceImport(decl)) {
      const importDecl = ts.isImportClause(decl) ? decl.parent : decl.parent.parent;
      if (ts.isStringLiteral(importDecl.moduleSpecifier)) {
        return { module: importDecl.moduleSpecifier.text, name: ts.isImportClause(decl) ? 'default' : '*', resolvedBy: 'declaration' };
      }
    }
    return undefined;
  }

  private originOfTypeNode(typeNode: ts.TypeNode | undefined): TypeOrigin | undefined {
    if (!typeNode) return undefined;
    if (ts.isUnionTypeNode(typeNode)) {
      for (const t of typeNode.types) {
        const o = this.originOfTypeNode(t);
        if (o) return o;
      }
      return undefined;
    }
    if (!ts.isTypeReferenceNode(typeNode)) return undefined;
    const name = ts.isIdentifier(typeNode.typeName) ? typeNode.typeName : typeNode.typeName.right;
    if (ts.isIdentifier(typeNode.typeName)) {
      const fromImport = this.importOrigin(typeNode.typeName);
      if (fromImport) return fromImport;
    }
    // ElementRef<HTMLDivElement> → keep the generic for nativeElement resolution.
    const sym = this.symbolAt(name);
    const decl = sym?.declarations?.[0];
    return decl ? { module: this.moduleOf(decl), name: name.text, resolvedBy: 'declaration' } : undefined;
  }

  private declaredOrigin(expr: ts.Expression): TypeOrigin | undefined {
    const e = skipOuter(expr);
    if (ts.isCallExpression(e) && ts.isIdentifier(e.expression) && e.expression.text === 'inject' && e.arguments[0]) {
      const arg = skipOuter(e.arguments[0]);
      if (ts.isIdentifier(arg)) return this.importOrigin(arg) ?? this.originOfIdentifierDecl(arg);
    }
    if (ts.isNewExpression(e) && ts.isIdentifier(e.expression)) {
      return this.importOrigin(e.expression) ?? this.originOfIdentifierDecl(e.expression);
    }
    if (ts.isIdentifier(e)) {
      const imp = this.importOrigin(e);
      if (imp) return imp;
    }
    // ElementRef.nativeElement → the generic argument or HTMLElement.
    if (ts.isPropertyAccessExpression(e) && e.name.text === 'nativeElement') {
      const owner = this.typeOrigin(e.expression);
      if (owner?.name === 'ElementRef' && owner.module === '@angular/core') {
        const decl = this.declarationOf(e.expression);
        const typeNode = decl && (ts.isParameter(decl) || ts.isPropertyDeclaration(decl) || ts.isVariableDeclaration(decl)) ? decl.type : undefined;
        const arg = typeNode && ts.isTypeReferenceNode(typeNode) ? typeNode.typeArguments?.[0] : undefined;
        return this.originOfTypeNode(arg) ?? { module: 'dom', name: 'HTMLElement', resolvedBy: 'declaration' };
      }
    }
    const decl = this.declarationOf(e);
    if (!decl) return undefined;
    if ((ts.isParameter(decl) || ts.isPropertyDeclaration(decl) || ts.isVariableDeclaration(decl) || ts.isPropertySignature(decl)) ) {
      const fromType = this.originOfTypeNode(decl.type);
      if (fromType) return fromType;
      if ((ts.isPropertyDeclaration(decl) || ts.isVariableDeclaration(decl)) && decl.initializer) {
        return this.declaredOrigin(decl.initializer);
      }
    }
    return undefined;
  }

  private originOfIdentifierDecl(id: ts.Identifier): TypeOrigin | undefined {
    const sym = this.symbolAt(id);
    const decl = sym?.declarations?.[0];
    return decl ? { module: this.moduleOf(decl), name: id.text, resolvedBy: 'declaration' } : undefined;
  }

  /** Memoized per node: rules ask the same questions about the same calls (type resolution dominates scan time). */
  private readonly typeOriginCache = new WeakMap<ts.Node, TypeOrigin | null>();
  private readonly calleeCache = new WeakMap<ts.Node, CalleeInfo | null>();

  typeOrigin(expression: ts.Expression): TypeOrigin | undefined {
    const e = skipOuter(expression);
    const hit = this.typeOriginCache.get(e);
    if (hit !== undefined) return hit ?? undefined;
    const origin = this.computeTypeOrigin(e);
    this.typeOriginCache.set(e, origin ?? null);
    return origin;
  }

  private computeTypeOrigin(e: ts.Expression): TypeOrigin | undefined {
    let type: ts.Type | undefined;
    try {
      type = this.checker.getNonNullableType(this.checker.getTypeAtLocation(e));
    } catch {
      type = undefined;
    }
    if (type && !(type.flags & (ts.TypeFlags.Any | ts.TypeFlags.Unknown))) {
      // Unions like `HTMLElement | null` are reduced above; for other unions, use the first object member.
      const t = type.isUnionOrIntersection() ? type.types.find((x) => x.getSymbol()) ?? type : type;
      const sym = t.aliasSymbol ?? t.getSymbol();
      const decl = sym?.declarations?.[0];
      if (sym && decl && sym.name !== '__type' && sym.name !== '__object') {
        return { module: this.moduleOf(decl), name: sym.name, resolvedBy: 'type-checker' };
      }
    }
    return this.declaredOrigin(e);
  }

  /**
   * Project class an expression is an instance of, from its declaration when the
   * checker cannot infer it (e.g. `inject(Service)` while `@angular/core` is unresolved).
   */
  declaredClass(expression: ts.Expression): ts.ClassDeclaration | undefined {
    const classOf = (id: ts.Node | undefined) => {
      const d = id && this.symbolAt(id)?.declarations?.[0];
      return d && ts.isClassDeclaration(d) && this.isProjectNode(d) ? d : undefined;
    };
    const fromInit = (init: ts.Expression | undefined): ts.ClassDeclaration | undefined => {
      const e = init && skipOuter(init);
      if (!e) return undefined;
      if (ts.isCallExpression(e) && ts.isIdentifier(e.expression) && e.expression.text === 'inject' && e.arguments[0]) return classOf(skipOuter(e.arguments[0]));
      if (ts.isNewExpression(e)) return classOf(e.expression);
      return undefined;
    };
    const decl = this.declarationOf(expression);
    if (!decl) return undefined;
    if (ts.isParameter(decl) || ts.isPropertyDeclaration(decl) || ts.isVariableDeclaration(decl)) {
      if (decl.type && ts.isTypeReferenceNode(decl.type)) {
        const c = classOf(ts.isIdentifier(decl.type.typeName) ? decl.type.typeName : decl.type.typeName.right);
        if (c) return c;
      }
      if (!ts.isParameter(decl)) return fromInit(decl.initializer);
    }
    return undefined;
  }

  /** User-code function-like declaration a call targets, if any. */
  functionDeclaration(callee: ts.Expression): ts.SignatureDeclaration | undefined {
    let decl = this.declarationOf(callee);
    const c = skipOuter(callee);
    if (!decl && ts.isPropertyAccessExpression(c)) {
      const cls = this.declaredClass(c.expression);
      decl = cls?.members.find((m) => m.name && ts.isIdentifier(m.name) && m.name.text === c.name.text);
    }
    if (!decl || !this.isProjectNode(decl)) return undefined;
    if (isFunctionLike(decl)) return decl;
    if ((ts.isVariableDeclaration(decl) || ts.isPropertyDeclaration(decl) || ts.isPropertyAssignment(decl)) && decl.initializer) {
      const init = skipOuter(decl.initializer);
      if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) return init;
    }
    return undefined;
  }

  callee(call: ts.CallExpression | ts.NewExpression): CalleeInfo | undefined {
    const hit = this.calleeCache.get(call);
    if (hit !== undefined) return hit ?? undefined;
    const info = this.computeCallee(call);
    this.calleeCache.set(call, info ?? null);
    return info;
  }

  private computeCallee(call: ts.CallExpression | ts.NewExpression): CalleeInfo | undefined {
    const expr = skipOuter(call.expression);
    let name: string | undefined;
    let receiverExpr: ts.Expression | undefined;
    if (ts.isIdentifier(expr)) name = expr.text;
    else if (ts.isPropertyAccessExpression(expr)) {
      name = expr.name.text;
      receiverExpr = expr.expression;
    } else if (ts.isElementAccessExpression(expr)) {
      const arg = skipOuter(expr.argumentExpression);
      if (ts.isStringLiteralLike(arg)) name = arg.text;
      receiverExpr = expr.expression;
    }
    if (!name) return undefined;
    const info: CalleeInfo = { name };
    const declaration = this.functionDeclaration(expr);
    if (declaration) info.declaration = declaration;
    if (receiverExpr) {
      const receiver = this.typeOrigin(receiverExpr);
      if (receiver) info.receiver = receiver;
    } else if (ts.isIdentifier(expr)) {
      const imp = this.importOrigin(expr);
      if (imp) info.origin = imp;
      else {
        const decl = this.declarationOf(expr);
        if (decl) info.origin = { module: this.moduleOf(decl), name, resolvedBy: 'type-checker' };
      }
    }
    return info;
  }

  constantString(expression: ts.Expression, depth = 0): string | undefined {
    if (depth > 10) return undefined;
    const e = skipOuter(expression);
    if (ts.isStringLiteralLike(e)) return e.text;
    if (ts.isNumericLiteral(e)) return e.text;
    if (ts.isTemplateExpression(e)) {
      let out = e.head.text;
      for (const span of e.templateSpans) {
        const v = this.constantString(span.expression, depth + 1);
        if (v === undefined) return undefined;
        out += v + span.literal.text;
      }
      return out;
    }
    if (ts.isBinaryExpression(e) && e.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const l = this.constantString(e.left, depth + 1);
      const r = l === undefined ? undefined : this.constantString(e.right, depth + 1);
      return l !== undefined && r !== undefined ? l + r : undefined;
    }
    if (ts.isIdentifier(e) || ts.isPropertyAccessExpression(e) || ts.isElementAccessExpression(e)) {
      const decl = this.declarationOf(e);
      if (!decl) return undefined;
      if (ts.isVariableDeclaration(decl) && decl.initializer && ts.isVariableDeclarationList(decl.parent)
        && decl.parent.flags & ts.NodeFlags.Const) {
        return this.constantString(decl.initializer, depth + 1);
      }
      if (ts.isEnumMember(decl) && decl.initializer) return this.constantString(decl.initializer, depth + 1);
      if (ts.isPropertyAssignment(decl) && this.isConstObject(decl.parent)) return this.constantString(decl.initializer, depth + 1);
      if (ts.isPropertyDeclaration(decl) && decl.initializer
        && decl.modifiers?.some((m) => m.kind === ts.SyntaxKind.ReadonlyKeyword)) {
        return this.constantString(decl.initializer, depth + 1);
      }
    }
    return undefined;
  }

  private isConstObject(obj: ts.Node): boolean {
    // `const X = { ... }` or `{ ... } as const` objects whose properties are never reassigned in practice.
    let p: ts.Node = obj.parent;
    while (ts.isAsExpression(p) || ts.isSatisfiesExpression(p) || ts.isParenthesizedExpression(p)) p = p.parent;
    return ts.isVariableDeclaration(p) && ts.isVariableDeclarationList(p.parent) && !!(p.parent.flags & ts.NodeFlags.Const);
  }

  propertyNames(expression: ts.Expression): string[] {
    try {
      const type = this.checker.getTypeAtLocation(skipOuter(expression));
      if (type.flags & (ts.TypeFlags.Any | ts.TypeFlags.Unknown)) return [];
      return this.checker.getApparentType(type).getProperties().map((p) => p.name);
    } catch {
      return [];
    }
  }
}

/** True when `origin` names `name` declared by one of `modules`. */
export function originIs(origin: TypeOrigin | undefined, modules: string | readonly string[], ...names: string[]): boolean {
  if (!origin) return false;
  const mods = typeof modules === 'string' ? [modules] : modules;
  return mods.some((m) => moduleMatches(origin, m)) && names.includes(origin.name);
}

/**
 * Import specifiers name entry points (`@angular/common/http`); the TypeChecker
 * only knows the package a declaration file lives in (`@angular/common`).
 */
export function moduleMatches(origin: TypeOrigin, module: string): boolean {
  return origin.module === module || (origin.resolvedBy === 'type-checker' && module.startsWith(`${origin.module}/`));
}
