import ts from 'typescript';
import type { FlowHelpers, Guard } from '@ngbastion/plugin-api';
import type { Symbols } from './symbols.js';
import { isFunctionLike, skipOuter } from './util.js';

function alwaysExits(stmt: ts.Statement): boolean {
  if (ts.isReturnStatement(stmt) || ts.isThrowStatement(stmt) || ts.isContinueStatement(stmt) || ts.isBreakStatement(stmt)) return true;
  if (ts.isBlock(stmt)) {
    const last = stmt.statements[stmt.statements.length - 1];
    return !!last && alwaysExits(last);
  }
  if (ts.isIfStatement(stmt)) return !!stmt.elseStatement && alwaysExits(stmt.thenStatement) && alwaysExits(stmt.elseStatement);
  return false;
}

export class Flow implements FlowHelpers {
  constructor(private readonly symbols: Symbols) {}

  enclosingFunction(node: ts.Node): ts.SignatureDeclaration | undefined {
    for (let p = node.parent; p; p = p.parent) if (isFunctionLike(p)) return p;
    return undefined;
  }

  guards(node: ts.Node): Guard[] {
    const out: Guard[] = [];
    let child: ts.Node = node;
    for (let p = node.parent; p && !isFunctionLike(child); child = p, p = p.parent) {
      if (ts.isIfStatement(p) && child !== p.expression) {
        out.push({ condition: p.expression, whenTrue: child === p.thenStatement, kind: 'if' });
      } else if (ts.isConditionalExpression(p) && child !== p.condition) {
        out.push({ condition: p.condition, whenTrue: child === p.whenTrue, kind: 'conditional' });
      } else if (ts.isBinaryExpression(p) && child === p.right) {
        if (p.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) out.push({ condition: p.left, whenTrue: true, kind: 'logical' });
        if (p.operatorToken.kind === ts.SyntaxKind.BarBarToken) out.push({ condition: p.left, whenTrue: false, kind: 'logical' });
      }
      if (ts.isBlock(p) || ts.isSourceFile(p) || ts.isCaseClause(p) || ts.isDefaultClause(p)) {
        const stmts: readonly ts.Statement[] = p.statements;
        const idx = stmts.indexOf(child as ts.Statement);
        for (let i = idx - 1; i >= 0; i--) {
          const s = stmts[i]!;
          if (ts.isIfStatement(s) && !s.elseStatement && alwaysExits(s.thenStatement)) {
            out.push({ condition: s.expression, whenTrue: false, kind: 'early-exit' });
          }
        }
      }
      if (isFunctionLike(p)) break;
    }
    return out;
  }

  resolveFunction(expression: ts.Expression): ts.SignatureDeclaration | undefined {
    let e = skipOuter(expression);
    // handler.bind(this)
    if (ts.isCallExpression(e) && ts.isPropertyAccessExpression(e.expression) && e.expression.name.text === 'bind') {
      e = skipOuter(e.expression.expression);
    }
    if (ts.isArrowFunction(e) || ts.isFunctionExpression(e)) return e;
    if (ts.isIdentifier(e) || ts.isPropertyAccessExpression(e)) return this.symbols.functionDeclaration(e);
    return undefined;
  }
}
