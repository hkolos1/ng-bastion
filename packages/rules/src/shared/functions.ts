import type * as ts from 'typescript';
import type { AnalysisContext } from '@ngbastion/plugin-api';
import { memberName, strip } from './common.js';

/** Return statements of a function body, not descending into nested functions. */
export function returns(ctx: AnalysisContext, fn: ts.SignatureDeclaration): ts.Expression[] {
  const t = ctx.ts;
  const out: ts.Expression[] = [];
  const body = (fn as { body?: ts.Node }).body;
  if (!body) return out;
  if (!t.isBlock(body)) return [body as ts.Expression];
  const visit = (n: ts.Node): void => {
    if (t.isFunctionLike(n)) return;
    if (t.isReturnStatement(n) && n.expression) out.push(n.expression);
    t.forEachChild(n, visit);
  };
  t.forEachChild(body, visit);
  return out;
}

/** The returned expression is the `value` parameter itself (possibly cast / stringified). */
export function isParam(ctx: AnalysisContext, e: ts.Expression, param: ts.ParameterDeclaration): boolean {
  const t = ctx.ts;
  let x = strip(ctx, e);
  for (let i = 0; i < 3; i++) {
    if (t.isCallExpression(x)) {
      const c = strip(ctx, x.expression);
      if (t.isIdentifier(c) && c.text === 'String' && x.arguments[0]) x = strip(ctx, x.arguments[0]);
      else if (memberName(ctx, c) === 'toString' && t.isPropertyAccessExpression(c)) x = strip(ctx, c.expression);
      else break;
    } else if (t.isBinaryExpression(x) && x.operatorToken.kind === t.SyntaxKind.QuestionQuestionToken) x = strip(ctx, x.left);
    else break;
  }
  return t.isIdentifier(x) && ctx.symbols.declarationOf(x) === param;
}
