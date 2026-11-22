import ts from 'typescript';
import type { SourceLocation } from '@ngbastion/plugin-api';

export function locationOf(node: ts.Node, sf: ts.SourceFile = node.getSourceFile()): SourceLocation {
  const start = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  const end = sf.getLineAndCharacterOfPosition(node.getEnd());
  return { file: sf.fileName, line: start.line + 1, column: start.character + 1, endLine: end.line + 1, endColumn: end.character + 1 };
}

export function locationAt(sf: ts.SourceFile, startPos: number, endPos: number): SourceLocation {
  const s = sf.getLineAndCharacterOfPosition(startPos);
  const e = sf.getLineAndCharacterOfPosition(endPos);
  return { file: sf.fileName, line: s.line + 1, column: s.character + 1, endLine: e.line + 1, endColumn: e.character + 1 };
}

/** Removes syntax that does not change a value: parentheses, type assertions, `!`, `satisfies`. */
export function skipOuter(expr: ts.Expression): ts.Expression {
  let e = expr;
  for (;;) {
    if (ts.isParenthesizedExpression(e) || ts.isAsExpression(e) || ts.isNonNullExpression(e)
      || ts.isTypeAssertionExpression(e) || ts.isSatisfiesExpression(e)) {
      e = e.expression;
    } else return e;
  }
}

/** Property name of `a.b`, `a['b']` or `a?.b`; undefined for computed non-literal keys. */
export function memberName(expr: ts.Expression): string | undefined {
  const e = skipOuter(expr);
  if (ts.isPropertyAccessExpression(e)) return e.name.text;
  if (ts.isElementAccessExpression(e)) {
    const arg = skipOuter(e.argumentExpression);
    if (ts.isStringLiteralLike(arg) || ts.isNumericLiteral(arg)) return arg.text;
  }
  return undefined;
}

export function memberObject(expr: ts.Expression): ts.Expression | undefined {
  const e = skipOuter(expr);
  if (ts.isPropertyAccessExpression(e) || ts.isElementAccessExpression(e)) return e.expression;
  return undefined;
}

export function isFunctionLike(node: ts.Node): node is ts.SignatureDeclaration & { body?: ts.ConciseBody | ts.Block } {
  return ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node) || ts.isArrowFunction(node)
    || ts.isFunctionExpression(node) || ts.isConstructorDeclaration(node) || ts.isGetAccessorDeclaration(node)
    || ts.isSetAccessorDeclaration(node);
}

/** Collects return expressions of a function (concise arrow body counts as one), skipping nested functions. */
export function returnExpressions(fn: ts.SignatureDeclaration): ts.Expression[] {
  const body = (fn as { body?: ts.Node }).body;
  if (!body) return [];
  if (!ts.isBlock(body)) return [body as ts.Expression];
  const out: ts.Expression[] = [];
  const walk = (n: ts.Node): void => {
    if (isFunctionLike(n) || ts.isClassLike(n)) return;
    if (ts.isReturnStatement(n) && n.expression) out.push(n.expression);
    ts.forEachChild(n, walk);
  };
  ts.forEachChild(body, walk);
  return out;
}

export function nameOf(node: ts.Node | undefined): string | undefined {
  if (!node) return undefined;
  const n = (node as { name?: ts.Node }).name;
  if (n && (ts.isIdentifier(n) || ts.isPrivateIdentifier(n) || ts.isStringLiteral(n))) return n.text;
  return undefined;
}

/** Short source text for messages (single line, truncated). */
export function shortText(node: ts.Node, max = 60): string {
  const t = node.getText().replace(/\s+/g, ' ').trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

export function packageOfFile(fileName: string): string | undefined {
  const norm = fileName.replace(/\\/g, '/');
  if (/\/typescript\/lib\/lib\.dom(\.iterable|\.asynciterable)?\.d\.ts$/.test(norm)) return 'dom';
  if (/\/typescript\/lib\/lib\.[^/]+\.d\.ts$/.test(norm)) return 'lib';
  const all = [...norm.matchAll(/\/node_modules\/((?:@[^/]+\/)?[^/]+)\//g)].filter((m) => m[1] !== '.pnpm');
  return all.length ? all[all.length - 1]![1] : undefined;
}

export const ASSIGNMENT_OPERATORS = new Set([
  ts.SyntaxKind.EqualsToken,
  ts.SyntaxKind.PlusEqualsToken,
  ts.SyntaxKind.QuestionQuestionEqualsToken,
  ts.SyntaxKind.BarBarEqualsToken,
  ts.SyntaxKind.AmpersandAmpersandEqualsToken,
]);
