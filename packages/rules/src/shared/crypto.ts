import type * as ts from 'typescript';
import type { AnalysisContext } from '@ngbastion/plugin-api';
import { memberName, strip } from './common.js';

/**
 * Whether `e` is fixed at build time: string constants, `TextEncoder().encode('…')`,
 * `Buffer.from('…')`, `new Uint8Array([1, 2, …])`, `Uint8Array.from([...])`, zero-filled buffers,
 * and `const` variables holding one of these.
 */
export function constantBytes(ctx: AnalysisContext, e: ts.Expression, depth = 0): boolean {
  const t = ctx.ts;
  const x = strip(ctx, e);
  if (depth > 4) return false;
  if (ctx.symbols.constantString(x) !== undefined) return true;
  if (t.isArrayLiteralExpression(x)) return x.elements.length > 0 && x.elements.every((el) => t.isNumericLiteral(strip(ctx, el)));
  if (t.isNewExpression(x) && t.isIdentifier(x.expression) && /^(Uint8Array|Int8Array|ArrayBuffer|Uint16Array|Uint32Array)$/.test(x.expression.text)) {
    const a = x.arguments?.[0];
    if (!a || t.isNumericLiteral(strip(ctx, a))) return true;
    return constantBytes(ctx, a, depth + 1);
  }
  if (t.isCallExpression(x)) {
    const name = memberName(ctx, x.expression) ?? (t.isIdentifier(x.expression) ? x.expression.text : '');
    if (['encode', 'from', 'of', 'parse'].includes(name) && x.arguments[0]) {
      // CryptoJS.enc.Utf8.parse('k'), Buffer.from('k', 'hex'), new TextEncoder().encode('k')
      return x.arguments.slice(0, name === 'of' ? undefined : 1).every((a) => constantBytes(ctx, a, depth + 1));
    }
    return false;
  }
  if (t.isIdentifier(x)) {
    const d = ctx.symbols.declarationOf(x);
    if (d && t.isVariableDeclaration(d) && d.initializer && t.isVariableDeclarationList(d.parent) && d.parent.flags & t.NodeFlags.Const) return constantBytes(ctx, d.initializer, depth + 1);
  }
  return false;
}
