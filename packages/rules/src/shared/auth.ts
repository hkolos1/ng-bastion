import type * as ts from 'typescript';
import type { AnalysisContext } from '@ngbastion/plugin-api';
import { strip } from './common.js';

export interface AuthSignals {
  /** `withCredentials: true` / `credentials: 'include'` somewhere in the project. */
  cookieCredentials: ts.Node[];
  /** An `Authorization` / bearer header is attached somewhere in the project. */
  bearerHeaders: ts.Node[];
}

const cache = new WeakMap<object, AuthSignals>();

/** Project-wide hints about how requests authenticate (cookies vs. bearer headers). */
export function authSignals(ctx: AnalysisContext): AuthSignals {
  const hit = cache.get(ctx.program);
  if (hit) return hit;
  const t = ctx.ts;
  const out: AuthSignals = { cookieCredentials: [], bearerHeaders: [] };
  for (const sf of ctx.sourceFiles) {
    const visit = (n: ts.Node): void => {
      if (t.isPropertyAssignment(n) && (t.isIdentifier(n.name) || t.isStringLiteralLike(n.name))) {
        const key = n.name.text;
        const v = strip(ctx, n.initializer);
        if (key === 'withCredentials' && v.kind === t.SyntaxKind.TrueKeyword) out.cookieCredentials.push(n);
        if (key === 'credentials' && ctx.symbols.constantString(v) === 'include') out.cookieCredentials.push(n);
        if (/^authorization$/i.test(key)) out.bearerHeaders.push(n);
      }
      if (t.isCallExpression(n) && n.arguments[0] && t.isStringLiteralLike(n.arguments[0]) && /^authorization$/i.test(n.arguments[0].text)) out.bearerHeaders.push(n);
      t.forEachChild(n, visit);
    };
    visit(sf);
  }
  cache.set(ctx.program, out);
  return out;
}

/** Cookie names that typically carry a session or authentication credential. */
export function authCookieName(name: string): boolean {
  const n = name.toLowerCase();
  if (/(csrf|xsrf)/.test(n)) return false;
  return /^(__host-|__secure-)?(sid|sess|session|sessionid|session[-_]?id|connect\.sid|auth|auth[-_]?token|access[-_]?token|refresh[-_]?token|id[-_]?token|jwt|token|remember[-_]?me|jsessionid|phpsessid|asp\.net_sessionid)$/.test(n);
}
