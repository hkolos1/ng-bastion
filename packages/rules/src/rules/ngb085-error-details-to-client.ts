import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding, type Severity } from '@ngbastion/plugin-api';
import { memberName, receiverOf, strip } from '../shared/common.js';
import { responseCall } from '../shared/server.js';

const RESPONSE_METHODS = ['send', 'json', 'jsonp', 'end', 'write', 'render'];
const ERROR_NAME = /^(e|err|error|ex|exc|exception|reason)$/i;
const DEV_ONLY = /NODE_ENV|isDev|isDevelopment|development|debug|isProduction|production/i;

/** Whether an identifier is an error value: catch variable, Express error-handler `err`, `.catch()` / Node-callback error parameter. */
function isErrorBinding(ctx: AnalysisContext, id: ts.Identifier): boolean {
  const t = ctx.ts;
  const d = ctx.symbols.declarationOf(id);
  if (!d) return false;
  if (t.isVariableDeclaration(d) && t.isCatchClause(d.parent)) return true;
  if (!t.isParameter(d) || !t.isFunctionLike(d.parent)) return false;
  const fn = d.parent;
  const i = fn.parameters.indexOf(d);
  // Express error middleware: (err, req, res, next)
  if (i === 0 && fn.parameters.length === 4) return true;
  // promise.catch(err => …), promise.then(ok, err => …)
  const call = fn.parent;
  if (i === 0 && t.isCallExpression(call)) {
    const m = memberName(ctx, call.expression);
    if (m === 'catch' && call.arguments[0] === fn) return true;
    if (m === 'then' && call.arguments[1] === fn) return true;
    // Node-style callback: fs.readFile(p, (err, data) => …)
    if (ERROR_NAME.test(id.text) && call.arguments[call.arguments.length - 1] === fn && fn.parameters.length >= 1) return true;
  }
  return false;
}

interface Leak { what: 'stack' | 'object' | 'message'; text: string }

/** Error details embedded in a response value (direct, in object literals, templates, concatenation, String()/JSON.stringify()). */
function leaks(ctx: AnalysisContext, expr: ts.Expression, depth = 0): Leak[] {
  const t = ctx.ts;
  if (depth > 4) return [];
  const e = strip(ctx, expr);
  if (t.isIdentifier(e)) return isErrorBinding(ctx, e) ? [{ what: 'object', text: e.text }] : [];
  if (t.isPropertyAccessExpression(e) || t.isElementAccessExpression(e)) {
    const obj = strip(ctx, e.expression);
    const name = memberName(ctx, e);
    if (t.isIdentifier(obj) && isErrorBinding(ctx, obj)) {
      if (name === 'stack') return [{ what: 'stack', text: e.getText() }];
      if (name === 'message' || name === 'sqlMessage' || name === 'sql') return [{ what: name === 'message' ? 'message' : 'object', text: e.getText() }];
    }
    return [];
  }
  if (t.isObjectLiteralExpression(e)) {
    return e.properties.flatMap((p) => t.isPropertyAssignment(p) ? leaks(ctx, p.initializer, depth + 1) : t.isShorthandPropertyAssignment(p) ? leaks(ctx, p.name, depth + 1) : t.isSpreadAssignment(p) ? leaks(ctx, p.expression, depth + 1) : []);
  }
  if (t.isTemplateExpression(e)) return e.templateSpans.flatMap((s) => leaks(ctx, s.expression, depth + 1));
  if (t.isBinaryExpression(e) && e.operatorToken.kind === t.SyntaxKind.PlusToken) return [...leaks(ctx, e.left, depth + 1), ...leaks(ctx, e.right, depth + 1)];
  if (t.isCallExpression(e)) {
    const callee = strip(ctx, e.expression);
    const name = t.isIdentifier(callee) ? callee.text : memberName(ctx, callee);
    if ((name === 'String' || name === 'stringify' || name === 'inspect' || name === 'format') && e.arguments[0]) return leaks(ctx, e.arguments[0], depth + 1);
    if (name === 'toString' && t.isPropertyAccessExpression(callee)) return leaks(ctx, callee.expression, depth + 1);
  }
  return [];
}

export const ngb085 = defineRule({
  meta: {
    id: 'NGB085',
    name: 'Error details sent to clients',
    category: 'ssr',
    defaultSeverity: 'medium',
    cwe: ['CWE-209', 'CWE-497'],
    docs: {
      description:
        "Reports server code (Express / Node SSR servers, API routes) that sends a caught error to the HTTP client: the stack trace, the raw error object, or its message, in `res.send()`, `res.json()`, `res.end()`, `res.write()`, `res.render()` (also after `res.status(500)`). Errors come from `catch` clauses, Express error middleware `(err, req, res, next)`, promise `.catch()` handlers and Node-style `(err, …)` callbacks.",
      rationale:
        'Stack traces reveal file paths, framework and library versions, and internal function names; driver errors carry SQL statements, table names, hostnames and sometimes connection strings or user data. Attackers use these details to fingerprint the server and to tune injection payloads. Express itself hides stacks in production — sending `err.stack` manually bypasses that.',
      patterns: [
        '`res.status(500).send(err.stack)`, `res.json({ error: err })`, `res.send(`Failed: ${err}`)`, `res.end(String(error))` — stack: medium severity; raw error object / driver `sql` / `sqlMessage`: medium; `err.message`: low',
        'Error values: `catch (e)`, the first parameter of 4-parameter Express error middleware, `.catch(err => …)`, `.then(_, err => …)`, last-argument Node callbacks `(err, data) => …`',
        'Responses guarded by a development check (`NODE_ENV`, `isDev`, `debug`) are not reported',
        'Response objects: Express `Response`, Node `ServerResponse`, and untyped `res` parameters next to `req`',
      ],
      limitations: [
        'Errors copied into other variables or wrapped in custom error classes before sending are not followed.',
        'Error details rendered by frameworks other than Express / Node `http` (Fastify reply, NestJS exception filters) are not analyzed.',
        'Whether `err.message` is safe depends on where the error was thrown; it is reported with low severity.',
      ],
      falsePositives: [
        'Validation errors whose message is written for users (`throw new ValidationError("Email is required")`) are reported when sent as `err.message`; return a curated message or an error code instead.',
      ],
      remediation:
        'Log the full error on the server (with a correlation ID) and send a generic message: `res.status(500).json({ error: "Internal error", id })`. Map expected errors to explicit, user-safe messages.',
      example: {
        unsafe: "app.use((err, req, res, next) => res.status(500).send(err.stack));",
        safe: "app.use((err, req, res, next) => {\n  logger.error({ err, id: req.id });\n  res.status(500).json({ error: 'Internal server error', id: req.id });\n});",
      },
      references: [
        { title: 'OWASP — Error Handling Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html' },
        { title: 'Express — Error handling (production stack traces)', url: 'https://expressjs.com/en/guide/error-handling.html' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const call of ctx.index.calls) {
      if (!responseCall(ctx, call, RESPONSE_METHODS)) continue;
      // res.render(view, locals): the view name is not data.
      const args = memberName(ctx, call.expression) === 'render' ? call.arguments.slice(1) : call.arguments;
      const found = args.flatMap((a) => leaks(ctx, a));
      if (!found.length) continue;
      if (ctx.flow.guards(call).some((g) => DEV_ONLY.test(g.condition.getText()))) continue;
      const worst = found.find((l) => l.what === 'stack') ?? found.find((l) => l.what === 'object') ?? found[0]!;
      const severity: Severity = worst.what === 'message' ? 'low' : 'medium';
      const recv = receiverOf(ctx, strip(ctx, call.expression));
      findings.push({
        node: call,
        message: worst.what === 'stack'
          ? `The error stack trace (${worst.text}) is sent to the client; it reveals file paths, library versions and internal structure.`
          : worst.what === 'object'
            ? `The raw error (${worst.text}) is sent to the client; driver and library errors can contain queries, hostnames and internal details.`
            : `The internal error message (${worst.text}) is sent to the client; return a generic message and log the details server-side.`,
        confidence: worst.what === 'stack' ? 'high' : 'medium',
        severity,
        evidenceKind: 'pattern',
        evidence: [`response: ${recv?.getText().slice(0, 40) ?? 'res'}.${memberName(ctx, call.expression)}()`, ...found.slice(0, 3).map((l) => `error detail: ${l.text}`)],
      });
    }
    return findings;
  },
});
