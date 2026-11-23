import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { memberName, receiverOf, strip } from '../shared/common.js';
import { objectLiteral } from '../shared/http.js';
import { moduleCall } from '../shared/server.js';
import { flowFinding, SERVER_SOURCE, taintedFlow, type TaintedValue } from '../shared/server-flow.js';

const MONGO = ['mongoose', 'mongodb'];
const QUERY_METHODS = [
  'find', 'findOne', 'findOneAndUpdate', 'findOneAndDelete', 'findOneAndRemove', 'findOneAndReplace', 'updateOne', 'updateMany',
  'deleteOne', 'deleteMany', 'replaceOne', 'countDocuments', 'count', 'exists', 'distinct', 'where',
];
/**
 * Request values that can be objects: JSON / urlencoded bodies, `qs`-parsed query strings
 * (`?user[$ne]=x`) and JSON cookies. Route params, paths and headers are always strings.
 */
const OBJECT_CAPABLE = /^server request (body|query|cookies)/;
/** Conversions and sanitizers that turn the value into a primitive or strip `$` operators. */
const SAFE_STEP = /\b(String|Number|parseInt|parseFloat|Boolean|toString|sanitize\w*|mongoSanitize|escape\w*)\(\)/;

function importsMongo(sf: ts.SourceFile): boolean {
  return /(from\s+|require\(\s*)['"](mongoose|mongodb)['"]/.test(sf.text);
}

function queryCall(ctx: AnalysisContext, call: ts.CallExpression): string | undefined {
  const callee = strip(ctx, call.expression);
  const name = memberName(ctx, callee);
  const recv = receiverOf(ctx, callee);
  if (!name || !recv || !QUERY_METHODS.includes(name)) return undefined;
  const info = ctx.symbols.callee(call);
  if (info?.declaration) return undefined;
  const o = info?.receiver ?? ctx.symbols.typeOrigin(recv);
  if (o && MONGO.includes(o.module)) return name;
  // Typed receivers from other libraries (arrays, Maps, ORMs) are not MongoDB; project types fall through.
  if (o && o.name !== 'any' && !o.module.startsWith('/')) return undefined;
  return importsMongo(call.getSourceFile()) ? name : undefined;
}

/** A conversion visible at the use site or in the `const` initializer: `String(x)`, `` `${x}` ``, `x + ''`. */
function primitive(ctx: AnalysisContext, e: ts.Expression, depth = 0): boolean {
  const t = ctx.ts;
  const x = strip(ctx, e);
  if (t.isTemplateExpression(x) || t.isNoSubstitutionTemplateLiteral(x) || t.isStringLiteral(x) || t.isNumericLiteral(x)) return true;
  if (t.isBinaryExpression(x) && x.operatorToken.kind === t.SyntaxKind.PlusToken) return true;
  if (t.isCallExpression(x)) {
    const c = strip(ctx, x.expression);
    const n = t.isIdentifier(c) ? c.text : memberName(ctx, c);
    if (n && /^(String|Number|parseInt|parseFloat|Boolean|toString|sanitize\w*|escape\w*)$/.test(n)) return true;
  }
  if (t.isIdentifier(x) && depth < 3) {
    const d = ctx.symbols.declarationOf(x);
    if (d && t.isVariableDeclaration(d) && d.initializer) return primitive(ctx, d.initializer, depth + 1);
  }
  return false;
}

/** Whether the project applies `express-mongo-sanitize` (strips `$` / `.` keys from body, query, params). */
function globalSanitizer(ctx: AnalysisContext): boolean {
  return ctx.index.calls.some((c) => !!moduleCall(ctx, c, ['express-mongo-sanitize', 'mongo-sanitize'], ['default', 'sanitize', 'mongoSanitize']) || /^mongoSanitize$/.test(strip(ctx, c.expression).getText()));
}

export const ngb080 = defineRule({
  meta: {
    id: 'NGB080',
    name: 'NoSQL injection in server code',
    category: 'ssr',
    defaultSeverity: 'high',
    cwe: ['CWE-943'],
    docs: {
      description:
        "Reports MongoDB / Mongoose queries in server code whose filter takes request values that can be objects — the request body, `qs`-parsed query strings and JSON cookies — without converting them to a primitive: `User.findOne({ email: req.body.email })`, `collection.find(req.query)`, and any `$where` built from request data.",
      rationale:
        'Express parses `?password[$ne]=x` and JSON bodies into objects. Passed into a query filter, `{ "$ne": null }` matches every document: login checks are bypassed and records of other users are returned or modified (operator injection). `$where` evaluates JavaScript on the database server.',
      patterns: [
        "`Model.find/findOne/updateOne/deleteMany/findOneAndUpdate/countDocuments/exists …(filter)` on Mongoose models or MongoDB collections (typed receivers, or files importing `mongoose` / `mongodb`)",
        'The whole filter from request data (`find(req.body)`) or a top-level filter property from request body / query / cookies (high)',
        '`$where` with request data in its value (critical)',
        'Not reported: `String(x)` / `Number(x)` / template literals / `x + ""` (at the use or in the `const` initializer), `mongo-sanitize`, an applied `express-mongo-sanitize` middleware, nested operator objects such as `{ email: { $eq: v } }`, route params and headers (always strings)',
      ],
      limitations: [
        'Only filters written as object literals (or passed whole) at the call are inspected; filters assembled elsewhere are traced only as a whole.',
        'Schema-level casting (Mongoose casts to the schema type for many paths, and `sanitizeFilter`) is not evaluated — such queries are reported with the same confidence.',
        'Validation libraries (zod, class-validator, joi) applied in middleware are not recognized.',
      ],
      falsePositives: [
        'Requests validated by a schema middleware that guarantees strings are reported; add an explicit `String()` conversion or document an exception.',
        'Mongoose `sanitizeFilter: true` makes operator injection ineffective for that query or connection.',
      ],
      remediation:
        "Convert request values to the expected primitive (`String(req.body.email)`), validate the request schema, wrap untrusted values in `{ $eq: value }`, enable Mongoose `sanitizeFilter` or apply `express-mongo-sanitize`. Never build `$where` from request data.",
      example: {
        unsafe: 'const user = await User.findOne({ email: req.body.email, password: req.body.password });',
        safe: 'const user = await User.findOne({ email: String(req.body.email) });\nconst ok = user && await bcrypt.compare(String(req.body.password), user.passwordHash);',
      },
      references: [
        { title: 'OWASP WSTG — Testing for NoSQL Injection', url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection' },
        { title: 'Mongoose — sanitizeFilter', url: 'https://mongoosejs.com/docs/api/mongoose.html#Mongoose.prototype.sanitizeFilter()' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    if (globalSanitizer(ctx)) return findings;
    const objectFlow = (e: ts.Expression): TaintedValue | undefined => (primitive(ctx, e) ? undefined
      : taintedFlow(ctx, e, { sanitizers: SAFE_STEP, skip: (f) => !OBJECT_CAPABLE.test(f.source.description) }));
    for (const call of ctx.index.calls) {
      const method = queryCall(ctx, call);
      const filter = call.arguments[0];
      if (!method || !filter) continue;
      const lit = objectLiteral(ctx, filter);
      if (!lit) {
        const tv = objectFlow(filter);
        if (tv) findings.push(flowFinding(ctx, call, tv, `${method}() filter`, `The whole ${method}() filter comes from request data (${tv.flow.source.description}); clients can send MongoDB operators such as {"$ne": null} or {"$where": …}.`));
        continue;
      }
      for (const p of lit.properties) {
        if (!ctx.ts.isPropertyAssignment(p) && !ctx.ts.isShorthandPropertyAssignment(p)) continue;
        const key = p.name && (ctx.ts.isIdentifier(p.name) || ctx.ts.isStringLiteralLike(p.name)) ? p.name.text : '?';
        const value = ctx.ts.isPropertyAssignment(p) ? p.initializer : p.name;
        if (key === '$where') {
          const tv = taintedFlow(ctx, value, { context: 'code', skip: (f) => !SERVER_SOURCE.test(f.source.description) });
          if (tv) findings.push(flowFinding(ctx, call, tv, `${method}() $where`, `Request data (${tv.flow.source.description}) is evaluated as JavaScript by MongoDB through $where.`, { severity: 'critical' }));
          continue;
        }
        if (key.startsWith('$') || ctx.ts.isObjectLiteralExpression(strip(ctx, value))) continue;
        const tv = objectFlow(value);
        if (!tv) continue;
        findings.push(flowFinding(ctx, call, tv, `${method}() filter property '${key}'`, `Filter property '${key}' of ${method}() takes ${tv.flow.source.description} unconverted; an object such as {"$ne": null} turns the equality check into an operator (NoSQL injection).`));
        break;
      }
    }
    return findings;
  },
});
