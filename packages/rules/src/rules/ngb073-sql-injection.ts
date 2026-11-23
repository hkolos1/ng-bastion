import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { memberName, receiverOf, strip } from '../shared/common.js';
import { urlParts } from '../shared/http.js';
import { flowFinding, taintedFlow, type TaintedValue } from '../shared/server-flow.js';

/** Packages whose clients execute raw SQL strings. */
const SQL_MODULES = ['pg', 'pg-pool', 'mysql', 'mysql2', 'mysql2/promise', 'sqlite3', 'sqlite', 'better-sqlite3', 'mssql', 'tedious', 'oracledb', 'knex', 'sequelize', 'typeorm', '@prisma/client', 'postgres', '@neondatabase/serverless', '@vercel/postgres', 'kysely', 'drizzle-orm', 'mariadb'];
/** Raw-SQL entry points whose names are specific enough to match without types. */
const RAW_METHODS = ['$queryRawUnsafe', '$executeRawUnsafe', 'whereRaw', 'orWhereRaw', 'havingRaw', 'orderByRaw', 'groupByRaw', 'joinRaw', 'fromRaw', 'selectRaw', 'unsafe'];
/** Generic names; only on receivers of an SQL package type, or db-named receivers in files that import one. */
const QUERY_METHODS = ['query', 'execute', 'raw', 'exec', 'run', 'all', 'get', 'prepare', 'each', 'queryOne', 'many', 'one', 'none', 'any', 'oneOrNone', 'manyOrNone'];
const DB_NAME = /^(db|database|pool|client|conn|connection|knex|sequelize|sql|pg|mysql|sqlite|dataSource|manager|entityManager|queryRunner|prisma|trx|tx|transaction)$/i;
/** Escaping helpers of SQL drivers (`mysql.escape`, `pg-format`, `sqlstring`). */
const ESCAPE = /\b(escape|escapeId|escapeLiteral|escapeIdentifier|format|quoteIdent|quoteLiteral|sqlstring)\w*\(\)/i;

function importsSqlModule(sf: ts.SourceFile): boolean {
  return new RegExp(`(from\\s+|require\\(\\s*)['"](${SQL_MODULES.map((m) => m.replace(/[/$.]/g, '\\$&')).join('|')})['"]`).test(sf.text);
}

function sqlCall(ctx: AnalysisContext, call: ts.CallExpression): string | undefined {
  const callee = strip(ctx, call.expression);
  const name = memberName(ctx, callee);
  const recv = receiverOf(ctx, callee);
  if (!name || !recv) return undefined;
  const info = ctx.symbols.callee(call);
  if (info?.declaration) return undefined;
  if (RAW_METHODS.includes(name)) return name;
  if (!QUERY_METHODS.includes(name)) return undefined;
  const o = info?.receiver ?? ctx.symbols.typeOrigin(recv);
  if (o && SQL_MODULES.some((m) => o.module === m || o.module.startsWith(`${m}/`))) return name;
  const r = strip(ctx, recv);
  const recvName = ctx.ts.isIdentifier(r) ? r.text : memberName(ctx, r);
  return recvName && DB_NAME.test(recvName) && importsSqlModule(call.getSourceFile()) ? name : undefined;
}

export const ngb073 = defineRule({
  meta: {
    id: 'NGB073',
    name: 'SQL injection in server code',
    category: 'ssr',
    defaultSeverity: 'critical',
    cwe: ['CWE-89'],
    docs: {
      description:
        "Traces request data (Express / Node query, params, body, cookies, headers) into SQL text executed by server code — SSR servers, BFFs and API routes in the workspace: `query()` / `execute()` / `raw()` … on clients of `pg`, `mysql` / `mysql2`, `sqlite3` / `better-sqlite3`, `mssql`, `knex`, `sequelize`, `typeorm` and Prisma's `$queryRawUnsafe()` / `$executeRawUnsafe()`. Only the SQL string argument is checked; bound parameters are safe.",
      rationale:
        'Concatenating or interpolating request values into SQL lets an attacker change the statement: read other users\' rows, bypass login checks, modify or drop data. Parameterized queries keep data out of the SQL grammar and are supported by every driver.',
      patterns: [
        "`db.query(`SELECT … ${req.query.id}`)`, `pool.query('… ' + req.body.name)`, `connection.execute(sql)` where `sql` is built from request data (receivers typed as an SQL package, or named `db` / `pool` / `client` / `connection` / `knex` … in files that import one)",
        "`knex.raw(…)`, `.whereRaw(…)`, `.orderByRaw(…)`, `sequelize.query(…)`, `dataSource.query(…)`, `prisma.$queryRawUnsafe(…)`, `sql.unsafe(…)` with request data in the SQL text",
        'Not reported: placeholders with bound values (`query("… WHERE id = $1", [id])`), tagged templates (`sql`…``, `prisma.$queryRaw`…``), values passed through an escaping helper (`mysql.escape()`, `pg-format`) or numeric conversion',
      ],
      limitations: [
        'ORM query builders with object conditions are not analyzed (they parameterize values).',
        'SQL assembled in helper functions is followed only as far as the taint engine follows the flow; dynamic identifiers (table / column names) validated by an allowlist are still reported.',
      ],
      falsePositives: [
        'A column name chosen from request data but checked against an allowlist in a separate function is reported; inline the check or document an exception.',
      ],
      remediation:
        'Use placeholders and pass values separately (`$1` / `?` with a values array, Prisma `$queryRaw` tagged templates, knex bindings). Choose dynamic identifiers (sort column, direction) from a fixed map instead of inserting the request value.',
      example: {
        unsafe: "await pool.query(`SELECT * FROM orders WHERE customer = '${req.query.customer}'`);",
        safe: "await pool.query('SELECT * FROM orders WHERE customer = $1', [req.query.customer]);",
      },
      references: [
        { title: 'OWASP — SQL Injection Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html' },
        { title: 'node-postgres — Parameterized queries', url: 'https://node-postgres.com/features/queries#parameterized-query' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const call of ctx.index.calls) {
      const method = sqlCall(ctx, call);
      const sql = call.arguments[0];
      if (!method || !sql) continue;
      // Trace the dynamic parts of the SQL text separately so an escaping helper on one part counts.
      let hit: TaintedValue | undefined;
      for (const part of urlParts(ctx, sql)) {
        if (part.expr && (hit = taintedFlow(ctx, part.expr, { sanitizers: ESCAPE }))) break;
      }
      if (!hit) continue;
      findings.push(flowFinding(ctx, call, hit, `${method}() SQL text`, `Untrusted data (${hit.flow.source.description}) is inserted into the SQL text of ${method}(); it can change the statement (SQL injection). Pass it as a bound parameter instead.`));
    }
    return findings;
  },
});
