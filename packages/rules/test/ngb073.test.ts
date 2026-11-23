import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const EXPRESS = `import type { Request, Response } from 'express';\n`;

describe('NGB073 SQL injection in server code', () => {
  it('reports SQL text built from request data (pg, knex raw, Prisma unsafe)', async () => {
    const res = await findings('NGB073', {
      'src/server.ts': `${EXPRESS}import { Pool } from 'pg';
import knexFactory from 'knex';
declare const prisma: { $queryRawUnsafe(q: string): Promise<unknown> };
const pool = new Pool();
const knex = knexFactory({});
export async function h(req: Request, res: Response) {
  await pool.query(\`SELECT * FROM orders WHERE customer = '\${req.query.customer}'\`);
  const sql = 'DELETE FROM carts WHERE id = ' + req.body.id;
  await pool.query(sql);
  await knex('users').whereRaw('name = ' + req.query.name);
  await prisma.$queryRawUnsafe(\`SELECT * FROM t ORDER BY \${req.query.sort}\`);
}`,
    });
    expect(res).toHaveLength(4);
    expect(res.every((r) => r.evidenceKind === 'dataflow')).toBe(true);
    expect(res[0]!.message).toMatch(/bound parameter/);
  });

  it('safe: placeholders, escaping helpers, numeric conversion, constant SQL', async () => {
    expect(await findings('NGB073', {
      'src/server.ts': `${EXPRESS}import mysql from 'mysql2';
const db = mysql.createPool({});
export async function h(req: Request, res: Response) {
  await db.query('SELECT * FROM orders WHERE customer = ?', [req.query.customer]);
  await db.query('SELECT * FROM t WHERE name = ' + mysql.escape(req.query.name));
  await db.query('SELECT * FROM t LIMIT ' + Number(req.query.limit));
  await db.query('SELECT 1');
}`,
    })).toEqual([]);
  });

  it('false-positive regression: query() on non-SQL receivers and files without an SQL client', async () => {
    expect(await findings('NGB073', {
      'src/server.ts': `${EXPRESS}declare const client: { query(q: string): void };
declare const el: { querySelector(q: string): void };
export function h(req: Request) { client.query('?q=' + req.query.q); el.querySelector('#' + req.query.id); }`,
    })).toEqual([]);
  });
});
