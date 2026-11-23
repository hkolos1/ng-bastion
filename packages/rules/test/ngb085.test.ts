import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const EXPRESS = `import type { Request, Response, NextFunction } from 'express';\n`;

describe('NGB085 error details sent to clients', () => {
  it('reports stack traces, raw errors and messages in responses', async () => {
    const res = await findings('NGB085', {
      'src/server.ts': `${EXPRESS}import { readFile } from 'fs';
declare function db(): Promise<unknown>;
export function errorHandler(err: Error, req: Request, res: Response, next: NextFunction) {
  res.status(500).send(err.stack);
}
export async function list(req: Request, res: Response) {
  try { res.json(await db()); } catch (e) { res.status(500).json({ error: e }); }
  db().catch((error) => res.status(500).send(\`Failed: \${error.message}\`));
  readFile('/data/x', (err, data) => { if (err) return res.end(String(err)); res.end(data); });
}`,
    });
    expect(res.map((r) => r.severity).sort()).toEqual(['low', 'medium', 'medium', 'medium']);
    expect(res.find((r) => r.message.includes('stack'))!.confidence).toBe('high');
  });

  it('safe: generic messages, logging, dev-only details, next(err)', async () => {
    expect(await findings('NGB085', {
      'src/server.ts': `${EXPRESS}export function errorHandler(err: Error, req: Request, res: Response, next: NextFunction) {
  console.error(err);
  if (process.env.NODE_ENV !== 'production') return res.status(500).send(err.stack);
  res.status(500).json({ error: 'Internal server error' });
}
export async function list(req: Request, res: Response, next: NextFunction) {
  try { res.json([]); } catch (e) { next(e); }
}`,
    })).toEqual([]);
  });

  it('false-positive regression: non-error variables named like errors, error codes, non-response send()', async () => {
    expect(await findings('NGB085', {
      'src/server.ts': `${EXPRESS}export function f(req: Request, res: Response, socket: { send(x: unknown): void }) {
  const error = { code: 'E_VALIDATION' };
  res.status(400).json({ error });
  try { JSON.parse('x'); } catch (e) { socket.send((e as Error).stack); res.status(400).json({ code: (e as Error & { code: string }).code }); }
}`,
    })).toEqual([]);
  });
});
