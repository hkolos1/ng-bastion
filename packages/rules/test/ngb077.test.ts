import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const EXPRESS = `import type { Request, Response } from 'express';\n`;

describe('NGB077 path traversal in server code', () => {
  it('reports fs reads / writes / deletes and res.sendFile with request-chosen paths', async () => {
    const res = await findings('NGB077', {
      'src/server.ts': `${EXPRESS}import fs from 'fs';
import { readFile } from 'node:fs/promises';
import path from 'path';
export async function h(req: Request, res: Response) {
  fs.readFileSync(path.join(__dirname, 'files', req.params.name));
  await readFile(\`./uploads/\${req.query.f}\`);
  fs.unlinkSync('/tmp/' + req.body.file);
  res.sendFile(path.join(__dirname, 'invoices', req.params.file));
}`,
    });
    expect(res).toHaveLength(4);
    expect(res.every((r) => r.evidenceKind === 'dataflow')).toBe(true);
    expect(res.map((r) => r.message).join('\n')).toMatch(/delete arbitrary files/);
  });

  it('safe: basename, sendFile with root, containment checks, constant paths', async () => {
    expect(await findings('NGB077', {
      'src/server.ts': `${EXPRESS}import fs from 'fs';
import path from 'path';
const BASE = path.join(__dirname, 'files');
export function h(req: Request, res: Response) {
  fs.readFileSync(path.join(BASE, path.basename(req.params.name)));
  res.sendFile(req.params.file, { root: BASE });
  const p = path.resolve(BASE, req.query.f as string);
  if (!p.startsWith(BASE + path.sep)) return res.sendStatus(400);
  fs.createReadStream(p);
  fs.readFileSync(path.join(__dirname, 'index.html'));
}`,
    })).toEqual([]);
  });

  it('false-positive regression: browser code and non-fs readFile methods', async () => {
    expect(await findings('NGB077', {
      'src/app/a.ts': `import { ActivatedRoute } from '@angular/router';
export class C { constructor(private route: ActivatedRoute, private files: { readFile(p: string): void }) {}
  run() { this.files.readFile(this.route.snapshot.queryParams['f']); } }`,
    })).toEqual([]);
  });
});
