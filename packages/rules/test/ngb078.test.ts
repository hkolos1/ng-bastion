import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const EXPRESS = `import type { Request, Response } from 'express';\n`;

describe('NGB078 OS command injection', () => {
  it('reports exec / execSync command lines built from request data (import, namespace, require)', async () => {
    const res = await findings('NGB078', {
      'src/server.ts': `${EXPRESS}import { exec } from 'child_process';
import * as cp from 'node:child_process';
const { execSync: run } = require('child_process');
export function h(req: Request, res: Response) {
  exec(\`convert \${req.query.file} out.png\`);
  cp.execSync('git log ' + req.body.ref);
  run(String(req.params.cmd));
}`,
    });
    expect(res).toHaveLength(3);
    expect(res.every((r) => r.severity === 'critical' && r.evidenceKind === 'dataflow')).toBe(true);
    expect(res[0]!.trace?.[0]?.description).toMatch(/server request query/);
  });

  it('reports spawn / execFile with shell: true and untrusted program names; untyped (req, res) handlers', async () => {
    const res = await findings('NGB078', {
      'src/server.ts': `const cp = require('child_process');
declare const app: any;
app.get('/zip', (req, res) => {
  cp.spawn('zip', ['-r', req.query.name], { shell: true });
  cp.execFile(req.query.tool, ['--version']);
});`,
    });
    expect(res.map((r) => r.severity)).toEqual(['critical', 'high']);
  });

  it('safe: execFile / spawn with argument arrays, constant commands, shell-quoting, numeric conversion', async () => {
    expect(await findings('NGB078', {
      'src/server.ts': `${EXPRESS}import { exec, execFile, spawn } from 'child_process';
import { quote } from 'shell-quote';
export function h(req: Request, res: Response) {
  execFile('convert', ['--', String(req.query.file), 'out.png']);
  spawn('git', ['log', req.body.ref]);
  exec('git status');
  exec('kill ' + Number(req.query.pid));
  exec('ls ' + quote([req.query.dir as string]));
}`,
    })).toEqual([]);
  });

  it('false-positive regression: project functions named exec and other modules', async () => {
    expect(await findings('NGB078', {
      'src/server.ts': `${EXPRESS}import { exec } from './db';
const re = /x/;
export function h(req: Request) { exec(req.query.q as string); re.exec(req.query.q as string); }`,
      'src/db.ts': `export function exec(q: string) { return q; }`,
    })).toEqual([]);
  });
});
