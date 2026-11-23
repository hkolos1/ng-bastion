import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const EXPRESS = `import type { Request, Response } from 'express';\n`;

describe('NGB076 server-side request forgery', () => {
  it('reports Node HTTP clients whose destination comes from request data', async () => {
    const res = await findings('NGB076', {
      'src/server.ts': `${EXPRESS}import axios from 'axios';
import got from 'got';
import https from 'node:https';
import fetch from 'node-fetch';
export async function h(req: Request, res: Response) {
  await axios.get(req.query.url as string);
  await got(\`\${req.body.webhook}\`);
  https.get({ host: req.query.host as string, path: '/' });
  await fetch(\`https://internal.example.com/\${req.params.path}\`);
}`,
    });
    expect(res.map((r) => r.severity)).toEqual(['high', 'high', 'high', 'medium']);
    expect(res[0]!.message).toMatch(/SSRF/);
  });

  it('safe: constant destinations, query values, host allowlists, encoded segments', async () => {
    expect(await findings('NGB076', {
      'src/server.ts': `${EXPRESS}import axios from 'axios';
const ALLOWED = new Set(['api.example.com']);
export async function h(req: Request, res: Response) {
  await axios.get('https://api.example.com/search?q=' + req.query.q);
  await axios.get(\`https://api.example.com/users/\${encodeURIComponent(req.params.id)}\`);
  const target = new URL(String(req.query.url));
  if (!ALLOWED.has(target.hostname)) return;
  await axios.get(target.toString());
}`,
    })).toEqual([]);
  });

  it('false-positive regression: browser URLs and global fetch (NGB026)', async () => {
    expect(await findings('NGB076', {
      'src/app/a.ts': `import axios from 'axios';
export function f() { return axios.get(location.hash.slice(1)); }`,
      'src/server.ts': `${EXPRESS}export function h(req: Request) { return fetch(req.query.url as string); }`,
    })).toEqual([]);
  });
});
