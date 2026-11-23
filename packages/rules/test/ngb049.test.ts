import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const MAIN = { 'src/main.ts': 'export {};' };

describe('NGB049 insecure dependency source', () => {
  it('reports http/git protocols (high), unpinned git refs (medium) and open ranges (low)', async () => {
    const res = await findings('NGB049', {
      ...MAIN,
      'package.json': JSON.stringify({ dependencies: { a: 'http://pkgs.example.com/a.tgz', b: 'git://github.com/x/b.git', c: 'github:acme/c#main', d: 'acme/d', e: '*' } }, null, 2),
    });
    expect(res.map((r) => r.severity).sort()).toEqual(['high', 'high', 'low', 'medium', 'medium']);
    expect(res[0]!.location.file).toBe('package.json');
  });

  it('lowers confidence when a lockfile exists and scans nested manifests', async () => {
    const res = await findings('NGB049', {
      ...MAIN,
      'package.json': JSON.stringify({ dependencies: { c: 'github:acme/c#v1' } }),
      'pnpm-lock.yaml': 'lockfileVersion: 9.0',
      'libs/widget/package.json': JSON.stringify({ devDependencies: { t: 'https://example.com/t.tgz' } }),
    });
    expect(res.map((r) => r.confidence).sort()).toEqual(['low', 'medium']);
  });

  it('safe: registry ranges, workspace/file/npm aliases, git pinned to a commit', async () => {
    expect(await findings('NGB049', {
      ...MAIN,
      'package.json': JSON.stringify({ dependencies: { a: '^1.2.3', b: 'workspace:*', c: 'file:../c', d: 'npm:other@1.0.0', e: 'github:acme/e#4f1c2e9d3b7a6f5e8d9c0b1a2f3e4d5c6b7a8f9e', f: '>=1.0.0 <2.0.0', g: '~22.3.0' } }),
    })).toEqual([]);
  });

  it('false-positive regression: node_modules and build output manifests are ignored', async () => {
    expect(await findings('NGB049', {
      ...MAIN,
      'node_modules/x/package.json': JSON.stringify({ dependencies: { a: 'http://x/a.tgz' } }),
      'dist/app/package.json': JSON.stringify({ dependencies: { a: '*' } }),
    })).toEqual([]);
  });
});
