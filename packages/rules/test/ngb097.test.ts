import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const MAIN = { 'src/main.ts': 'export {};' };

describe('NGB097 package manager TLS verification disabled', () => {
  it('reports strict-ssl=false and http registries in .npmrc', async () => {
    const res = await findings('NGB097', { ...MAIN, '.npmrc': 'strict-ssl=false\n@acme:registry = http://npm.acme.example/\n' });
    expect(res.map((f) => f.location.line)).toEqual([1, 2]);
    expect(res[0]!.location.file).toBe('.npmrc');
  });

  it('reports yarn 1 and yarn 2+ settings', async () => {
    const res = await findings('NGB097', { ...MAIN, '.yarnrc': 'strict-ssl false\nregistry "http://registry.example.com"\n', '.yarnrc.yml': 'enableStrictSsl: false\nnpmRegistryServer: "http://registry.example.com"\n' });
    expect(res).toHaveLength(4);
  });

  it('safe: https registries, strict-ssl true, local registries', async () => {
    expect(await findings('NGB097', { ...MAIN, '.npmrc': 'registry=https://registry.npmjs.org/\nstrict-ssl=true\n@local:registry=http://localhost:4873/\n' })).toEqual([]);
  });

  it('false-positive regression: commented-out settings', async () => {
    expect(await findings('NGB097', { ...MAIN, '.npmrc': '# strict-ssl=false\n; registry=http://registry.example.com\n' })).toEqual([]);
  });
});
