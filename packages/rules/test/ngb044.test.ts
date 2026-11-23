import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const ng = (build: unknown) => JSON.stringify({ version: 1, projects: { app: { projectType: 'application', root: '', architect: { build } } } }, null, 2);
const MAIN = { 'src/main.ts': 'export {};' };

describe('NGB044 public production source maps', () => {
  it('reports production source maps (high) located in angular.json', async () => {
    const res = await findings('NGB044', { ...MAIN, 'angular.json': ng({ options: {}, configurations: { production: { sourceMap: true } } }) });
    expect(res).toHaveLength(1);
    expect(res[0]!.confidence).toBe('high');
    expect(res[0]!.location.file).toBe('angular.json');
  });

  it('reports inherited build options and object form without hidden', async () => {
    const res = await findings('NGB044', { ...MAIN, 'angular.json': ng({ options: { sourceMap: { scripts: true } }, configurations: { production: { outputHashing: 'all' } } }) });
    expect(res).toHaveLength(1);
    expect(res[0]!.message).toMatch(/inherited/);
  });

  it('safe: hidden maps, production override to false, default', async () => {
    expect(await findings('NGB044', { ...MAIN, 'angular.json': ng({ options: { sourceMap: true }, configurations: { production: { sourceMap: { scripts: true, hidden: true } } } }) })).toEqual([]);
    expect(await findings('NGB044', { ...MAIN, 'angular.json': ng({ options: { sourceMap: true }, configurations: { production: { sourceMap: false }, development: { sourceMap: true } } }) })).toEqual([]);
    expect(await findings('NGB044', { ...MAIN, 'angular.json': ng({ options: {}, configurations: { production: {} } }) })).toEqual([]);
  });

  it('false-positive regression: development-only source maps', async () => {
    expect(await findings('NGB044', { ...MAIN, 'angular.json': ng({ options: {}, configurations: { development: { sourceMap: true } } }) })).toEqual([]);
  });
});
