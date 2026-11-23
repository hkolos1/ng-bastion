import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const ng = (serve: unknown) => JSON.stringify({ version: 1, projects: { app: { projectType: 'application', root: '', architect: { serve } } } }, null, 2);
const MAIN = { 'src/main.ts': 'export {};' };

describe('NGB096 development server exposed to the network', () => {
  it('reports angular.json serve host / host-check settings', async () => {
    const res = await findings('NGB096', { ...MAIN, 'angular.json': ng({ options: { host: '0.0.0.0' }, configurations: { docker: { disableHostCheck: true, allowedHosts: ['all'] } } }) });
    expect(res.map((f) => f.severity).sort()).toEqual(['low', 'medium', 'medium']);
    expect(res.every((f) => f.location.file === 'angular.json')).toBe(true);
  });

  it('reports ng serve flags in package.json scripts', async () => {
    const res = await findings('NGB096', { ...MAIN, 'package.json': JSON.stringify({ scripts: { start: 'ng serve --host 0.0.0.0 --disable-host-check', lan: 'ng serve --host=0.0.0.0' } }) });
    expect(res.map((f) => f.severity).sort()).toEqual(['low', 'low', 'medium']);
  });

  it('safe: localhost, explicit allowed hosts, other commands', async () => {
    expect(await findings('NGB096', {
      ...MAIN,
      'angular.json': ng({ options: { host: 'localhost', allowedHosts: ['dev.example.test'] } }),
      'package.json': JSON.stringify({ scripts: { start: 'ng serve', api: 'node server.js --host 0.0.0.0' } }),
    })).toEqual([]);
  });

  it('false-positive regression: host settings outside the serve target', async () => {
    expect(await findings('NGB096', { ...MAIN, 'angular.json': JSON.stringify({ version: 1, projects: { app: { root: '', architect: { e2e: { options: { host: '0.0.0.0' } } } } } }) })).toEqual([]);
  });
});
