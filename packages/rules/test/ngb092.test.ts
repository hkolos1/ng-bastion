import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const wf = (yml: string) => findings('NGB092', { 'src/main.ts': 'export {};', '.github/workflows/w.yml': yml });

describe('NGB092 excessive workflow token permissions', () => {
  it('reports write-all at workflow and job level', async () => {
    const res = await wf(`on: push
permissions: write-all
jobs:
  a:
    permissions: write-all
    steps:
      - run: echo
`);
    expect(res).toHaveLength(2);
    expect(res.every((f) => f.severity === 'high' && f.confidence === 'high')).toBe(true);
  });

  it('reports privileged triggers without any permissions (low confidence)', async () => {
    const res = await wf(`on:
  issue_comment:
    types: [created]
jobs:
  reply:
    steps:
      - run: echo hi
`);
    expect(res).toHaveLength(1);
    expect(res[0]!.confidence).toBe('low');
    expect(res[0]!.location.line).toBe(1);
  });

  it('safe: explicit scopes, read-all, empty permissions, per-job permissions', async () => {
    expect(await wf(`on: pull_request_target
permissions:
  contents: read
jobs:
  a:
    permissions:
      pull-requests: write
`)).toEqual([]);
    expect(await wf(`on: issues\npermissions: read-all\njobs:\n  a:\n    steps: []\n`)).toEqual([]);
    expect(await wf(`on: issues\npermissions: {}\njobs:\n  a:\n    steps: []\n`)).toEqual([]);
    expect(await wf(`on: issues\njobs:\n  a:\n    permissions:\n      issues: write\n`)).toEqual([]);
  });

  it('false-positive regression: unprivileged triggers without permissions are not reported', async () => {
    expect(await wf(`on: [push, pull_request]\njobs:\n  a:\n    steps:\n      - run: npm test\n`)).toEqual([]);
  });
});
