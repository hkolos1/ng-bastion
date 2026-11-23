import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';
import { parseYaml, workflows } from '../src/shared/workflows.js';

const wf = (yml: string) => findings('NGB091', { 'src/main.ts': 'export {};', '.github/workflows/pr.yml': yml });

const PWN = `name: PR
on:
  pull_request_target:
    types: [opened, synchronize]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4 # checkout
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - name: Test
        run: |
          npm ci
          npm test
`;

describe('NGB091 untrusted code in a privileged workflow', () => {
  it('reports checkout of the PR head followed by run steps (critical, high confidence)', async () => {
    const res = await wf(PWN);
    expect(res).toHaveLength(1);
    expect(res[0]!.severity).toBe('critical');
    expect(res[0]!.confidence).toBe('high');
    expect(res[0]!.location).toMatchObject({ file: '.github/workflows/pr.yml', line: 11 });
  });

  it('reports issue_comment refs/pull checkouts and gh pr checkout; checkout without later run is medium confidence', async () => {
    const res = await wf(`on: issue_comment
jobs:
  a:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/\${{ github.event.issue.number }}/merge
  b:
    steps:
      - run: gh pr checkout \${{ github.event.issue.number }}
      - run: make
`);
    expect(res).toHaveLength(2);
    expect(res.find((f) => f.location.line === 5)!.confidence).toBe('medium');
    expect(res.find((f) => f.location.line === 10)!.confidence).toBe('high');
  });

  it('safe: pull_request trigger, default checkout under pull_request_target, same-repo guard', async () => {
    expect(await wf(PWN.replace('pull_request_target', 'pull_request'))).toEqual([]);
    expect(await wf(`on: pull_request_target
jobs:
  label:
    steps:
      - uses: actions/checkout@v4
      - run: echo label
`)).toEqual([]);
    expect(await wf(PWN.replace('    runs-on: ubuntu-latest', "    if: github.event.pull_request.head.repo.full_name == github.repository\n    runs-on: ubuntu-latest"))).toEqual([]);
  });

  it('false-positive regression: expressions in comments and other inputs are ignored', async () => {
    expect(await wf(`on: pull_request_target
jobs:
  a:
    steps:
      # ref: \${{ github.event.pull_request.head.sha }}
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - run: echo "\${{ github.event.pull_request.number }}"
`)).toEqual([]);
  });

  it('parser resilience: malformed YAML never throws', async () => {
    for (const bad of ['', ':::', '- - -\n  : x', 'jobs:\n\t- [\n  steps: {', 'on: [push\njobs:\n  a:\n      b:\n    c: |\n', '"unterminated: x\n  - y: |\n'.repeat(50)]) {
      expect(() => parseYaml(bad)).not.toThrow();
      expect(await wf(bad)).toEqual([]);
    }
    const doc = parseYaml('a:\n  - x: 1\n    y: |\n      line1\n      line2\n  - z\nb: [p, "q"]\n');
    expect(JSON.stringify(doc)).toContain('line1\\nline2');
    expect(workflows).toBeTypeOf('function');
  });
});
