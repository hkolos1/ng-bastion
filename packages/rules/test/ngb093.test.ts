import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const wf = (yml: string) => findings('NGB093', { 'src/main.ts': 'export {};', '.github/workflows/w.yml': yml });

describe('NGB093 third-party action not pinned to a commit', () => {
  it('reports tags (medium), branches (high), reusable workflows and docker tags (low)', async () => {
    const res = await wf(`on: push
jobs:
  a:
    steps:
      - uses: tj-actions/changed-files@v45
      - uses: some/action@main
      - uses: 'docker://alpine:3.20'
  b:
    uses: org/shared/.github/workflows/build.yml@v1
`);
    expect(res.map((f) => [f.location.line, f.severity]).sort((a, b) => (a[0] as number) - (b[0] as number))).toEqual([[5, 'medium'], [6, 'high'], [7, 'low'], [9, 'medium']]);
  });

  it('safe: SHA pins, first-party actions, local actions, docker digests', async () => {
    expect(await wf(`on: push
jobs:
  a:
    steps:
      - uses: tj-actions/changed-files@a284dc1814e3fd07f2e34267fc8f81227ed29fb8 # v45.0.7
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
      - uses: ./.github/actions/setup
      - uses: docker://alpine@sha256:${'a'.repeat(64)}
`)).toEqual([]);
  });

  it('false-positive regression: "uses" inside run scripts and with inputs is not an action reference', async () => {
    expect(await wf(`on: push
jobs:
  a:
    steps:
      - run: |
          echo "uses: evil/action@main"
      - uses: actions/github-script@v7
        with:
          uses: other/thing@main
`)).toEqual([]);
  });
});
