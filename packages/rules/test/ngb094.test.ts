import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const wf = (yml: string) => findings('NGB094', { 'src/main.ts': 'export {};', '.github/workflows/w.yml': yml });

describe('NGB094 untrusted expression in a workflow script', () => {
  it('reports untrusted contexts in run scripts and github-script (high for privileged triggers)', async () => {
    const res = await wf(`on: issues
jobs:
  triage:
    steps:
      - run: echo "\${{ github.event.issue.title }}"
      - run: |
          echo start
          git log "\${{ github.head_ref }}"
      - uses: actions/github-script@v7
        with:
          script: |
            const body = \`\${{ github.event.comment.body }}\`;
`);
    expect(res.map((f) => [f.location.line, f.severity])).toEqual([[5, 'high'], [8, 'high'], [12, 'high']]);
  });

  it('medium severity when only triggered by pull_request', async () => {
    const res = await wf(`on: pull_request\njobs:\n  a:\n    steps:\n      - run: echo \${{ github.event.pull_request.title }}\n`);
    expect(res).toHaveLength(1);
    expect(res[0]!.severity).toBe('medium');
  });

  it('safe: env indirection and trusted contexts', async () => {
    expect(await wf(`on: issues
jobs:
  a:
    steps:
      - env:
          TITLE: \${{ github.event.issue.title }}
        run: echo "$TITLE \${{ github.event.issue.number }} \${{ github.sha }}"
`)).toEqual([]);
  });

  it('false-positive regression: untrusted contexts in if: and with: of other actions', async () => {
    expect(await wf(`on: pull_request_target
jobs:
  a:
    if: contains(github.event.pull_request.title, 'docs')
    steps:
      - uses: some/labeler@a284dc1814e3fd07f2e34267fc8f81227ed29fb8
        with:
          title: \${{ github.event.pull_request.title }}
`)).toEqual([]);
  });
});
