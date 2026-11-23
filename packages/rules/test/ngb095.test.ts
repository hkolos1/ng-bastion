import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const wf = (yml: string) => findings('NGB095', { 'src/main.ts': 'export {};', '.github/workflows/w.yml': yml });

const ON = `on:
  workflow_run:
    workflows: [CI]
    types: [completed]
`;

describe('NGB095 untrusted artifact in a privileged workflow', () => {
  it('reports download of the triggering run followed by run steps', async () => {
    const res = await wf(`${ON}jobs:
  comment:
    steps:
      - uses: actions/download-artifact@v4
        with:
          run-id: \${{ github.event.workflow_run.id }}
          github-token: \${{ secrets.GITHUB_TOKEN }}
      - run: bash ./report.sh
`);
    expect(res).toHaveLength(1);
    expect(res[0]!.confidence).toBe('high');
    expect(res[0]!.location.line).toBe(8);
  });

  it('reports dawidd6/action-download-artifact and gh run download (medium without later run)', async () => {
    const res = await wf(`${ON}jobs:
  a:
    steps:
      - uses: dawidd6/action-download-artifact@v6
  b:
    steps:
      - run: gh run download \${{ github.event.workflow_run.id }}
`);
    expect(res.map((f) => f.confidence)).toEqual(['medium', 'medium']);
  });

  it('safe: other triggers and artifacts of the same run', async () => {
    expect(await wf(`on: push\njobs:\n  a:\n    steps:\n      - uses: dawidd6/action-download-artifact@v6\n      - run: ls\n`)).toEqual([]);
    expect(await wf(`${ON}jobs:\n  a:\n    steps:\n      - uses: actions/download-artifact@v4\n        with:\n          name: build\n      - run: ls\n`)).toEqual([]);
  });

  it('false-positive regression: run-id mentioned only in a later run step does not mark the download', async () => {
    expect(await wf(`${ON}jobs:\n  a:\n    steps:\n      - uses: actions/download-artifact@v4\n      - run: echo \${{ github.event.workflow_run.id }}\n`)).toEqual([]);
  });
});
