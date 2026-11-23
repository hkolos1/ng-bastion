import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, expect, it } from 'vitest';
import { run } from '../../packages/cli/src/run.js';
import { classifyDiff } from '../../packages/cli/src/git-diff.js';

const tmp = mkdtempSync(path.join(os.tmpdir(), 'ngb-diff-'));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));
const cli = async (cwd: string, args: string[]) => {
  let stdout = '', stderr = '';
  const code = await run(args, { cwd, isTTY: false, env: {}, stdout: s => { stdout += s; }, stderr: s => { stderr += s; } });
  return { code, stdout, stderr };
};
it('uses local working tree hunks, untracked files and trace locations across a monorepo', async () => {
  const repo = mkdtempSync(path.join(tmp, 'repo-')), app = path.join(repo, 'apps/shop');
  mkdirSync(app, { recursive: true });
  const git = (...args: string[]) => execFileSync('git', ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@localhost', ...args], { cwd: repo });
  git('init', '--quiet');
  writeFileSync(path.join(app, 'ngbastion.config.json'), '{"extends":[],"rules":{"NGB003":"error"},"minConfidence":"low","failOn":"high"}');
  writeFileSync(path.join(app, 'input.ts'), 'export function user() { return location.hash; }');
  writeFileSync(path.join(app, 'sink.ts'), "import { user } from './input';\nexport function display(el: HTMLElement) { el.innerHTML = user(); }");
  writeFileSync(path.join(app, 'remove.ts'), 'export const old = 1;');
  writeFileSync(path.join(app, 'old name.ts'), 'export const value = 7;');
  git('add', '.'); git('commit', '-qm', 'fixture');
  const old = path.join(tmp, 'before.json'), current = path.join(tmp, 'after.json');
  expect((await cli(app, ['scan', '-f', 'json', '-o', old])).code).toBe(1);
  writeFileSync(path.join(app, 'input.ts'), 'export function user() { return location.search; }');
  renameSync(path.join(app, 'old name.ts'), path.join(app, 'new\nname.ts'));
  rmSync(path.join(app, 'remove.ts'));
  git('add', '-A');
  writeFileSync(path.join(app, 'untracked.ts'), 'export const another = 1;');
  writeFileSync(path.join(repo, '.gitattributes'), '*.ts filter=fixture\n');
  git('config', 'filter.fixture.clean', 'exit 1');
  git('config', 'filter.fixture.required', 'true');
  const scan = await cli(app, ['scan', '--diff', 'HEAD', '-f', 'json', '-o', current]);
  expect(scan.code, scan.stderr).toBe(1);
  const report = JSON.parse(readFileSync(current, 'utf8'));
  expect(report.scan.git.files).toEqual(expect.arrayContaining([
    expect.objectContaining({ file: 'remove.ts', kind: 'D' }),
    expect.objectContaining({ file: 'new\nname.ts', previous: 'old name.ts', kind: 'R' }),
    expect.objectContaining({ file: 'untracked.ts', kind: '?' }),
  ]));
  expect(report.findings[0].location.file).toBe('sink.ts');
  expect(Object.values(report.scan.git.findings)).toContain('changed-line');
  expect(report.scan.comparison).toBeUndefined();
  const args = ['report', 'compare', old, current, '-f', 'json'];
  const comparison = await cli(app, args);
  expect(comparison.code, comparison.stderr).toBe(0);
  expect(JSON.parse(comparison.stdout).coverage.addedFiles).toContain('untracked.ts');
  expect((await cli(app, args)).stdout).toBe(comparison.stdout);
  expect((await cli(app, ['scan', '--diff', 'no-such-ref'])).code).toBe(2);
  expect(() => classifyDiff(tmp, 'HEAD', [])).toThrow(/working tree/);
  expect((await cli(app, [...args, '-o', old])).code).toBe(2);
});
it('explains missing comparison metadata in legacy JSON', async () => {
  const legacy = path.join(tmp, 'legacy.json');
  writeFileSync(legacy, '{"schemaVersion":1,"scan":{}}');
  const result = await cli(tmp, ['report', 'compare', legacy, legacy]);
  expect(result.code).toBe(2);
  expect(result.stderr).toMatch(/Missing comparison data/);
});
