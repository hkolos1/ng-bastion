import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { realpathSync } from 'node:fs';
import type { Finding, RelativeLocation } from '@ngbastion/core';
import { ReportingError } from './baseline.js';

interface ChangedFile {
  file: string;
  previous?: string;
  kind: string;
  lines: [number, number][];
}

export interface GitClassification {
  revision: string;
  files: ChangedFile[];
  findings: Record<string, 'changed-line' | 'changed-file' | 'outside-diff'>;
}

function git(cwd: string, args: string[], failure: string) {
  const result = spawnSync('git', ['--no-pager', '--no-optional-locks', '-c', 'core.fsmonitor=false', ...args], {
    cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, GIT_NO_LAZY_FETCH: '1', GIT_ALLOW_PROTOCOL: '', GIT_TERMINAL_PROMPT: '0' },
  });
  if (result.error || result.status !== 0) throw new ReportingError(`${failure}: ${result.error?.message ?? result.stderr.trim()}`);
  return result.stdout;
}

// The raw NUL-delimited records and patches are emitted together in the same order.
// Never parse quoted, escaped or space-separated filenames from the patch headers.
export function parseGitPatch(output: string): ChangedFile[] {
  if (!output) return [];
  const boundary = output.indexOf('\0\0');
  if (boundary < 0) throw new ReportingError('Invalid Git diff: incomplete raw records');
  const tokens = output.slice(0, boundary).split('\0');
  const files: ChangedFile[] = [];
  for (let i = 0; i < tokens.length;) {
    const header = tokens[i++]!;
    const kind = /^:\d+ \d+ [a-f0-9]+ [a-f0-9]+ ([AMDRT])\d*$/.exec(header)?.[1];
    if (!kind) throw new ReportingError('Unsupported Git diff record (resolve any unmerged paths before scanning)');
    const first = tokens[i++]!;
    if (kind === 'R') files.push({ kind, previous: first, file: tokens[i++]!, lines: [] });
    else files.push({ kind, file: first, lines: [] });
  }
  let index = -1;
  for (const line of output.slice(boundary + 2).split('\n')) {
    if (line.startsWith('diff --git ')) { index++; continue; }
    const match = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (!match) continue;
    const start = Number(match[1]), count = Number(match[2] ?? 1);
    if (!files[index]) throw new ReportingError('Invalid Git diff: unmatched patch');
    if (count) files[index]!.lines.push([start, start + count - 1]);
  }
  if (index + 1 !== files.length) throw new ReportingError('Cannot match Git patch coverage to paths');
  return files;
}

export function classifyDiff(cwd: string, ref: string, findings: Finding[]): GitClassification {
  const root = git(cwd, ['rev-parse', '--show-toplevel'], 'Git working tree required').replace(/\r?\n$/, '');
  const revision = git(root, ['rev-parse', '--verify', '--end-of-options', ref + '^{commit}'], 'Invalid local Git revision ' + ref).trim();
  const patch = git(root, ['diff', '--raw', '-z', '--patch', '--find-renames', '--unified=0', '--inter-hunk-context=0',
    '--no-ext-diff', '--no-textconv', '--no-color', '--no-relative', '--ignore-submodules=all', revision, '--'], 'Cannot read local Git diff');
  const tracked = parseGitPatch(patch);
  const other = git(root, ['ls-files', '--others', '--exclude-standard', '-z'], 'Cannot list untracked paths');
  for (const file of other.split('\0')) if (file) tracked.push({ kind: '?', file, lines: [] });
  const workspace = realpathSync(cwd);
  const relative = (file: string) => path.relative(workspace, path.join(root, file)).split(path.sep).join('/');
  const inside = (file: string) => file !== '..' && !file.startsWith('../');
  const files = tracked.map(f => ({ ...f, file: relative(f.file), ...(f.previous ? { previous: relative(f.previous) } : {}) }))
    .filter(f => inside(f.file) || (f.previous && inside(f.previous)));
  const byPath = new Map(files.filter(f => f.kind !== 'D').map(f => [f.file, f]));
  function relation(loc: RelativeLocation) {
    const f = byPath.get(loc.file);
    if (!f) return 'outside-diff';
    const last = loc.endColumn === 1 && loc.endLine > loc.line ? loc.endLine - 1 : loc.endLine;
    return f.kind === '?' || f.kind === 'A' || f.lines.some(([start, end]) => start <= last && end >= loc.line)
      ? 'changed-line' : 'changed-file';
  }
  const labels: GitClassification['findings'] = Object.create(null);
  for (const finding of findings) {
    const locations = [finding.location, ...(finding.trace ?? [])].map(relation);
    labels[finding.fingerprintV2!] = locations.includes('changed-line') ? 'changed-line'
      : locations.includes('changed-file') ? 'changed-file' : 'outside-diff';
  }
  return { revision, files, findings: labels };
}
