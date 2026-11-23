#!/usr/bin/env node
// Regenerates the rule tables and rule counts in README.md and packages/cli/README.md from the
// authoritative registry (@ngbastion/rules). Usage: pnpm build && node scripts/sync-rule-docs.mjs [--check]
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { builtinRules } from '../packages/rules/dist/index.js';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const check = process.argv.includes('--check');
const cap = (s) => s[0].toUpperCase() + s.slice(1);
const table = ['| ID | Rule | Default severity |', '|---|---|---|', ...builtinRules.map((r) => `| ${r.meta.id} | ${r.meta.name} | ${cap(r.meta.defaultSeverity)} |`)].join('\n');
let stale = false;
for (const file of ['README.md', 'packages/cli/README.md']) {
  const abs = path.join(repo, file);
  const before = readFileSync(abs, 'utf8');
  const after = before
    .replace(/(## Security rules\n\n)\| ID \| Rule \|[\s\S]*?\n\n/, `$1${table}\n\n`)
    .replace(/\*\*\d+ security rules\*\*/, `**${builtinRules.length} security rules**`);
  if (after === before) continue;
  stale = true;
  if (!check) writeFileSync(abs, after);
  console.log(`${check ? 'stale' : 'updated'}: ${file}`);
}
if (check && stale) process.exit(1);
