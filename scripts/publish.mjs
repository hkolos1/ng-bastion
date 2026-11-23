// Publishes every non-private package under packages/ at the given version.
// pnpm pack resolves workspace:* to real versions; npm publish then uses Trusted Publishing (OIDC).
// Usage: node scripts/publish.mjs <version>   (DRY_RUN=1 packs and runs npm publish --dry-run)
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const version = process.argv[2];
if (!/^\d+\.\d+\.\d+(-[\w.]+)?$/.test(version ?? '')) throw new Error(`usage: publish.mjs <version>, got "${version}"`);

const run = (cmd, args, opts = {}) => execFileSync(cmd, args, { stdio: 'inherit', ...opts });
const out = mkdtempSync(path.join(tmpdir(), 'ngbastion-pack-'));

const pkgs = readdirSync('packages')
  .map((d) => ({ dir: path.join('packages', d), json: JSON.parse(readFileSync(path.join('packages', d, 'package.json'), 'utf8')) }))
  .filter((p) => !p.json.private)
  // Dependencies first, so no published package ever points at a missing version.
  // ponytail: sort by internal-dep count; fine for this tree, switch to a topo sort if deps get deeper.
  .sort((a, b) => internal(a) - internal(b));
function internal(p) {
  return Object.keys(p.json.dependencies ?? {}).filter((d) => d.startsWith('@ngbastion/')).length;
}

// Refuse to publish a tag that does not match the committed versions.
const wrong = pkgs.filter((p) => p.json.version !== version);
if (wrong.length) throw new Error(`tag v${version} does not match: ${wrong.map((p) => `${p.json.name}@${p.json.version}`).join(', ')}`);

for (const { dir, json } of pkgs) {
  const spec = `${json.name}@${version}`;
  let exists = false;
  try {
    exists = execFileSync('npm', ['view', spec, 'version'], { encoding: 'utf8' }).trim() === version;
  } catch {
    // 404: not published yet
  }
  if (exists && !process.env.DRY_RUN) {
    console.log(`skip ${spec} (already on npm)`);
    continue;
  }
  run('pnpm', ['pack', '--pack-destination', out], { cwd: dir });
  const tgz = path.join(out, `${json.name.replace('@', '').replace('/', '-')}-${version}.tgz`);
  const tag = version.includes('-') ? 'next' : 'latest';
  run('npm', ['publish', tgz, '--access', 'public', '--tag', tag, ...(process.env.DRY_RUN ? ['--dry-run'] : [])]);
}
