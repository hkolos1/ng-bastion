import path from 'node:path';
import { defineRule, type AnalysisContext, type Confidence, type RuleFinding, type Severity } from '@ngbastion/plugin-api';
import { relative } from '../shared/common.js';
import { readJson, textLocation } from '../shared/files.js';

const SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies', 'overrides', 'resolutions'] as const;
const LOCKFILES = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'npm-shrinkwrap.json', 'bun.lockb', 'bun.lock'];
const FULL_SHA = /#(commit=)?[0-9a-f]{40}$/i;

interface Issue {
  severity: Severity;
  confidence: Confidence;
  why: string;
}

function classify(spec: string, locked: boolean): Issue | undefined {
  const s = spec.trim();
  if (/^(workspace:|file:|link:|portal:|catalog:|npm:)/.test(s)) return undefined;
  if (/^http:\/\//i.test(s)) return { severity: 'high', confidence: 'high', why: 'downloaded over plain HTTP; anyone on the network path can replace the package' };
  if (/^git(\+http)?:\/\//i.test(s)) return { severity: 'high', confidence: 'high', why: 'fetched over the unauthenticated git:// / git+http:// protocol' };
  const gitLike = /^(git\+(https|ssh|file):\/\/|git@|github:|gitlab:|bitbucket:|gist:)/i.test(s) || /^[\w.-]+\/[\w.-]+(#.*)?$/.test(s);
  if (gitLike) {
    if (FULL_SHA.test(s)) return undefined;
    return { severity: 'medium', confidence: locked ? 'medium' : 'high', why: `Git dependency ${/#/.test(s) ? 'pinned to a branch, tag or semver range' : 'without a commit'}; the repository owner (or whoever compromises it) can change the code behind the same specifier` };
  }
  if (/^https:\/\//i.test(s)) return { severity: 'low', confidence: locked ? 'low' : 'medium', why: 'tarball URL; its content can change unless the lockfile pins an integrity hash' };
  if (s === '*' || s === 'latest' || s === 'x' || s === '' || /^>=?\s*\d[\w.]*$/.test(s)) {
    return { severity: 'low', confidence: locked ? 'low' : 'medium', why: `unbounded version range '${s || '(empty)'}'; any future release, including a malicious one, is accepted${locked ? ' on the next lockfile update' : ' (no lockfile found)'}` };
  }
  return undefined;
}

function manifests(ctx: AnalysisContext): string[] {
  const out = new Set<string>();
  for (const f of ctx.findFiles('**/package.json')) {
    const rel = relative(ctx, f);
    if (!/(^|\/)(node_modules|dist|\.angular|coverage|tmp|out-tsc)\//.test(rel)) out.add(f);
  }
  const root = path.join(ctx.project.workspaceRoot, 'package.json');
  if (ctx.readFile(root) !== undefined) out.add(root);
  return [...out];
}

export const ngb049 = defineRule({
  meta: {
    id: 'NGB049',
    name: 'Insecure dependency source',
    category: 'supply-chain',
    defaultSeverity: 'medium',
    cwe: ['CWE-494', 'CWE-829'],
    docs: {
      description:
        "Reads the project's `package.json` files (`dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`, `overrides`, `resolutions`) and reports dependency specifiers that can change under you or be tampered with in transit: plain `http://` tarballs and `git://` URLs (high), Git / GitHub dependencies not pinned to a full commit SHA (medium), `https://` tarballs and unbounded ranges such as `*`, `latest`, `>=1.0` (low). Confidence is lower when a lockfile is present.",
      rationale:
        "Registry packages are immutable per version and integrity-checked through the lockfile. A Git branch, a moving tag or an unbounded range is not: whoever controls the repository (or compromises it) changes what your next install and CI build execute, including `postinstall` scripts with access to your CI secrets. Plain HTTP and `git://` let anyone on the network path swap the code.",
      patterns: [
        '`"lib": "http://…/lib.tgz"` and `"lib": "git://…"` / `git+http://` (high)',
        '`"lib": "github:org/repo"`, `"org/repo#main"`, `"git+https://…#v1.2"`, `"git+ssh://…"` without a 40-character commit SHA (medium)',
        '`"lib": "https://…/lib.tgz"`, `"*"`, `"latest"`, `">=1.0.0"` (low)',
        '`workspace:`, `file:`, `link:`, `npm:` aliases and pinned semver ranges are not reported',
        'Manifests under `node_modules`, `dist` and build output folders are ignored',
      ],
      limitations: [
        'The lockfile content is not parsed; its presence only lowers confidence.',
        'Known-vulnerable or malicious package versions are out of scope (use `npm audit` / an SCA tool).',
      ],
      falsePositives: [
        'Forked dependencies on a Git branch you control are reported; pin them to a commit SHA to remove the finding.',
      ],
      remediation:
        'Depend on published registry versions, pin Git dependencies to a full commit SHA (`github:org/repo#<40-hex sha>`), never use `http://` or `git://`, and commit a lockfile so CI installs exactly what was reviewed (`npm ci`, `pnpm install --frozen-lockfile`).',
      example: {
        unsafe: `"dependencies": { "legacy-widget": "github:acme/legacy-widget#main", "charts": "*" }`,
        safe: `"dependencies": { "legacy-widget": "github:acme/legacy-widget#4f1c2e9d3b7a6f5e8d9c0b1a2f3e4d5c6b7a8f9e", "charts": "^4.4.1" }`,
      },
      references: [
        { title: 'npm — package.json dependency specifiers', url: 'https://docs.npmjs.com/cli/configuring-npm/package-json#dependencies' },
        { title: 'OWASP — Software Supply Chain Security Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const file of manifests(ctx)) {
      const parsed = readJson(ctx, file);
      if (!parsed || typeof parsed.json !== 'object' || !parsed.json) continue;
      const dir = path.dirname(file);
      const locked = [dir, ctx.project.workspaceRoot].some((d) => LOCKFILES.some((l) => ctx.readFile(path.join(d, l)) !== undefined));
      const pkg = parsed.json as Record<string, unknown>;
      for (const section of SECTIONS) {
        const deps = pkg[section];
        if (!deps || typeof deps !== 'object') continue;
        for (const [name, spec] of Object.entries(deps as Record<string, unknown>)) {
          if (typeof spec !== 'string') continue;
          const issue = classify(spec, locked);
          if (!issue) continue;
          const idx = parsed.text.indexOf(`${JSON.stringify(name)}`, parsed.text.indexOf(`"${section}"`));
          findings.push({
            location: textLocation(file, parsed.text, idx, name.length + 2),
            message: `${section}.${name} (${spec}): ${issue.why}.`,
            confidence: issue.confidence,
            severity: issue.severity,
            evidenceKind: 'pattern',
            evidence: [`${relative(ctx, file)} → ${section}["${name}"] = "${spec}"`, locked ? 'lockfile present' : 'no lockfile found next to the manifest or at the workspace root'],
          });
        }
      }
    }
    return findings;
  },
});
