import { defineRule, type RuleFinding, type Severity } from '@ngbastion/plugin-api';
import { lineLength, workflows } from '../shared/workflows.js';

/** GitHub-owned namespaces: maintained by the platform operator that already runs the workflow. */
const FIRST_PARTY = /^(actions|github)\//i;
const MUTABLE_BRANCH = /^(main|master|develop|dev|trunk|latest|HEAD|stable|release|nightly)$/i;

function classify(uses: string): { severity: Severity; why: string } | undefined {
  const u = uses.trim();
  if (!u || u.startsWith('./') || u.includes('${{')) return undefined;
  if (u.startsWith('docker://')) {
    return /@sha256:[0-9a-f]{64}$/i.test(u) ? undefined : { severity: 'low', why: 'container image referenced by tag, not by digest' };
  }
  const at = u.lastIndexOf('@');
  if (at < 0) return { severity: 'high', why: 'no version at all (resolves to the default branch)' };
  const repo = u.slice(0, at);
  const ref = u.slice(at + 1);
  if (FIRST_PARTY.test(repo) || /^[0-9a-f]{40}$/i.test(ref)) return undefined;
  if (MUTABLE_BRANCH.test(ref)) return { severity: 'high', why: `pinned to the branch '${ref}'` };
  return { severity: 'medium', why: `pinned to the tag or branch '${ref}', which its owner can move` };
}

export const ngb093 = defineRule({
  meta: {
    id: 'NGB093',
    name: 'Third-party action not pinned to a commit',
    category: 'supply-chain',
    defaultSeverity: 'medium',
    cwe: ['CWE-829', 'CWE-494'],
    docs: {
      description:
        'Reports `uses:` references in GitHub Actions workflows (steps and reusable-workflow jobs) to third-party actions that are not pinned to a full 40-character commit SHA, and `docker://` images referenced by tag instead of digest.',
      rationale:
        'Git tags and branches are mutable: whoever controls the action repository — its maintainer or an attacker who compromised it — can point `v1` at new code, which then runs in your workflow with your secrets and token. This is how the tj-actions/changed-files compromise (2025) leaked CI secrets from thousands of repositories. A commit SHA cannot be moved.',
      patterns: [
        '`uses: owner/repo@v1` / `@v1.2.3` (medium), `@main` / `@master` / no `@ref` (high)',
        '`uses: owner/repo/.github/workflows/x.yml@v1` reusable workflows',
        '`uses: docker://image:tag` without `@sha256:` digest (low)',
        'Not reported: full commit SHAs, local actions (`./…`), GitHub-owned `actions/*` and `github/*` (maintained by the platform that already runs the workflow; pin them too if your policy requires it)',
      ],
      limitations: [
        'Actions referenced inside composite actions or called reusable workflows are not followed.',
        'A SHA pin does not prove the commit is reviewed or belongs to the upstream repository (fork commits are reachable too); keep pins updated with Dependabot / Renovate.',
      ],
      falsePositives: [
        'Actions owned by your own organization are reported; pin them or accept the risk with an exception.',
      ],
      remediation:
        'Pin every third-party action to a full commit SHA and keep the version in a comment (`uses: owner/action@<40-hex sha> # v4.1.0`); let Dependabot or Renovate update the pins. Reference container images by digest.',
      example: {
        unsafe: `- uses: tj-actions/changed-files@v45`,
        safe: `- uses: tj-actions/changed-files@a284dc1814e3fd07f2e34267fc8f81227ed29fb8 # v45.0.7`,
      },
      references: [
        { title: 'GitHub Docs — Using third-party actions (pin to a full-length commit SHA)', url: 'https://docs.github.com/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions' },
        { title: 'OpenSSF Scorecard — Pinned-Dependencies', url: 'https://github.com/ossf/scorecard/blob/main/docs/checks.md#pinned-dependencies' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const w of workflows(ctx)) {
      const refs = w.jobs.flatMap((j) => [...(j.uses ? [{ uses: j.uses, index: j.node.entries.find((e) => e.key === 'uses')!.value.index }] : []), ...j.steps.filter((s) => s.uses).map((s) => ({ uses: s.uses!, index: s.node.entries.find((e) => e.key === 'uses')!.value.index }))]);
      for (const r of refs) {
        const issue = classify(r.uses);
        if (!issue) continue;
        findings.push({
          location: w.loc(r.index, Math.min(r.uses.length, lineLength(w, r.index))),
          message: `${r.uses}: ${issue.why}; the referenced code can change without a change to this workflow.`,
          confidence: 'high',
          severity: issue.severity,
          evidenceKind: 'pattern',
          evidence: [`${w.rel}: uses: ${r.uses}`],
        });
      }
    }
    return findings;
  },
});
