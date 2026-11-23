import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { PRIVILEGED_TRIGGERS, get, lineLength, workflows, type YNode } from '../shared/workflows.js';

export const ngb092 = defineRule({
  meta: {
    id: 'NGB092',
    name: 'Excessive workflow token permissions',
    category: 'supply-chain',
    defaultSeverity: 'medium',
    cwe: ['CWE-250', 'CWE-732'],
    docs: {
      description:
        'Reads GitHub Actions workflows and reports `permissions: write-all` (workflow or job level), and workflows triggered by events that process contributor-controlled data (`pull_request_target`, `workflow_run`, `issue_comment`, `issues`, `pull_request_review_comment`, `discussion`, `discussion_comment`) that declare no `permissions` at all, so the `GITHUB_TOKEN` gets the repository default.',
      rationale:
        'Every job receives a `GITHUB_TOKEN`. If any step is compromised — a script injection (NGB094), a hijacked third-party action (NGB093) or executed PR code (NGB091) — the token\'s scopes decide the damage: with `contents: write` an attacker pushes to branches and tags, with `actions: write` they alter workflows, with `packages: write` / `id-token: write` they publish. Least privilege turns a full compromise into a read-only one.',
      patterns: [
        '`permissions: write-all` at workflow or job level (high severity)',
        'Workflow with a privileged trigger, no top-level `permissions:` and at least one job without its own `permissions:` (medium severity, low confidence: the default depends on repository / organization settings)',
        '`permissions: read-all`, `{}` and explicit scope maps are not reported',
      ],
      limitations: [
        'The repository / organization default token permission ("Read and write" vs "Read") is not visible; missing `permissions:` is therefore low confidence.',
        'Individual write scopes are not judged; whether a job needs `pull-requests: write` depends on what it does.',
      ],
      falsePositives: [
        'Repositories whose default token permission is already read-only are reported for missing `permissions:`; adding an explicit block documents the intent and removes the finding.',
      ],
      remediation:
        'Set `permissions: {}` or `permissions: { contents: read }` at the top of every workflow and grant individual write scopes only to the jobs that need them. Avoid `write-all`.',
      example: {
        unsafe: `on: issue_comment
permissions: write-all`,
        safe: `on: issue_comment
permissions:
  contents: read
jobs:
  triage:
    permissions:
      issues: write`,
      },
      references: [
        { title: 'GitHub Docs — Controlling permissions for GITHUB_TOKEN', url: 'https://docs.github.com/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token' },
        { title: 'OpenSSF Scorecard — Token-Permissions', url: 'https://github.com/ossf/scorecard/blob/main/docs/checks.md#token-permissions' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const w of workflows(ctx)) {
      const writeAll = (n: YNode | undefined, where: string) => {
        if (n?.kind === 'scalar' && n.value === 'write-all') {
          findings.push({ location: w.loc(n.index, n.value.length), message: `${where} grants the GITHUB_TOKEN write access to every scope (write-all).`, confidence: 'high', severity: 'high', evidenceKind: 'pattern', evidence: [`${w.rel}: permissions: write-all`, `triggers: ${w.triggers.join(', ') || '(none)'}`] });
        }
      };
      const top = get(w.root, 'permissions');
      writeAll(top, 'Workflow');
      for (const j of w.jobs) writeAll(get(j.node, 'permissions'), `Job '${j.id}'`);
      const privileged = w.triggers.filter((t) => PRIVILEGED_TRIGGERS.includes(t));
      if (!top && privileged.length) {
        const open = w.jobs.filter((j) => !get(j.node, 'permissions') && !j.uses);
        if (open.length) {
          const onIdx = w.root.entries.find((e) => e.key === 'on' || e.key === 'true')?.index ?? 0;
          findings.push({
            location: w.loc(onIdx, lineLength(w, onIdx)),
            message: `Workflow triggered by ${privileged.join(', ')} declares no permissions; job(s) ${open.map((j) => `'${j.id}'`).join(', ')} get the repository's default GITHUB_TOKEN scopes.`,
            confidence: 'low',
            evidenceKind: 'pattern',
            evidence: [`${w.rel}: no top-level permissions`, 'repository default token permission: not visible'],
          });
        }
      }
    }
    return findings;
  },
});
