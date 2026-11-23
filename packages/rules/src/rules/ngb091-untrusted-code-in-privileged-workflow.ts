import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { expressions, get, lineLength, str, workflows, type Job, type Step, type Workflow } from '../shared/workflows.js';

/** Triggers that run in the base repository's context (secrets, write token) for contributor events. */
const TRIGGERS = ['pull_request_target', 'workflow_run', 'issue_comment', 'pull_request_review_comment'];
/** Refs / repositories that resolve to contributor-controlled code. */
const PR_CODE = /github\.(head_ref\b|event\.(pull_request\.(head\.(sha|ref|repo\.full_name)|number|merge_commit_sha)|workflow_run\.(head_sha|head_branch|head_repository\.full_name)|issue\.number))/;
/** Job conditions that restrict the job to branches of the same repository. */
const SAME_REPO_GUARD = /head\.repo\.full_name\s*==\s*github\.repository|github\.repository\s*==\s*github\.event\.pull_request\.head\.repo\.full_name|head\.repo\.fork\s*==\s*false|!\s*github\.event\.pull_request\.head\.repo\.fork|head_repository\.full_name\s*==\s*github\.repository/;
const SHELL_CHECKOUT = /\bgh\s+pr\s+checkout\b|\bgit\s+fetch\b[^\n]*\bpull\/|\bgit\s+(checkout|switch|reset)\b[^\n]*\$\{\{\s*github\.(head_ref|event\.(pull_request|workflow_run))/;

function checkoutOf(w: Workflow, s: Step): string | undefined {
  if (s.uses && /^actions\/checkout@/i.test(s.uses) && s.with) {
    for (const key of ['ref', 'repository']) {
      const v = get(s.with, key);
      if (v?.kind === 'scalar' && (expressions(w, v).some((e) => PR_CODE.test(e.expr)) || /refs\/pull\//.test(v.value))) return `actions/checkout with ${key}: ${v.value}`;
    }
  }
  if (s.run && SHELL_CHECKOUT.test(s.run.value)) return `run: ${s.run.value.split('\n').find((l) => SHELL_CHECKOUT.test(l))?.trim() ?? s.run.value}`;
  return undefined;
}

/** Later steps that execute code from the working tree. */
function executesCode(after: Step[]): string | undefined {
  for (const s of after) {
    if (s.run) return `later step runs: ${s.run.value.split('\n')[0]!.trim().slice(0, 80)}`;
    if (s.uses?.startsWith('./')) return `later step uses a local action: ${s.uses}`;
  }
  return undefined;
}

export const ngb091 = defineRule({
  meta: {
    id: 'NGB091',
    name: 'Untrusted code in a privileged workflow',
    category: 'supply-chain',
    defaultSeverity: 'critical',
    cwe: ['CWE-829', 'CWE-94'],
    docs: {
      description:
        'Reads GitHub Actions workflows (`.github/workflows/*.yml`) triggered by `pull_request_target`, `workflow_run`, `issue_comment` or `pull_request_review_comment` and reports jobs that check out the contributor\'s code (the pull request head, merge ref or the triggering run\'s head) — critical when a later step in the same job runs commands or a local action, because that executes attacker-controlled code with the base repository\'s secrets and write token.',
      rationale:
        'These triggers exist so that workflows can label, comment on or deploy previews for pull requests from forks; they therefore run in the context of the base repository with secrets and a token that can write to it. Checking out the pull request and then running `npm install`, a build or tests runs the fork\'s `package.json` scripts, build config and tests — a "pwn request" that has been used to steal publishing tokens and push to default branches.',
      patterns: [
        '`actions/checkout` with `ref:` / `repository:` set from `github.event.pull_request.head.sha|ref|repo.full_name`, `github.head_ref`, `github.event.pull_request.number|merge_commit_sha`, `github.event.workflow_run.head_sha|head_branch|head_repository.full_name`, `github.event.issue.number` or a literal `refs/pull/…`',
        '`run:` steps with `gh pr checkout`, `git fetch … pull/…`, or `git checkout ${{ github.event.pull_request… }}`',
        'Critical (high confidence) when a later step of the same job has `run:` or uses a local `./` action; otherwise high severity with medium confidence',
        'Jobs whose `if:` limits them to the same repository (`github.event.pull_request.head.repo.full_name == github.repository`, `head.repo.fork == false`) are not reported',
      ],
      limitations: [
        'Code executed in a different job via uploaded artifacts is NGB095; reusable workflows called with `uses:` are not followed.',
        'Environment protection rules (required reviewers) and repository settings that require approval for fork workflows are not visible.',
        'YAML anchors / aliases and composite actions are not expanded.',
      ],
      falsePositives: [
        'Label-gated jobs (`if: contains(github.event.pull_request.labels.*.name, \'safe to test\')`) are reported: a maintainer reviews one commit, but the contributor can push a new one before the job checks it out.',
        'Jobs that only read files of the checkout (no `run:` step) are reported with medium confidence.',
      ],
      remediation:
        'Use the `pull_request` trigger for building and testing contributor code (no secrets, read-only token). If a privileged follow-up is needed, split it: an unprivileged `pull_request` workflow uploads results, and a `workflow_run` workflow only consumes them as data (NGB095). Never run the checked-out PR code in a job that has secrets or a write token.',
      example: {
        unsafe: `on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm test`,
        safe: `on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    permissions: { contents: read }
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm test`,
      },
      references: [
        { title: 'GitHub Security Lab — Preventing pwn requests', url: 'https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/' },
        { title: 'GitHub Docs — Security hardening for GitHub Actions', url: 'https://docs.github.com/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const w of workflows(ctx)) {
      const triggers = w.triggers.filter((t) => TRIGGERS.includes(t));
      if (!triggers.length) continue;
      for (const job of w.jobs) {
        if (guarded(job)) continue;
        job.steps.forEach((s, i) => {
          const how = checkoutOf(w, s);
          if (!how) return;
          const exec = executesCode(job.steps.slice(i + 1));
          findings.push({
            location: w.loc(s.index, lineLength(w, s.index)),
            message: `Job '${job.id}' (${triggers.join(', ')}) checks out contributor-controlled code${exec ? ' and then runs it' : ''} with the base repository's secrets and token.`,
            confidence: exec ? 'high' : 'medium',
            ...(exec ? {} : { severity: 'high' as const }),
            evidenceKind: 'pattern',
            evidence: [`${w.rel}: on ${triggers.join(', ')}`, how, ...(exec ? [exec] : ['no later run: step in this job'])],
          });
        });
      }
    }
    return findings;
  },
});

function guarded(job: Job): boolean {
  return SAME_REPO_GUARD.test(str(get(job.node, 'if')) ?? '');
}
