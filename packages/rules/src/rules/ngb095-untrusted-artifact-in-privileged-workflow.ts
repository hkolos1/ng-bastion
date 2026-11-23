import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { get, lineLength, str, workflows, type Step } from '../shared/workflows.js';

const RUN_ID = /github\.event\.workflow_run\.(id|workflow_id|head_sha)/;

function downloadsTriggeringRun(s: Step): string | undefined {
  const withText = (s.with?.entries ?? []).map((e) => `${e.key}: ${str(e.value) ?? ''}`).join('\n');
  if (s.uses && /^actions\/download-artifact@/i.test(s.uses) && RUN_ID.test(withText)) return `${s.uses} with run-id of the triggering run`;
  if (s.uses && /^dawidd6\/action-download-artifact@/i.test(s.uses)) return `${s.uses} (downloads artifacts of other workflow runs)`;
  const script = s.uses && /^actions\/github-script@/i.test(s.uses) ? str(get(s.with, 'script')) : undefined;
  if (script && /\b(listWorkflowRunArtifacts|downloadArtifact)\b/.test(script)) return 'actions/github-script downloading workflow run artifacts';
  if (s.run && /\bgh\s+run\s+download\b/.test(s.run.value) && RUN_ID.test(s.run.value)) return 'gh run download of the triggering run';
  return undefined;
}

export const ngb095 = defineRule({
  meta: {
    id: 'NGB095',
    name: 'Untrusted artifact in a privileged workflow',
    category: 'supply-chain',
    defaultSeverity: 'high',
    cwe: ['CWE-829', 'CWE-494'],
    docs: {
      description:
        'Reports `workflow_run` workflows that download artifacts produced by the triggering run (`actions/download-artifact` with `run-id: ${{ github.event.workflow_run.id }}`, `dawidd6/action-download-artifact`, `github-script` artifact APIs, `gh run download`) — with high confidence when a later step of the same job runs commands that can consume them.',
      rationale:
        '`workflow_run` lets a privileged workflow (secrets, write token) react to an unprivileged `pull_request` run. The artifacts of that run were produced by contributor-controlled code: a fork can upload a crafted archive that overwrites scripts, `package.json`, or files later sourced into `$GITHUB_ENV`, turning the privileged workflow into a code-execution primitive ("artifact poisoning").',
      patterns: [
        '`on: workflow_run` workflows only',
        'Download steps listed above; high confidence when a later `run:` step exists in the same job, medium otherwise',
      ],
      limitations: [
        'Whether the artifact content is treated strictly as data (e.g. only parsed as JSON and validated) is not analyzed.',
        'Artifacts downloaded in one job and used in another are reported at the download step only.',
      ],
      falsePositives: [
        'Workflows that extract artifacts into an isolated directory (`path: ${{ runner.temp }}/artifacts`) and only read validated data from it are reported with the same severity; document the validation in an exception.',
      ],
      remediation:
        'Treat downloaded artifacts as untrusted input: extract into a temporary directory outside the workspace, never execute or `source` their content, validate any values (e.g. a PR number must be numeric) before use, and keep the privileged job\'s permissions minimal.',
      example: {
        unsafe: `on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  comment:
    steps:
      - uses: actions/download-artifact@v4
        with:
          run-id: \${{ github.event.workflow_run.id }}
          github-token: \${{ secrets.GITHUB_TOKEN }}
      - run: bash ./report.sh`,
        safe: `      - uses: actions/download-artifact@v4
        with:
          run-id: \${{ github.event.workflow_run.id }}
          path: \${{ runner.temp }}/pr
      - run: jq -e '.number | numbers' "$RUNNER_TEMP/pr/meta.json"`,
      },
      references: [
        { title: 'GitHub Security Lab — Keeping your GitHub Actions and workflows secure: untrusted artifacts', url: 'https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/' },
        { title: 'GitHub Docs — workflow_run event', url: 'https://docs.github.com/actions/writing-workflows/choosing-when-your-workflow-runs/events-that-trigger-workflows#workflow_run' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const w of workflows(ctx)) {
      if (!w.triggers.includes('workflow_run')) continue;
      for (const job of w.jobs) {
        job.steps.forEach((s, i) => {
          const how = downloadsTriggeringRun(s);
          if (!how) return;
          const later = job.steps.slice(i + 1).find((x) => x.run);
          findings.push({
            location: w.loc(s.index, lineLength(w, s.index)),
            message: `Job '${job.id}' (workflow_run) downloads artifacts produced by the triggering, possibly contributor-controlled run${later ? ' and then runs commands' : ''}; treat them as untrusted.`,
            confidence: later ? 'high' : 'medium',
            evidenceKind: 'pattern',
            evidence: [`${w.rel}: on workflow_run`, how, ...(later ? [`later step runs: ${later.run!.value.split('\n')[0]!.trim().slice(0, 80)}`] : [])],
          });
        });
      }
    }
    return findings;
  },
});
