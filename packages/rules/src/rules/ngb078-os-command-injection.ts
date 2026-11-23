import type * as ts from 'typescript';
import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { strip } from '../shared/common.js';
import { objectProp } from '../shared/http.js';
import { moduleCall, nodeModules } from '../shared/server.js';
import { flowFinding, taintedFlow } from '../shared/server-flow.js';

const CHILD_PROCESS = nodeModules('child_process');
/** Run their first argument through a shell. */
const SHELL_FNS = ['exec', 'execSync'];
/** Run a program directly; a shell only with `shell: true`. */
const DIRECT_FNS = ['execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork'];
/** Quoting / escaping helpers (shell-quote, shell-escape, shescape …). */
const SHELL_ESCAPE = /\b(quote|escape|shellEscape|shellQuote|escapeShellArg|shescape)\w*\(\)/i;

export const ngb078 = defineRule({
  meta: {
    id: 'NGB078',
    name: 'OS command injection',
    category: 'ssr',
    defaultSeverity: 'critical',
    cwe: ['CWE-78', 'CWE-88'],
    docs: {
      description:
        'Traces untrusted data (Express / Node request query, params, body, cookies and headers, `postMessage` data, URLs) into Node.js `child_process` calls that run a shell: the command string of `exec()` / `execSync()`, and the program or arguments of `execFile()` / `spawn()` (and their sync variants) when `shell: true` is set. Also reports a program name chosen by untrusted data for `spawn()` / `execFile()` without a shell, and `shelljs` `exec()`.',
      rationale:
        "SSR servers, API routes and build helpers sometimes shell out to tools (image converters, PDF renderers, git). When request data becomes part of a shell command line, `;`, `&&`, `$(…)` or backticks run arbitrary commands with the server's privileges — remote code execution on the machine that holds your secrets and session keys.",
      patterns: [
        "`exec(cmd)` / `execSync(cmd)` from `child_process` / `node:child_process` (named import, namespace / default import, `require()`), and `shell.exec(cmd)` from `shelljs`, where `cmd` contains traced untrusted data (critical)",
        '`execFile(file, args, { shell: true })`, `spawn(cmd, args, { shell: true })` and sync variants with untrusted program or arguments (critical)',
        '`spawn(file, …)` / `execFile(file, …)` without a shell where the program itself is untrusted (high)',
        'Recognized mitigation: values passed through a shell-quoting helper (`quote()` from shell-quote, `shellEscape()`, `shescape`), numeric conversion',
      ],
      limitations: [
        'Arguments passed to `spawn()` / `execFile()` without a shell are not reported, although option injection (`--upload-pack=…`, `-o`) can still be possible for some programs.',
        'Process helpers other than `child_process` and `shelljs` (execa, zx `$`) are not modeled.',
        'Allowlist checks are not recognized; validated values are still reported (document an exception).',
      ],
      falsePositives: [
        'Values validated against a strict allowlist before reaching the command are reported; prefer `execFile()` with an argument array so the check is not needed.',
      ],
      remediation:
        'Do not build shell command lines from request data. Use `execFile()` / `spawn()` with a fixed program and an argument array (no `shell: true`), validate each argument against an allowlist or strict pattern, and pass `--` before user-supplied operands.',
      example: {
        unsafe: "exec(`convert ${req.query.file} out.png`);",
        safe: "execFile('convert', ['--', path.basename(String(req.query.file)), 'out.png']);",
      },
      references: [
        { title: 'OWASP — OS Command Injection Defense Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html' },
        { title: 'Node.js — child_process', url: 'https://nodejs.org/api/child_process.html' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    const t = ctx.ts;
    const report = (call: ts.CallExpression, value: ts.Expression | undefined, what: string, severity: 'critical' | 'high') => {
      if (!value) return false;
      const tv = taintedFlow(ctx, value, { sanitizers: SHELL_ESCAPE });
      if (!tv) return false;
      findings.push(flowFinding(ctx, call, tv, what, `Untrusted data (${tv.flow.source.description}) reaches ${what}; shell metacharacters in it run arbitrary commands on the server.`, { severity }));
      return true;
    };
    for (const call of ctx.index.calls) {
      const fn = moduleCall(ctx, call, CHILD_PROCESS, [...SHELL_FNS, ...DIRECT_FNS]) ?? (moduleCall(ctx, call, ['shelljs'], ['exec']) ? 'shell.exec' : undefined);
      if (!fn) continue;
      const [first, second, third] = call.arguments;
      if (SHELL_FNS.includes(fn) || fn === 'shell.exec') {
        report(call, first, `${fn}() command line`, 'critical');
        continue;
      }
      if (fn === 'fork') continue; // runs a Node.js module, not a shell
      const options = second && t.isArrayLiteralExpression(strip(ctx, second)) ? third : second && !t.isArrayLiteralExpression(strip(ctx, second)) ? second : third;
      const shellOpt = objectProp(ctx, options, 'shell');
      const shell = !!shellOpt && strip(ctx, shellOpt).kind !== t.SyntaxKind.FalseKeyword;
      if (shell) {
        if (report(call, first, `${fn}() with shell: true`, 'critical')) continue;
        if (second && t.isArrayLiteralExpression(strip(ctx, second))) {
          for (const a of (strip(ctx, second) as ts.ArrayLiteralExpression).elements) if (report(call, a, `${fn}() argument with shell: true`, 'critical')) break;
        }
      } else {
        report(call, first, `${fn}() program name`, 'high');
      }
    }
    return findings;
  },
});
