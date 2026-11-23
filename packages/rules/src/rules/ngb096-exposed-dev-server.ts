import { defineRule, type RuleFinding, type Severity } from '@ngbastion/plugin-api';
import path from 'node:path';
import { relative } from '../shared/common.js';
import { readJson, textLocation } from '../shared/files.js';
import { configFiles } from '../shared/workflows.js';

const ALL_INTERFACES = /^(0\.0\.0\.0|::|\[::\]|\*)$/;

interface Issue { severity: Severity; what: string }

function serveIssues(o: Record<string, unknown>): Issue[] {
  const out: Issue[] = [];
  if (o.disableHostCheck === true) out.push({ severity: 'medium', what: 'disableHostCheck: true' });
  const ah = o.allowedHosts;
  if (ah === true || (Array.isArray(ah) && ah.some((h) => h === 'all' || h === '*' || h === '.'))) out.push({ severity: 'medium', what: `allowedHosts: ${JSON.stringify(ah)}` });
  if (typeof o.host === 'string' && ALL_INTERFACES.test(o.host)) out.push({ severity: 'low', what: `host: "${o.host}"` });
  return out;
}

function scriptIssues(cmd: string): Issue[] {
  if (!/\bng\s+serve\b|\bng\s+s\b/.test(cmd)) return [];
  const out: Issue[] = [];
  if (/--disable-host-check\b|--disableHostCheck(?:[= ]true)?\b/.test(cmd)) out.push({ severity: 'medium', what: '--disable-host-check' });
  if (/--allowed-hosts[= ](all|\*|true)\b/.test(cmd)) out.push({ severity: 'medium', what: '--allowed-hosts all' });
  const host = /--host[= ](\S+)/.exec(cmd)?.[1]?.replace(/^['"]|['"]$/g, '');
  if (host && ALL_INTERFACES.test(host)) out.push({ severity: 'low', what: `--host ${host}` });
  return out;
}

const WHY: Record<string, string> = {
  low: 'listens on every network interface; anyone on the same network can load the unminified app and its source maps',
  medium: 'accepts requests for any Host name, so a malicious website can read the dev server through DNS rebinding',
};

export const ngb096 = defineRule({
  meta: {
    id: 'NGB096',
    name: 'Development server exposed to the network',
    category: 'security-config',
    defaultSeverity: 'low',
    cwe: ['CWE-1327', 'CWE-350'],
    docs: {
      description:
        'Reports Angular dev-server settings that expose `ng serve` beyond the developer\'s machine: `serve` target options / configurations in `angular.json` with `host: "0.0.0.0"` (or `::`), `disableHostCheck: true` or `allowedHosts: true` / `["all"]`, and `ng serve` commands in `package.json` scripts with `--host 0.0.0.0`, `--disable-host-check` or `--allowed-hosts all`.',
      rationale:
        'The dev server serves unminified code, source maps, proxied backend APIs (with the developer\'s cookies through `proxy.conf.json`) and environment files. Binding it to all interfaces publishes all of that on café and office networks. Disabling the Host check is worse: any website the developer visits can use DNS rebinding to make the browser read the dev server, and the proxied APIs, cross-origin.',
      patterns: [
        '`angular.json` → `architect|targets.serve.options|configurations.*`: `host` = `0.0.0.0` / `::` (low), `disableHostCheck: true`, `allowedHosts: true | ["all"]` (medium)',
        '`package.json` scripts running `ng serve` with `--host 0.0.0.0` (low), `--disable-host-check`, `--allowed-hosts all` (medium)',
      ],
      limitations: [
        'Vite / webpack dev-server configuration files and Docker / devcontainer port mappings are not read.',
        'Whether the machine is reachable from untrusted networks (firewall, container) is not known.',
      ],
      falsePositives: [
        'Containers and devcontainers often need `--host 0.0.0.0` inside the container; the finding is low severity and can be accepted with an exception when ports are only published to localhost.',
      ],
      remediation:
        'Keep the default host (`localhost`) and Host check. If the server must be reachable from a container or device, bind it to that interface only and list explicit `allowedHosts` names instead of disabling the check.',
      example: {
        unsafe: `"start": "ng serve --host 0.0.0.0 --disable-host-check"`,
        safe: `"start": "ng serve"`,
      },
      references: [
        { title: 'Angular CLI — ng serve options (host, allowedHosts)', url: 'https://angular.dev/cli/serve' },
        { title: 'webpack-dev-server — allowedHosts and DNS rebinding', url: 'https://webpack.js.org/configuration/dev-server/#devserverallowedhosts' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    const add = (file: string, text: string, anchor: number, len: number, where: string, issue: Issue) => findings.push({
      location: textLocation(file, text, Math.max(0, anchor), len),
      message: `${where}: ${issue.what} — the dev server ${WHY[issue.severity]}.`,
      confidence: 'high',
      severity: issue.severity,
      evidenceKind: 'pattern',
      evidence: [`${relative(ctx, file)}: ${issue.what}`],
    });
    const p = ctx.project.angularProject as { architect?: Record<string, unknown>; targets?: Record<string, unknown> } | undefined;
    const serve = (p?.architect ?? p?.targets)?.serve as { options?: Record<string, unknown>; configurations?: Record<string, Record<string, unknown>> } | undefined;
    const ng = [ctx.project.root, ctx.project.workspaceRoot].map((d) => path.join(d, 'angular.json')).find((f) => ctx.readFile(f) !== undefined);
    if (serve && ng) {
      const text = ctx.readFile(ng)!;
      const blocks: [string, Record<string, unknown> | undefined][] = [['serve options', serve.options], ...Object.entries(serve.configurations ?? {}).map(([k, v]) => [`serve configuration '${k}'`, v] as [string, Record<string, unknown>])];
      for (const [where, o] of blocks) {
        if (!o || typeof o !== 'object') continue;
        for (const issue of serveIssues(o)) {
          const key = `"${issue.what.split(':')[0]}"`;
          add(ng, text, text.indexOf(key, Math.max(0, text.indexOf('"serve"'))), key.length, `angular.json ${where}`, issue);
        }
      }
    }
    for (const file of configFiles(ctx, '**/package.json')) {
      const parsed = readJson(ctx, file);
      const scripts = (parsed?.json as { scripts?: Record<string, unknown> } | undefined)?.scripts;
      if (!parsed || !scripts || typeof scripts !== 'object') continue;
      for (const [name, cmd] of Object.entries(scripts)) {
        if (typeof cmd !== 'string') continue;
        for (const issue of scriptIssues(cmd)) add(file, parsed.text, parsed.text.indexOf(JSON.stringify(name)), name.length + 2, `script "${name}"`, issue);
      }
    }
    return findings;
  },
});
