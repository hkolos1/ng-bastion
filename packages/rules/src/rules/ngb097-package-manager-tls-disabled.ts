import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { relative } from '../shared/common.js';
import { textLocation } from '../shared/files.js';
import { isPlaintextRemote } from '../shared/http.js';
import { configFiles, rcEntries } from '../shared/workflows.js';

const STRICT_SSL = /^(strict-ssl|strictSsl|enableStrictSsl)$/i;
const REGISTRY = /^((@[\w.-]+:)?registry|npmRegistryServer)$/i;

export const ngb097 = defineRule({
  meta: {
    id: 'NGB097',
    name: 'Package manager TLS verification disabled',
    category: 'supply-chain',
    defaultSeverity: 'high',
    cwe: ['CWE-295', 'CWE-494'],
    docs: {
      description:
        'Reads committed package-manager configuration (`.npmrc`, `.yarnrc`, `.yarnrc.yml` in the project and the workspace root) and reports disabled TLS certificate verification (`strict-ssl=false`, yarn `strict-ssl false`, `enableStrictSsl: false`) and registries over plain HTTP (`registry=http://…`, `@scope:registry=http://…`, `npmRegistryServer: "http://…"`).',
      rationale:
        'Every install downloads code that runs on developer machines and in CI (`postinstall` scripts, build tooling). Without certificate verification, or over plain HTTP, anyone on the network path — a compromised proxy, hostile Wi-Fi, a DNS spoof — can swap packages and gain code execution with access to CI secrets. A committed `.npmrc` applies the setting to everyone who clones the repository.',
      patterns: [
        '`strict-ssl=false` / `strict-ssl = false` (`.npmrc`, also read by pnpm), `strict-ssl false` (yarn 1), `enableStrictSsl: false` (yarn 2+)',
        '`registry=http://…`, `@scope:registry=http://…`, `registry "http://…"`, `npmRegistryServer: "http://…"` (loopback and private-network hosts excluded)',
      ],
      limitations: [
        'User-level (`~/.npmrc`) and CI-provided configuration, environment variables (`npm_config_strict_ssl`) and CLI flags are not visible.',
        'Yarn 2+ `unsafeHttpWhitelist` and per-scope `npmScopes` blocks are not interpreted.',
      ],
      falsePositives: [
        'Corporate TLS-intercepting proxies are a common reason; configure the proxy\'s CA with `cafile=` instead of disabling verification.',
      ],
      remediation:
        'Remove `strict-ssl=false` and use HTTPS registries. Behind a TLS-intercepting proxy, trust its CA explicitly (`cafile=/path/to/corp-ca.pem` or `NODE_EXTRA_CA_CERTS`).',
      example: {
        unsafe: `strict-ssl=false
registry=http://registry.npmjs.org/`,
        safe: `registry=https://registry.npmjs.org/
cafile=./certs/corp-proxy-ca.pem`,
      },
      references: [
        { title: 'npm Docs — strict-ssl', url: 'https://docs.npmjs.com/cli/using-npm/config#strict-ssl' },
        { title: 'Yarn — enableStrictSsl', url: 'https://yarnpkg.com/configuration/yarnrc#enableStrictSsl' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const file of ['**/.npmrc', '**/.yarnrc', '**/.yarnrc.yml'].flatMap((g) => configFiles(ctx, g))) {
      const text = ctx.readFile(file);
      if (text === undefined) continue;
      for (const e of rcEntries(text)) {
        let why: string | undefined;
        if (STRICT_SSL.test(e.key) && /^false$/i.test(e.value)) why = 'TLS certificate verification is disabled for package downloads';
        else if (REGISTRY.test(e.key) && isPlaintextRemote(e.value, 'http')) why = `the registry ${e.value} is used over plain HTTP`;
        if (!why) continue;
        findings.push({
          location: textLocation(file, text, e.index, e.length),
          message: `${relative(ctx, file)}: ${why}; a network attacker can replace installed packages.`,
          confidence: 'high',
          evidenceKind: 'pattern',
          evidence: [`${relative(ctx, file)}: ${e.key} ${e.value}`],
        });
      }
    }
    return findings;
  },
});
