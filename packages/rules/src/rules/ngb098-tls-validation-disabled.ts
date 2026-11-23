import type * as ts from 'typescript';
import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { codeFiles, memberName, receiverOf, relative, strip } from '../shared/common.js';
import { readJson, textLocation } from '../shared/files.js';
import { configFiles, rcEntries } from '../shared/workflows.js';

const ENV = 'NODE_TLS_REJECT_UNAUTHORIZED';
/** TLS options that turn off certificate validation when set to `false` (Node tls/https, request, got, superagent). */
const OPTIONS = new Set(['rejectUnauthorized', 'strictSSL']);

function isFalse(ctx: { ts: typeof ts }, e: ts.Expression): boolean {
  return e.kind === ctx.ts.SyntaxKind.FalseKeyword;
}

export const ngb098 = defineRule({
  meta: {
    id: 'NGB098',
    name: 'TLS certificate validation disabled',
    category: 'security-config',
    defaultSeverity: 'high',
    cwe: ['CWE-295'],
    docs: {
      description:
        'Reports code and configuration that switch off TLS certificate validation for Node.js clients (SSR servers, BFFs, build and tooling scripts): `process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"`, `rejectUnauthorized: false` / `strictSSL: false` in TLS, `https.Agent`, axios, got or request options, and `NODE_TLS_REJECT_UNAUTHORIZED=0` in `.env` files and `package.json` scripts.',
      rationale:
        'Without certificate validation, TLS still encrypts but no longer authenticates the server: anyone on the network path can impersonate the API, read the credentials and session cookies the SSR server forwards, and return forged data that is then rendered to users. `NODE_TLS_REJECT_UNAUTHORIZED=0` disables validation for every connection of the process, including database and identity-provider calls.',
      patterns: [
        '`process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"` (also element access and numeric `0`)',
        '`{ rejectUnauthorized: false }` / `{ strictSSL: false }` object properties in TypeScript / JavaScript',
        '`NODE_TLS_REJECT_UNAUTHORIZED=0` in `.env*` files and `package.json` scripts (medium severity)',
      ],
      limitations: [
        'Custom `checkServerIdentity` callbacks and certificate pinning bypasses are not analyzed.',
        'Angular dev-server proxy `"secure": false` (development only) is not reported.',
        'Values set in CI configuration or the deployment environment are not visible.',
      ],
      falsePositives: [
        'Code that only talks to a loopback service with a self-signed certificate is reported; trust that certificate explicitly with `ca:` instead.',
      ],
      remediation:
        'Remove the override. For internal or self-signed certificates, pass the issuing CA (`ca: fs.readFileSync(\'internal-ca.pem\')` or `NODE_EXTRA_CA_CERTS`) so validation stays on.',
      example: {
        unsafe: `const agent = new https.Agent({ rejectUnauthorized: false });`,
        safe: `const agent = new https.Agent({ ca: readFileSync('certs/internal-ca.pem') });`,
      },
      references: [
        { title: 'Node.js — NODE_TLS_REJECT_UNAUTHORIZED', url: 'https://nodejs.org/api/cli.html#node_tls_reject_unauthorizedvalue' },
        { title: 'Node.js — tls.connect() rejectUnauthorized', url: 'https://nodejs.org/api/tls.html#tlsconnectoptions-callback' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    for (const a of ctx.index.assignments) {
      const left = strip(ctx, a.left);
      if (memberName(ctx, left) !== ENV || memberName(ctx, receiverOf(ctx, left) ?? left) !== 'env') continue;
      const v = strip(ctx, a.right);
      const value = ctx.symbols.constantString(v) ?? (t.isNumericLiteral(v) ? v.text : undefined);
      if (value !== '0') continue;
      findings.push({ node: a, message: `${ENV} is set to 0: the whole Node.js process accepts any TLS certificate, so every HTTPS connection can be intercepted.`, confidence: 'high', evidenceKind: 'pattern', evidence: [`${ENV} = ${JSON.stringify(value)}`] });
    }
    for (const sf of codeFiles(ctx)) {
      if (!/rejectUnauthorized|strictSSL/.test(sf.text)) continue;
      const visit = (n: ts.Node): void => {
        if (t.isPropertyAssignment(n) && (t.isIdentifier(n.name) || t.isStringLiteral(n.name)) && OPTIONS.has(n.name.text) && isFalse(ctx, strip(ctx, n.initializer))) {
          findings.push({ node: n, message: `${n.name.text}: false disables TLS certificate validation for this client; a network attacker can impersonate the server.`, confidence: 'high', evidenceKind: 'pattern', evidence: [`${n.name.text}: false`] });
        }
        t.forEachChild(n, visit);
      };
      visit(sf);
    }
    for (const file of configFiles(ctx, '**/.env*')) {
      const text = ctx.readFile(file);
      if (text === undefined) continue;
      for (const e of rcEntries(text)) {
        if (e.key !== ENV || e.value.trim() !== '0') continue;
        findings.push({ location: textLocation(file, text, e.index, e.length), message: `${relative(ctx, file)} sets ${ENV}=0; processes loading it accept any TLS certificate.`, confidence: 'high', severity: 'medium', evidenceKind: 'pattern', evidence: [`${relative(ctx, file)}: ${ENV}=0`] });
      }
    }
    for (const file of configFiles(ctx, '**/package.json')) {
      const parsed = readJson(ctx, file);
      const scripts = (parsed?.json as { scripts?: Record<string, unknown> } | undefined)?.scripts;
      if (!parsed || !scripts || typeof scripts !== 'object') continue;
      for (const [name, cmd] of Object.entries(scripts)) {
        if (typeof cmd !== 'string' || !new RegExp(`\\b${ENV}=['"]?0\\b`).test(cmd)) continue;
        findings.push({ location: textLocation(file, parsed.text, parsed.text.indexOf(JSON.stringify(name)), name.length + 2), message: `Script "${name}" runs with ${ENV}=0; it accepts any TLS certificate.`, confidence: 'high', severity: 'medium', evidenceKind: 'pattern', evidence: [`${relative(ctx, file)} scripts.${name}: ${cmd}`] });
      }
    }
    return findings;
  },
});
