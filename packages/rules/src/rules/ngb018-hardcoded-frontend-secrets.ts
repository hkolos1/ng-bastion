import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding, type SourceLocation } from '@ngbastion/plugin-api';
import { memberName, relative } from '../shared/common.js';
import { classifySecret, redact, type SecretMatch } from '../shared/secrets.js';

const JSON_GLOBS = [
  '**/environment*.json',
  '**/environments/**/*.json',
  'src/assets/**/*.json',
  'public/**/*.json',
  '**/config*.json',
  '**/settings*.json',
  '**/appsettings*.json',
];
const IGNORED_JSON = /(^|\/)(package(-lock)?|tsconfig[^/]*|angular|project|nx|ngbastion\.config|firebase|vercel|staticwebapp\.config)\.json$/;

function assignedName(ctx: Pick<AnalysisContext, 'ts'>, lit: ts.Node): string | undefined {
  const t = ctx.ts;
  let p = lit.parent;
  while (p && (t.isParenthesizedExpression(p) || t.isAsExpression(p) || t.isSatisfiesExpression(p))) p = p.parent;
  if (!p) return undefined;
  if ((t.isVariableDeclaration(p) || t.isPropertyDeclaration(p) || t.isPropertyAssignment(p)) && p.initializer === lit) {
    return p.name.getText().replace(/['"`]/g, '');
  }
  if (t.isBinaryExpression(p) && p.right === lit) return memberName(ctx, p.left) ?? (t.isIdentifier(p.left) ? p.left.text : undefined);
  return undefined;
}

function isNonValueLiteral(ctx: Pick<AnalysisContext, 'ts'>, lit: ts.Node): boolean {
  const t = ctx.ts;
  const p = lit.parent;
  return t.isImportDeclaration(p) || t.isExportDeclaration(p) || t.isExternalModuleReference(p) || t.isLiteralTypeNode(p)
    || (t.isPropertyAssignment(p) && p.name === lit) || (t.isElementAccessExpression(p) && p.argumentExpression === lit)
    || (t.isCallExpression(p) && p.expression.kind === t.SyntaxKind.ImportKeyword);
}

function finding(location: SourceLocation | undefined, node: ts.Node | undefined, value: string, m: SecretMatch, where: string): RuleFinding {
  return {
    ...(node ? { node } : {}),
    ...(location ? { location } : {}),
    message: `Possible ${m.kind} hardcoded ${where} (${redact(value)}). Everything bundled into a frontend is readable by any visitor.`,
    confidence: m.confidence,
    ...(m.severity ? { severity: m.severity } : {}),
    evidenceKind: m.kind.startsWith('high-entropy') ? 'heuristic' : 'pattern',
    evidence: [`matched: ${m.kind}`, 'value redacted in this report'],
    redactSnippet: true,
  };
}

/** The TypeScript source pass, shared with the isolated browser snippet worker. */
export function inspectSecretLiterals(ctx: Pick<AnalysisContext, 'ts'>, literals: Iterable<ts.StringLiteralLike>): RuleFinding[] {
  const findings: RuleFinding[] = [];
  for (const lit of literals) {
    if (isNonValueLiteral(ctx, lit)) continue;
    const name = assignedName(ctx, lit);
    const m = classifySecret(lit.text, name);
    if (m) findings.push(finding(undefined, lit, lit.text, m, 'in frontend source'));
  }
  return findings;
}

export const ngb018 = defineRule({
  meta: {
    id: 'NGB018',
    name: 'Hardcoded frontend secrets',
    category: 'sensitive-data',
    defaultSeverity: 'high',
    cwe: ['CWE-798'],
    docs: {
      description:
        'Reports string literals in TypeScript sources and JSON configuration (environment files, `src/assets`, `public`) that match the format of a private credential (Stripe secret keys, AWS access key IDs, GitHub/Slack/npm/SendGrid/OpenAI/Anthropic tokens, PEM private keys, JWTs) or high-entropy values assigned to names such as `clientSecret`, `apiSecret`, `password` or `privateKey`. Reported values are always redacted.',
      rationale:
        'Frontend bundles are public. Any secret compiled into them can be extracted with the browser developer tools and used to call the backing service with your privileges, often for a long time because frontend secrets are rarely rotated.',
      patterns: [
        'Known private formats: `sk_live_` / `rk_live_` (critical), `sk_test_` (low severity), `AKIA…`, `ghp_` / `github_pat_`, `xox[baprs]-`, `-----BEGIN … PRIVATE KEY-----`, `sk-ant-`, `sk-proj-`, `SG.…`, `npm_…`, `eyJ….eyJ….…` (JWT)',
        'Generic: literal assigned to a variable/property whose name ends in `secret`, `password`, `privateKey`, `clientSecret`, `apiSecret`, `accessToken`, … with length ≥ 16, no whitespace and Shannon entropy ≥ 3 bits/char (≥ 4 → medium confidence)',
        'Not reported: Stripe publishable keys (`pk_…`), Google/Firebase browser API keys (`AIza…`), OAuth client IDs, names containing `public`/`publishable`/`clientId`/`siteKey`, placeholders (`changeme`, `<…>`, `${…}`, `your-…`, `example`, `dummy`, `test…`)',
      ],
      limitations: [
        'Secrets split across several literals, encoded (base64) or fetched at runtime are not detected.',
        'Only JSON files matching the configured globs are inspected; `.env` files are not read (they are not bundled by the Angular CLI).',
        'Whether a key is actually privileged cannot be verified offline; validity is never checked against the provider.',
      ],
      falsePositives: [
        'Generated identifiers with high entropy assigned to a `secret`-named property in mocks or demo data.',
        'Test-mode keys are reported with low severity because they still grant access to test data.',
      ],
      remediation:
        'Remove the secret from the frontend, rotate it immediately, and move the privileged call behind your backend (or a backend-for-frontend). Only publishable/public identifiers belong in Angular environment files.',
      example: {
        unsafe: `export const environment = { paymentsSecretKey: 'sk_live_…' };`,
        safe: `export const environment = { paymentsPublishableKey: 'pk_live_…' }; // secret key stays on the server`,
      },
      references: [{ title: 'OWASP — Use of hard-coded credentials', url: 'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password' }],
    },
  },
  analyze(ctx) {
    const findings = inspectSecretLiterals(ctx, ctx.index.stringLiterals);

    const files = new Set(JSON_GLOBS.flatMap((g) => ctx.findFiles(g)));
    for (const file of files) {
      if (IGNORED_JSON.test(file.replace(/\\/g, '/'))) continue;
      const text = ctx.readFile(file);
      if (!text) continue;
      let json: unknown;
      try {
        json = JSON.parse(text);
      } catch {
        ctx.diagnostic({ code: 'json-invalid', level: 'info', message: `NGB018: ${relative(ctx, file)} is not valid JSON; skipped`, file });
        continue;
      }
      const walk = (v: unknown, key?: string) => {
        if (typeof v === 'string') {
          const m = classifySecret(v, key);
          if (m) findings.push(finding(locate(text, file, v), undefined, v, m, `in ${relative(ctx, file)}`));
        } else if (Array.isArray(v)) v.forEach((x) => walk(x, key));
        else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) walk(x, k);
      };
      walk(json);
    }
    return findings;
  },
});

function locate(text: string, file: string, value: string): SourceLocation {
  const needle = JSON.stringify(value);
  const idx = Math.max(0, text.indexOf(needle));
  const before = text.slice(0, idx).split(/\r?\n/);
  const line = before.length;
  const column = before[before.length - 1]!.length + 1;
  return { file, line, column, endLine: line, endColumn: column + needle.length };
}
