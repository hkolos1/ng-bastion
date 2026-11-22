// Generates all website content from the real NgBastion packages (never hand-copied):
// - rule reference pages from @ngbastion/rules metadata
// - CLI reference from the built CLI's --help output
// - landing demo from a real scan of examples/vulnerable-showcase
// - playground results from real scans of playground-fixtures/*
// - changelog page from the repository CHANGELOG.md
// Then renders every markdown page (hand-written docs in content/docs + the generated pages) to
// HTML that passes Angular's sanitizer unchanged (class-based syntax highlighting, no inline
// styles), and writes navigation, search index, prerender route list and sitemap.
// Requires `pnpm build` at the repository root first (uses packages' dist output).
import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Marked } from 'marked';
import { createHighlighter } from 'shiki';
import { transformerStyleToClass } from '@shikijs/transformers';
import { loadConfig, resolveConfig, PRESETS } from '@ngbastion/config';
import { scan } from '@ngbastion/core';
import { builtinRules } from '@ngbastion/rules';

export const SITE = 'https://ngbastion.dev';
const site = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repo = path.resolve(site, '../..');
const handwritten = path.join(site, 'content/docs');
const genContent = path.join(site, 'content/generated');
const generated = path.join(site, 'src/generated');
const fail = (msg) => {
  console.error(`generate: ${msg}`);
  process.exit(1);
};

for (const d of [genContent, generated]) {
  rmSync(d, { recursive: true, force: true });
  mkdirSync(d, { recursive: true });
}
mkdirSync(path.join(genContent, 'rules'), { recursive: true });
mkdirSync(path.join(generated, 'pages'), { recursive: true });

const CATEGORY = {
  'angular-xss': 'Angular security & XSS',
  'cross-window': 'iframe & cross-window communication',
  'navigation-auth': 'Navigation & authentication',
  'sensitive-data': 'Sensitive data & payment security',
  'security-config': 'Security configuration',
  ssr: 'Angular SSR security',
};
const yaml = (s) => JSON.stringify(s);
const list = (items) => (items.length ? items.map((i) => `- ${i}`).join('\n') : '_None documented._');

// ---------------------------------------------------------------- rules (markdown)
for (const rule of builtinRules) {
  const m = rule.meta;
  const d = m.docs;
  const presets = Object.entries(PRESETS)
    .map(([name, p]) => [name, p.rules?.[m.id]])
    .filter(([, level]) => level)
    .map(([name, level]) => `\`${name}\`: ${level}`)
    .join(', ');
  const body = `---
title: ${yaml(`${m.id}: ${m.name}`)}
description: ${yaml(d.description.split('. ')[0].replace(/`/g, '') + '.')}
---

| Property | Value |
|---|---|
| **Rule ID** | \`${m.id}\` |
| **Category** | ${CATEGORY[m.category] ?? m.category} |
| **Default severity** | ${m.defaultSeverity} |
| **CWE** | ${(m.cwe ?? []).map((c) => `[${c}](https://cwe.mitre.org/data/definitions/${c.replace('CWE-', '')}.html)`).join(', ') || 'n/a'} |
| **Built-in presets** | ${presets || 'enabled through extends/presets inheritance'} |

Confidence is reported per finding (high, medium, low) and is independent of severity. See [Reading findings](/docs/getting-started/reading-findings/).

## What it checks

${d.description}

## Why it matters

${d.rationale}

## Detection behavior and supported patterns

${list(d.patterns)}

## Example

\`\`\`ts
${d.example.unsafe}
\`\`\`

## Safer alternative

\`\`\`ts
${d.example.safe}
\`\`\`

## Remediation

${d.remediation}

## False-positive considerations

${list(d.falsePositives)}

## Known limitations

${list(d.limitations)}
${d.references?.length ? `\n## References\n\n${d.references.map((r) => `- [${r.title}](${r.url})`).join('\n')}\n` : ''}
## Run it

\`\`\`sh
ngbastion explain ${m.id}
\`\`\`
`;
  writeFileSync(path.join(genContent, 'rules', `${m.id.toLowerCase()}.md`), body);
}

const byCategory = Object.entries(CATEGORY).map(([key, label]) => {
  const rows = builtinRules.filter((r) => r.meta.category === key)
    .map((r) => `| [${r.meta.id}](/rules/${r.meta.id.toLowerCase()}/) | ${r.meta.name} | ${r.meta.defaultSeverity} |`);
  return rows.length ? `## ${label}\n\n| ID | Rule | Default severity |\n|---|---|---|\n${rows.join('\n')}\n` : '';
}).join('\n');
writeFileSync(path.join(genContent, 'rules', 'index.md'), `---
title: Security rules
description: The ${builtinRules.length} built-in NgBastion rules for Angular applications, with detection boundaries, examples and remediation.
---

NgBastion ships ${builtinRules.length} built-in rules. Each page documents exactly which patterns the implementation recognizes, its known limitations and its false-positive considerations. A rule that is not listed here is not checked: the absence of findings never proves an application is secure.

${byCategory}
`);

// ---------------------------------------------------------------- CLI reference (markdown)
const cli = path.join(repo, 'packages/cli/dist/bin.js');
if (!existsSync(cli)) fail('packages/cli/dist/bin.js not found; run `pnpm build` at the repository root first');
const help = (args) => execFileSync(process.execPath, [cli, ...args], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } }).trimEnd();
const commands = [
  ['scan', 'Analyze an Angular workspace. Without a directory argument the current directory is scanned. Angular workspaces are discovered through `angular.json`; otherwise `tsconfig.json`, otherwise every `.ts` file in the directory.'],
  ['init', 'Create a configuration file. In an interactive terminal without `--format` you are asked for the format; in CI it defaults to JSON. Existing configuration is never overwritten without `--force`.'],
  ['explain', 'Print the full documentation of a rule: description, rationale, detected patterns, unsafe and safe examples, remediation, limitations and false-positive considerations.'],
  ['rules', 'List the available rules, optionally filtered.'],
  ['doctor', 'Check Node.js compatibility, configuration validity, Angular workspace detection, TypeScript project resolution, plugin compatibility and file accessibility. Doctor never modifies the project and exits with 2 when it finds a problem.'],
];
writeFileSync(path.join(genContent, 'cli-reference.md'), `---
title: CLI reference
description: Commands, options and exit codes of the ngbastion command-line interface.
---

:::note[Installation status]
The npm package is not published yet. Until it is, run the CLI from a clone of the repository: \`node packages/cli/dist/bin.js <command>\` (or \`pnpm ngbastion <command>\` from the repository root). The commands below use the intended \`ngbastion\` name.
:::

The help texts on this page are captured from the CLI at build time.

\`\`\`text
${help(['--help'])}
\`\`\`

${commands.map(([c, text]) => `## ngbastion ${c}\n\n${text}\n\n\`\`\`text\n${help([c, '--help'])}\n\`\`\`\n`).join('\n')}
## Exit codes

| Code | Meaning |
|---|---|
| \`0\` | Scan completed and the security gate passed (or \`--fail-on none\`). Other commands: success. |
| \`1\` | Security gate failed: at least one finding from a rule at level \`error\` has a severity at or above \`failOn\`. Findings from \`warn\` rules never fail the gate. |
| \`2\` | Configuration or execution error: invalid options or configuration, unloadable plugin, unknown project, a rule that crashed, or an error-level diagnostic. Treat it as "the scan result cannot be trusted". |

## Examples

\`\`\`sh
ngbastion scan                                  # terminal report, gate on high+
ngbastion scan --format sarif --output results.sarif
ngbastion scan --format json --fail-on critical
ngbastion scan apps/web --project admin --min-confidence low --verbose
ngbastion init --format ts --preset strict
ngbastion explain NGB013
ngbastion rules --category cross-window
\`\`\`

Colors follow the terminal: they are disabled when output is not a TTY, with \`--no-color\` or \`NO_COLOR\`, and forced with \`--color\` or \`FORCE_COLOR\`.
`);

// ---------------------------------------------------------------- showcase demo (JSON)
const showcase = path.join(repo, 'examples/vulnerable-showcase');
if (!existsSync(path.join(showcase, 'node_modules/@angular/core'))) fail('examples/vulnerable-showcase dependencies are not installed; run `pnpm install` at the repository root');
let showcaseData;
{
  const { config } = await loadConfig({ cwd: showcase });
  const r = await scan({ cwd: showcase, config, rules: builtinRules });
  const pick = (id, file) => r.findings.find((f) => f.ruleId === id && (!file || f.location.file.includes(file)));
  const featured = [pick('NGB001'), pick('NGB011'), pick('NGB020', 'profile.resolver')].filter(Boolean);
  if (featured.length < 3) fail('showcase scan did not produce the featured findings (NGB001, NGB011, NGB020)');
  const summary = {};
  for (const f of r.findings) summary[f.severity] = (summary[f.severity] ?? 0) + 1;
  showcaseData = {
    note: 'Output of `ngbastion scan` (recommended preset) on the repository\'s intentionally vulnerable showcase app, captured at build time.',
    version: r.tool.version,
    files: r.stats.filesAnalyzed,
    templates: r.stats.templatesAnalyzed,
    total: r.findings.length,
    rulesTriggered: new Set(r.findings.map((f) => f.ruleId)).size,
    ruleCount: builtinRules.length,
    hidden: r.stats.hiddenBelowConfidence,
    summary,
    gate: r.gate,
    featured: featured.map(({ ruleId, ruleName, severity, confidence, message, location, snippet, trace }) => ({ ruleId, ruleName, severity, confidence, message, location, snippet, trace })),
  };
  writeFileSync(path.join(generated, 'showcase.json'), JSON.stringify(showcaseData, null, 2));
}

// ---------------------------------------------------------------- playground (JSON)
const fixtures = path.join(site, 'playground-fixtures');
const EXAMPLES = {
  'sanitizer-bypass': { title: 'Sanitizer bypass', blurb: 'A query parameter is wrapped in markup and passed to bypassSecurityTrustHtml().' },
  'message-handler': { title: 'iframe message handling', blurb: 'A window message from an embedded payment frame decides where the user is redirected.' },
  'token-storage': { title: 'Sensitive token storage', blurb: 'A login flow stores and logs tokens returned by the API.' },
};
const ruleDocs = Object.fromEntries(builtinRules.map((r) => [r.meta.id, { name: r.meta.name, rationale: r.meta.docs.rationale, remediation: r.meta.docs.remediation }]));
const playground = [];
for (const [id, meta] of Object.entries(EXAMPLES)) {
  const variants = {};
  for (const variant of ['unsafe', 'safe']) {
    const dir = path.join(fixtures, id, variant);
    const files = readdirSync(dir).filter((f) => f.endsWith('.ts'));
    const config = await resolveConfig({ extends: ['recommended'], minConfidence: 'low' }, { cwd: dir });
    const r = await scan({ cwd: dir, config, rules: builtinRules });
    variants[variant] = {
      files: files.map((f) => ({ name: f, code: readFileSync(path.join(dir, f), 'utf8') })),
      findings: r.findings.map(({ ruleId, ruleName, severity, confidence, evidenceKind, message, location, trace }) => ({ ruleId, ruleName, severity, confidence, evidenceKind, message, location, trace })),
    };
  }
  if (!variants.unsafe.findings.length) fail(`playground example ${id}: unsafe variant produced no findings`);
  if (variants.safe.findings.length) fail(`playground example ${id}: safe variant produced findings: ${variants.safe.findings.map((f) => f.ruleId).join(', ')}`);
  playground.push({ id, ...meta, variants });
}
writeFileSync(path.join(generated, 'playground.json'), JSON.stringify({ examples: playground, rules: ruleDocs }, null, 2));

// ---------------------------------------------------------------- changelog (markdown)
const changelog = path.join(repo, 'CHANGELOG.md');
if (!existsSync(changelog)) fail('CHANGELOG.md not found at the repository root');
const changelogText = readFileSync(changelog, 'utf8').replace(/^# .*\n+/, '');
writeFileSync(path.join(genContent, 'changelog.md'), `---\ntitle: Changelog\ndescription: Notable changes to NgBastion, generated from the repository CHANGELOG.md.\n---\n\n${changelogText}`);

// ---------------------------------------------------------------- markdown → HTML
const walk = (dir) => readdirSync(dir).flatMap((f) => {
  const p = path.join(dir, f);
  return statSync(p).isDirectory() ? walk(p) : p.endsWith('.md') ? [p] : [];
});
/** slug → source file. Slugs have no leading/trailing slash: `docs`, `docs/cli-reference`, `rules/ngb001`. */
const sources = new Map();
for (const file of walk(handwritten)) {
  const rel = path.relative(handwritten, file).replace(/\\/g, '/').replace(/\.md$/, '');
  sources.set(rel === 'index' ? 'docs' : `docs/${rel.replace(/\/index$/, '')}`, file);
}
sources.set('docs/cli-reference', path.join(genContent, 'cli-reference.md'));
sources.set('changelog', path.join(genContent, 'changelog.md'));
sources.set('rules', path.join(genContent, 'rules/index.md'));
for (const r of builtinRules) sources.set(`rules/${r.meta.id.toLowerCase()}`, path.join(genContent, 'rules', `${r.meta.id.toLowerCase()}.md`));

function frontmatter(text, file) {
  const m = /^---\n([\s\S]*?)\n---\n/.exec(text);
  if (!m) fail(`${file}: missing frontmatter`);
  const data = {};
  for (const line of m[1].split('\n')) {
    const kv = /^(\w+):\s*(.*)$/.exec(line);
    if (!kv) continue;
    const v = kv[2].trim();
    data[kv[1]] = v.startsWith('"') ? JSON.parse(v) : v;
  }
  if (!data.title || !data.description) fail(`${file}: frontmatter needs title and description`);
  return { data, body: text.slice(m[0].length) };
}

const escapeHtml = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const slugify = (s) => s.toLowerCase().replace(/<[^>]+>/g, '').replace(/&[a-z]+;/g, '').replace(/[`*_]/g, '').replace(/[^\w\s-]/g, '').trim().replace(/\s+/g, '-');

const LANGS = ['ts', 'typescript', 'js', 'json', 'sh', 'bash', 'yaml', 'html', 'text'];
const highlighter = await createHighlighter({ themes: ['vitesse-dark', 'vitesse-light'], langs: LANGS.filter((l) => l !== 'text') });
// Converts Shiki's inline styles to classes: Angular's sanitizer removes `style` attributes.
const toClass = transformerStyleToClass({ classPrefix: 'sk-' });

function render(slug, text, file) {
  const { data, body } = frontmatter(text, file);
  const headings = [];
  const used = new Set();
  const marked = new Marked({ gfm: true });
  marked.use({
    renderer: {
      heading({ tokens, depth }) {
        const inner = this.parser.parseInline(tokens);
        let id = slugify(inner) || 'section';
        for (let i = 2; used.has(id); i++) id = `${slugify(inner)}-${i}`;
        used.add(id);
        if (depth === 2 || depth === 3) headings.push({ depth, id, text: inner.replace(/<[^>]+>/g, '') });
        // Placeholder split into a heading block below: Angular renders headings itself because
        // its sanitizer (rightly) removes `id` attributes from [innerHTML] content.
        return `\n<!--ngb-heading:${depth}:${id}-->${inner}<!--/ngb-heading-->\n`;
      },
      code({ text: code, lang }) {
        const language = LANGS.includes(lang) ? (lang === 'text' ? undefined : lang) : undefined;
        if (!language) return `<pre class="code code-plain"><code>${escapeHtml(code)}</code></pre>\n`;
        const html = highlighter.codeToHtml(code, { lang: language, themes: { dark: 'vitesse-dark', light: 'vitesse-light' }, defaultColor: false, transformers: [toClass] });
        return html.replace('<pre class="', '<pre class="code ').replace(/ tabindex="0"/, '');
      },
      table(token) {
        // Wrap tables so they scroll horizontally on small screens.
        return `<div class="table-wrap">${marked.Renderer.prototype.table.call(this, token)}</div>\n`;
      },
      // Raw HTML in markdown is shown as text (e.g. "<iframe>" in rule prose); only our callout wrappers pass.
      html({ text }) {
        return /^\s*<\/?aside[\s>]/.test(text) || /^<p class="callout-title">/.test(text.trim()) ? text : escapeHtml(text);
      },
      link({ href, title, tokens }) {
        const inner = this.parser.parseInline(tokens);
        const external = /^https?:\/\//.test(href);
        return `<a href="${escapeHtml(href)}"${title ? ` title="${escapeHtml(title)}"` : ''}${external ? ' class="external"' : ''}>${inner}</a>`;
      },
    },
  });
  // Callouts: `:::note[Title]` … `:::` (note | tip | caution | danger).
  const withCallouts = body.replace(/^:::(note|tip|caution|danger)(?:\[(.+?)\])?\n([\s\S]*?)\n:::[ \t]*$/gm, (_, kind, title, inner) =>
    `<aside class="callout callout-${kind}"><p class="callout-title">${escapeHtml(title ?? kind[0].toUpperCase() + kind.slice(1))}</p>\n\n${inner}\n\n</aside>\n`);
  const html = marked.parse(withCallouts, { async: false });
  const blocks = [];
  let rest = html;
  const re = /<!--ngb-heading:([23456]):([^>]+?)-->([\s\S]*?)<!--\/ngb-heading-->/;
  for (let m = re.exec(rest); m; m = re.exec(rest)) {
    const before = rest.slice(0, m.index).trim();
    if (before) blocks.push({ kind: 'html', html: before });
    blocks.push({ kind: 'heading', depth: Number(m[1]), id: m[2], html: m[3] });
    rest = rest.slice(m.index + m[0].length);
  }
  if (rest.trim()) blocks.push({ kind: 'html', html: rest.trim() });
  return { slug, title: data.title, description: data.description, blocks, headings };
}

/** Sidebar: same structure as the previous documentation site. */
const nav = [
  { label: 'Getting started', items: ['docs', 'docs/getting-started/installation', 'docs/getting-started/first-scan', 'docs/getting-started/reading-findings', 'docs/getting-started/compatibility'] },
  { label: 'Reference', items: ['docs/cli-reference', 'docs/configuration', 'docs/security-engine', 'docs/reports', 'docs/plugin-api', 'docs/ci-cd', 'docs/limitations'] },
  { label: 'Security rules', items: ['rules', ...builtinRules.map((r) => `rules/${r.meta.id.toLowerCase()}`)] },
  { label: 'Project', items: ['docs/contributing', 'docs/security-policy', 'changelog', 'playground'] },
];
const LABEL_OVERRIDES = { docs: 'What is NgBastion?', rules: 'All rules', playground: 'Playground', changelog: 'Changelog' };

const pages = {};
const search = [];
const plain = (html) => html.replace(/<pre[\s\S]*?<\/pre>/g, ' ').replace(/<[^>]+>/g, ' ').replace(/&[a-z#0-9]+;/g, ' ').replace(/\s+/g, ' ').trim();
for (const [slug, file] of sources) {
  const page = render(slug, readFileSync(file, 'utf8'), file);
  const section = slug.startsWith('rules') ? 'Security rules' : slug === 'changelog' ? 'Project' : 'Documentation';
  pages[slug] = { title: page.title, description: page.description, section };
  writeFileSync(path.join(generated, 'pages', `${slug.replace(/\//g, '__')}.json`), JSON.stringify({ ...page, section }));
  search.push({ slug, title: page.title, section, headings: page.headings.map((h) => h.text), text: plain(page.blocks.map((b) => b.html).join(' ')).slice(0, 4000) });
}
pages.playground = { title: 'Playground', description: 'Fixture-based NgBastion demonstration.', section: 'Project' };
for (const group of nav) for (const slug of group.items) if (!pages[slug]) fail(`navigation references unknown page ${slug}`);
const navOut = nav.map((g) => ({ label: g.label, items: g.items.map((slug) => ({ slug, label: LABEL_OVERRIDES[slug] ?? pages[slug].title.replace(/^(NGB\d+): /, '$1 · ') })) }));
const order = navOut.flatMap((g) => g.items.map((i) => i.slug)).filter((s) => s !== 'playground');
writeFileSync(path.join(generated, 'nav.json'), JSON.stringify({ groups: navOut, order }, null, 2));
writeFileSync(path.join(generated, 'search.json'), JSON.stringify(search));
writeFileSync(path.join(generated, 'shiki.css'), `/* Generated by scripts/generate.mjs (Shiki, class-based). */\n${toClass.getCSS()}\n`);

// Internal links must resolve to a page.
const routes = ['/', ...[...sources.keys()].map((s) => `/${s}`), '/playground'];
const routeSet = new Set(routes.map((r) => r.replace(/\/$/, '') || '/'));
for (const [slug] of sources) {
  const { blocks } = JSON.parse(readFileSync(path.join(generated, 'pages', `${slug.replace(/\//g, '__')}.json`), 'utf8'));
  const html = blocks.map((b) => b.html).join('\n');
  for (const [, href] of html.matchAll(/href="(\/[^"#?]*)/g)) {
    const target = href.replace(/\/$/, '') || '/';
    if (!routeSet.has(target) && !href.startsWith('/brand/')) fail(`${slug}: broken internal link ${href}`);
  }
}
writeFileSync(path.join(generated, 'routes.json'), JSON.stringify(routes, null, 2));

// ---------------------------------------------------------------- brand, sitemap
const brand = path.join(repo, 'assets/brand');
cpSync(brand, path.join(site, 'public/brand'), { recursive: true });
cpSync(path.join(brand, 'favicon.svg'), path.join(site, 'public/favicon.svg'));
const today = new Date().toISOString().slice(0, 10);
writeFileSync(path.join(site, 'public/sitemap.xml'), `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${routes.map((r) => `  <url><loc>${SITE}${r === '/' ? '/' : `${r}/`}</loc><lastmod>${today}</lastmod></url>`).join('\n')}
</urlset>
`);

console.log(`generate: ${builtinRules.length} rule pages, ${sources.size} content pages, showcase demo, ${playground.length} playground examples, ${routes.length} routes`);
