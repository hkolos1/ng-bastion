// Verifies the static (SSG) build: every route is pre-rendered with SEO metadata, the sitemap and
// robots.txt are present, internal links resolve, brand assets exist, and no Astro/Starlight output
// remains. Exits non-zero on the first category of problems.
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SITE = 'https://ngbastion.dev';
const site = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const out = path.join(site, 'dist/analog/public');
const routes = JSON.parse(readFileSync(path.join(site, 'src/generated/routes.json'), 'utf8'));
const problems = [];
const problem = (m) => problems.push(m);

const htmlFor = (route) => path.join(out, route === '/' ? 'index.html' : `${route.slice(1)}/index.html`);
const attr = (html, re) => re.exec(html)?.[1];
const canonical = (route) => (route === '/' ? `${SITE}/` : `${SITE}${route}/`);
const assetExists = (href) => existsSync(path.join(out, decodeURIComponent(href.split(/[?#]/)[0])));
const routeSet = new Set(routes);

for (const route of routes) {
  const file = htmlFor(route);
  if (!existsSync(file)) {
    problem(`${route}: not pre-rendered (${path.relative(site, file)} missing)`);
    continue;
  }
  const html = readFileSync(file, 'utf8');
  const title = attr(html, /<title>([^<]+)<\/title>/);
  if (!title || title === 'NgBastion') problem(`${route}: missing page-specific <title>`);
  if (!attr(html, /<meta name="description" content="([^"]{20,})"/)) problem(`${route}: missing meta description`);
  const canon = attr(html, /<link rel="canonical" href="([^"]+)"/);
  if (canon !== canonical(route)) problem(`${route}: canonical ${canon} ≠ ${canonical(route)}`);
  if (attr(html, /<meta property="og:url" content="([^"]+)"/) !== canonical(route)) problem(`${route}: og:url mismatch`);
  if (!html.includes(`<meta property="og:image" content="${SITE}/brand/social-preview.png"`)) problem(`${route}: og:image missing`);
  if (!html.includes('<meta name="twitter:card" content="summary_large_image"')) problem(`${route}: twitter:card missing`);
  const h1 = (html.match(/<h1[\s>]/g) ?? []).length;
  if (h1 !== 1) problem(`${route}: expected exactly one <h1>, found ${h1}`);
  if (/data-astro|astro-island|\/_astro\/|class="sl-|starlight-theme|pagefind/.test(html)) problem(`${route}: contains Astro/Starlight output`);
  if (!html.includes('<ngb-root')) problem(`${route}: not rendered by the Angular application`);
  for (const [, href] of html.matchAll(/href="(\/[^"]*)"/g)) {
    if (href.startsWith('//')) continue;
    const pathOnly = href.split(/[?#]/)[0].replace(/\/$/, '') || '/';
    if (!routeSet.has(pathOnly) && !assetExists(href)) problem(`${route}: broken internal link ${href}`);
  }
}

const home = readFileSync(htmlFor('/'), 'utf8');
if (!/<script type="application\/ld\+json"[^>]*>\{"@context":"https:\/\/schema.org","@type":"SoftwareApplication"/.test(home)) problem('/: SoftwareApplication JSON-LD missing');
if (!home.includes('Your Angular security stronghold.')) problem('/: tagline missing');
if (!home.includes('captured when this site was built')) problem('/: real-scan terminal demo missing');
const playground = readFileSync(htmlFor('/playground'), 'utf8');
if (!playground.includes('this page does not scan arbitrary input')) problem('/playground: demonstration label missing');

const sitemap = existsSync(path.join(out, 'sitemap.xml')) ? readFileSync(path.join(out, 'sitemap.xml'), 'utf8') : '';
for (const route of routes) if (!sitemap.includes(`<loc>${canonical(route)}</loc>`)) problem(`sitemap.xml: ${canonical(route)} missing`);
const robots = existsSync(path.join(out, 'robots.txt')) ? readFileSync(path.join(out, 'robots.txt'), 'utf8') : '';
if (!robots.includes(`Sitemap: ${SITE}/sitemap.xml`)) problem('robots.txt: sitemap reference missing');
for (const asset of ['favicon.svg', 'brand/social-preview.png', 'brand/logo-mark-dark.svg', 'brand/logo-mark-light.svg', 'brand/apple-touch-icon.png']) {
  if (!existsSync(path.join(out, asset))) problem(`asset missing: ${asset}`);
}
const walk = (d) => readdirSync(d).flatMap((f) => (statSync(path.join(d, f)).isDirectory() ? walk(path.join(d, f)) : [path.join(d, f)]));
if (walk(out).some((f) => /pagefind|_astro/.test(f))) problem('build output contains Astro/Starlight artifacts');

if (problems.length) {
  console.error(`verify-build: ${problems.length} problem(s)\n  ${problems.join('\n  ')}`);
  process.exit(1);
}
console.log(`verify-build: ${routes.length} pre-rendered routes with canonical/Open Graph metadata, sitemap, robots.txt and resolvable internal links`);
