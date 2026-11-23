# @ngbastion/website

Source of **[ngbastion.web.app](https://ngbastion.web.app)** — an Angular 22 application built with [AnalogJS](https://analogjs.org)
(Vite) and Tailwind CSS v4, statically pre-rendered (SSG) for every route:

| Route | Source |
|---|---|
| `/` | `src/app/home/` — landing page with a terminal demo of a real scan |
| `/docs`, `/docs/**` | `content/docs/*.md` (hand-written) + generated CLI reference |
| `/rules`, `/rules/ngb001` … `/rules/ngb020` | generated from `@ngbastion/rules` metadata |
| `/playground` | `src/app/playground/` — live NGB018 snippet analysis and build-time fixture walkthroughs |
| `/changelog` | generated from the repository `CHANGELOG.md` |

The original scaffold planned separate `apps/docs`, `apps/website` and `apps/playground`; they are
one app because all routes live on one domain and share navigation, search and branding.

```sh
pnpm build                                  # repository root: packages, then this site
pnpm --filter @ngbastion/website build      # generate → vite build (SSG) → verify-build
pnpm --filter @ngbastion/website test       # Vitest + Angular TestBed
pnpm --filter @ngbastion/website dev        # local dev server
```

## How content is produced

`scripts/generate.mjs` runs before every build, test and dev session and uses the real packages:

- rule pages from `@ngbastion/rules` metadata, the CLI reference from the built CLI's `--help`;
- `src/generated/showcase.json` from a real scan of `examples/vulnerable-showcase`;
- `src/generated/playground.json` from real scans of `playground-fixtures/*/{unsafe,safe}`
  (the build fails if an unsafe variant has no findings or a safe variant has any);
- the changelog from the root `CHANGELOG.md` (the build fails if it is missing);
- every markdown page rendered to HTML (marked + Shiki), plus navigation, search index,
  the prerender route list and `public/sitemap.xml`.

## Angular architecture

- File-based routes (`src/app/pages/**/*.page.ts`); each docs/rule/changelog route lazily loads its
  own generated JSON chunk through a route resolver, so prerendering waits for content.
- Standalone, `OnPush` components; signals for state (theme, search, playground, docs menu); modern
  control flow; zoneless change detection; hydration with event replay.
- Generated HTML is bound with `[innerHTML]` and **goes through Angular's sanitizer** — the site
  never calls `bypassSecurityTrust*`. Syntax highlighting is class-based because the sanitizer
  removes `style` attributes, and headings are rendered by Angular (with `[id]`) because it removes
  `id` attributes. A unit test fails if the sanitizer strips anything from any page.
- SEO: `Seo` service sets title, description, canonical URL, Open Graph/Twitter tags and JSON-LD
  during pre-rendering. `scripts/verify-build.mjs` checks every route after the build.
- The site is scanned by NgBastion itself in `tests/integration/website-selfscan.test.ts`.

Deploy (Firebase Hosting, manual): build, then `firebase deploy --only hosting` from this folder. `.firebaserc` is local and ignored; pass `--project` or run `firebase use --add` once.

## Browser analysis assets

Only the browser bootstrap installs the global Angular WebMCP provider. Catalog lookup, the dedicated TypeScript worker and standalone report rendering load on demand. The TypeScript compiler accounts for most of the worker's 3.58 MB (about 1.00 MB gzip). Neither prerendering nor ordinary landing-page visits start a worker. On the local production build the main JavaScript entry grew from 104.70 kB to about 106.30 kB gzip with the integration enabled.
