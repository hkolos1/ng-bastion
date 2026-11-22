# @ngbastion/website

Source of ngbastion.dev: landing page (`/`), documentation (`/docs/`), rule reference (`/rules/`),
playground (`/playground/`) and changelog (`/changelog/`). Built with Astro + Starlight.

The original scaffold planned separate `apps/docs`, `apps/website` and `apps/playground`. They are
one app here: all routes live on one domain, share one build, one navigation and one set of brand
assets, and the playground is a single static page.

```sh
pnpm build                                   # repository root: builds packages first
pnpm --filter @ngbastion/website build       # generate content + astro build → apps/website/dist
pnpm --filter @ngbastion/website dev
```

`scripts/generate.mjs` runs before every build and writes, from the real packages:

- `src/content/docs/rules/*.md` from `@ngbastion/rules` metadata,
- `src/content/docs/docs/cli-reference.md` from the built CLI's `--help` output,
- `src/generated/showcase.json` from a real scan of `examples/vulnerable-showcase`,
- `src/generated/playground.json` from real scans of `playground-fixtures/*/{unsafe,safe}`
  (the build fails if an unsafe variant has no findings or a safe variant has any),
- `src/content/docs/changelog.md` from the root `CHANGELOG.md` (the build fails if it is missing).

Brand assets are generated once by `scripts/brand.mjs` into `/assets/brand` and copied to `public/brand`.

Nothing here deploys the site. Publishing ngbastion.dev requires explicit approval.
