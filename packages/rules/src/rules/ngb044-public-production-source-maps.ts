import path from 'node:path';
import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { relative } from '../shared/common.js';
import { textLocation } from '../shared/files.js';

type SourceMap = boolean | { scripts?: boolean; styles?: boolean; hidden?: boolean; vendor?: boolean } | undefined;

/** Script source maps that are emitted and referenced from the bundles (`hidden` maps are not referenced). */
function publicScriptMaps(v: SourceMap): boolean {
  if (v === true) return true;
  if (v && typeof v === 'object') return v.scripts !== false && v.hidden !== true;
  return false;
}

export const ngb044 = defineRule({
  meta: {
    id: 'NGB044',
    name: 'Public production source maps',
    category: 'security-config',
    defaultSeverity: 'low',
    cwe: ['CWE-540', 'CWE-200'],
    docs: {
      description:
        "Reads the Angular build target in `angular.json` and reports production builds that emit script source maps referenced from the bundles: `sourceMap: true` or `{ scripts: true }` without `hidden: true` in the `production` configuration (or in the build options when the production configuration does not override them).",
      rationale:
        "Referenced source maps let anyone download the original TypeScript — comments, internal endpoints, feature flags, validation logic and occasionally secrets — which makes it much cheaper to find and exploit other weaknesses. Hidden source maps keep error-tracking uploads possible without advertising the maps to every visitor.",
      patterns: [
        '`projects.<app>.architect.build.configurations.production.sourceMap` (`targets` in Nx-style workspaces)',
        'Falls back to `build.options.sourceMap` when production does not set it; Angular defaults to no source maps in production',
        '`{ "scripts": true, "hidden": true }` is not reported (maps are emitted but not referenced)',
      ],
      limitations: [
        'Whether the generated `.map` files are actually deployed (and served) is not visible; hidden maps copied to the web root are still downloadable.',
        'Builders other than the Angular application / browser builders and custom webpack configs are not analyzed.',
      ],
      falsePositives: [
        'Teams that intentionally publish source maps (open-source applications) can disable this rule.',
      ],
      remediation:
        'Set `"sourceMap": false` for production, or `{ "scripts": true, "hidden": true }` if you upload maps to an error tracker, and keep `.map` files out of the deployed folder.',
      example: {
        unsafe: `"production": { "sourceMap": true, "outputHashing": "all" }`,
        safe: `"production": { "sourceMap": { "scripts": true, "hidden": true }, "outputHashing": "all" }`,
      },
      references: [
        { title: 'Angular — Build configuration: source maps', url: 'https://angular.dev/reference/configs/workspace-config#source-map-configuration' },
        { title: 'CWE-540 — Inclusion of Sensitive Information in Source Code', url: 'https://cwe.mitre.org/data/definitions/540.html' },
      ],
    },
  },
  analyze(ctx) {
    const p = ctx.project.angularProject as { architect?: Record<string, unknown>; targets?: Record<string, unknown> } | undefined;
    const build = (p?.architect ?? p?.targets)?.build as { options?: { sourceMap?: SourceMap }; configurations?: Record<string, { sourceMap?: SourceMap }> } | undefined;
    if (!build) return [];
    const prod = build.configurations?.production;
    const fromProd = prod && 'sourceMap' in prod;
    const effective = fromProd ? prod!.sourceMap : build.options?.sourceMap;
    if (!publicScriptMaps(effective)) return [];
    const file = [ctx.project.root, ctx.project.workspaceRoot].map((d) => path.join(d, 'angular.json')).find((f) => ctx.readFile(f) !== undefined);
    if (!file) return [];
    const text = ctx.readFile(file)!;
    const anchor = fromProd ? text.indexOf('"sourceMap"', Math.max(0, text.indexOf('"production"'))) : text.indexOf('"sourceMap"');
    const findings: RuleFinding[] = [{
      location: textLocation(file, text, anchor, '"sourceMap"'.length),
      message: `Production build emits source maps referenced from the bundles (${JSON.stringify(effective)}${fromProd ? '' : ', inherited from build options'}); anyone can download the original source.`,
      confidence: prod ? 'high' : 'medium',
      evidenceKind: 'pattern',
      evidence: [`${relative(ctx, file)}: ${fromProd ? 'configurations.production' : 'options'}.sourceMap = ${JSON.stringify(effective)}`, ...(prod ? [] : ['no production configuration found; build options apply'])],
    }];
    return findings;
  },
});
