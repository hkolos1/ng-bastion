import type { AnalysisContext, SourceLocation } from '@ngbastion/plugin-api';
import { relative } from './common.js';

/** Location of `index` (with `length`) inside a non-TypeScript file. */
export function textLocation(file: string, text: string, index: number, length = 0): SourceLocation {
  const before = text.slice(0, Math.max(0, index)).split(/\r?\n/);
  const line = before.length;
  const column = before[before.length - 1]!.length + 1;
  return { file, line, column, endLine: line, endColumn: column + length };
}

export interface HtmlTag {
  name: string;
  attrs: Map<string, string>;
  location: SourceLocation;
  /** Index of the tag in the file. */
  index: number;
}

/** Start tags in an HTML file (regex-based; static HTML only, no template syntax). */
export function htmlTags(text: string, file: string, names: string[]): HtmlTag[] {
  const out: HtmlTag[] = [];
  const re = new RegExp(`<(${names.join('|')})\\b([^>]*)>`, 'gi');
  // Ignore commented-out markup.
  const stripped = text.replace(/<!--[\s\S]*?-->/g, (c) => ' '.repeat(c.length));
  for (const m of stripped.matchAll(re)) {
    const attrs = new Map<string, string>();
    for (const a of m[2]!.matchAll(/([\w:@.[\]()*-]+)(?:\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+)))?/g)) attrs.set(a[1]!.toLowerCase(), a[3] ?? a[4] ?? a[5] ?? '');
    out.push({ name: m[1]!.toLowerCase(), attrs, location: textLocation(file, text, m.index!, m[0].length), index: m.index! });
  }
  return out;
}

export function readJson(ctx: AnalysisContext, file: string): { json: unknown; text: string } | undefined {
  const text = ctx.readFile(file);
  if (text === undefined) return undefined;
  try {
    return { json: JSON.parse(text), text };
  } catch {
    return undefined;
  }
}

export interface ObservedHeader {
  value: string;
  location: SourceLocation;
  origin: string;
}

/**
 * Constant values of an HTTP response header that are visible in the repository: hosting configs
 * (`firebase.json`, `vercel.json`, `staticwebapp.config.json`, `_headers`).
 */
export function hostingHeaders(ctx: AnalysisContext, header: string): ObservedHeader[] {
  const h = header.toLowerCase();
  const out: ObservedHeader[] = [];
  for (const file of ['firebase.json', 'vercel.json', 'staticwebapp.config.json'].flatMap((g) => ctx.findFiles(g))) {
    const parsed = readJson(ctx, file);
    if (!parsed) continue;
    const add = (value: string) => {
      const idx = parsed.text.indexOf(JSON.stringify(value));
      out.push({ value, location: textLocation(file, parsed.text, idx, value.length), origin: relative(ctx, file) });
    };
    const walk = (v: unknown): void => {
      if (Array.isArray(v)) v.forEach(walk);
      else if (v && typeof v === 'object') {
        const o = v as Record<string, unknown>;
        if (typeof o.key === 'string' && o.key.toLowerCase() === h && typeof o.value === 'string') add(o.value);
        for (const [k, x] of Object.entries(o)) {
          if (k.toLowerCase() === h && typeof x === 'string') add(x);
          else walk(x);
        }
      }
    };
    walk(parsed.json);
  }
  for (const file of ctx.findFiles('**/_headers')) {
    const text = ctx.readFile(file);
    if (!text) continue;
    const re = new RegExp(`^[ \\t]*${header.replace(/[-]/g, '\\-')}:[ \\t]*(.+)$`, 'gim');
    for (const m of text.matchAll(re)) out.push({ value: m[1]!.trim(), location: textLocation(file, text, m.index, m[0].length), origin: relative(ctx, file) });
  }
  return out;
}
