import type { AnalysisContext, SourceLocation } from '@ngbastion/plugin-api';
import { textLocation } from './files.js';

/**
 * Minimal YAML reader for the GitHub Actions workflow subset: block mappings, block sequences
 * (including `- key: value` items), plain / quoted scalars, `|` / `>` block scalars and simple flow
 * sequences. Anchors, aliases, multi-document streams, tags and flow mappings are not interpreted
 * (flow mappings stay scalars). Malformed input never throws; lines that do not fit are skipped.
 */
export type YNode = YScalar | YMap | YSeq;
export interface YScalar { kind: 'scalar'; value: string; index: number }
export interface YMap { kind: 'map'; entries: { key: string; index: number; value: YNode }[]; index: number }
export interface YSeq { kind: 'seq'; items: YNode[]; index: number }

interface Line { indent: number; text: string; index: number }

const MAX_BYTES = 1_000_000;
const MAX_LINES = 20_000;

/** Removes a trailing ` # comment` outside quotes. */
function stripComment(s: string): string {
  let q: string | undefined;
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (q) {
      if (c === q) q = undefined;
    } else if (c === '"' || c === "'") {
      if (i === 0 || /[\s:[{,-]/.test(s[i - 1]!)) q = c;
    } else if (c === '#' && (i === 0 || /\s/.test(s[i - 1]!))) return s.slice(0, i).trimEnd();
  }
  return s.trimEnd();
}

function unquote(s: string): string {
  const v = s.trim();
  if (v.length >= 2 && ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'")))) return v.slice(1, -1);
  return v;
}

/** Position of the `key:` separator (outside quotes / `${{ }}`), or -1. */
function keySep(s: string): number {
  let q: string | undefined;
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (q) {
      if (c === q) q = undefined;
      continue;
    }
    if ((c === '"' || c === "'") && i === 0) q = c;
    else if (c === '{' || c === '[') depth++;
    else if (c === '}' || c === ']') depth--;
    else if (c === ':' && depth === 0 && (i + 1 === s.length || s[i + 1] === ' ' || s[i + 1] === '\t')) return i;
  }
  return -1;
}

export function parseYaml(text: string): YNode | undefined {
  if (text.length > MAX_BYTES) return undefined;
  const raw = text.split(/\r?\n/).slice(0, MAX_LINES);
  const all: (Line & { raw: string })[] = [];
  let offset = 0;
  for (const r of raw) {
    const indent = r.length - r.trimStart().length;
    all.push({ indent, text: r.trim(), index: offset + indent, raw: r });
    offset += r.length + (text[offset + r.length] === '\r' ? 2 : 1);
  }
  let i = 0;
  const content = (l: Line) => l.text !== '' && !l.text.startsWith('#') && l.text !== '---' && l.text !== '...';
  const skip = () => {
    while (i < all.length && !content(all[i]!)) i++;
  };

  const scalar = (v: string, index: number): YNode => {
    const s = v.trim();
    if (s.startsWith('[') && s.endsWith(']')) {
      return { kind: 'seq', index, items: s.slice(1, -1).split(',').map((x) => x.trim()).filter(Boolean).map((x) => ({ kind: 'scalar', value: unquote(x), index }) as YScalar) };
    }
    return { kind: 'scalar', value: unquote(s), index };
  };

  /** `|` / `>` block scalar following line i-1 at parent indent `parent`. */
  const blockScalar = (parent: number, indicator: string, index: number): YScalar => {
    const parts: string[] = [];
    let first = index;
    let base: number | undefined;
    while (i < all.length) {
      const l = all[i]!;
      if (l.text !== '' && l.indent <= parent) break;
      if (l.text !== '') {
        base ??= l.indent;
        if (!parts.length) first = l.index;
      }
      parts.push(l.text === '' ? '' : l.raw.slice(Math.min(base ?? l.indent, l.indent)));
      i++;
    }
    const value = indicator.startsWith('>') ? parts.join(' ') : parts.join('\n');
    return { kind: 'scalar', value: value.trim(), index: first };
  };

  /** Value after `key:` (rest of the line or a nested block). */
  const valueOf = (rest: string, indent: number, index: number): YNode => {
    if (/^[|>][-+0-9]*$/.test(rest)) return blockScalar(indent, rest, index);
    if (rest !== '') return scalar(rest, index);
    skip();
    const next = all[i];
    if (next && (next.indent > indent || (next.indent === indent && /^-( |$)/.test(next.text)))) return block(next.indent);
    return { kind: 'scalar', value: '', index };
  };

  const mapAt = (indent: number): YMap => {
    const m: YMap = { kind: 'map', entries: [], index: all[i]?.index ?? 0 };
    for (;;) {
      skip();
      const l = all[i];
      if (!l || l.indent < indent) break;
      if (l.indent > indent || /^-( |$)/.test(l.text)) {
        if (l.indent === indent) break;
        i++; // malformed: unexpected deeper line
        continue;
      }
      const text = stripComment(l.text);
      const sep = keySep(text);
      i++;
      if (sep < 0) continue;
      const key = unquote(text.slice(0, sep));
      const rest = text.slice(sep + 1).trim();
      const restIndex = l.index + text.length - text.slice(sep + 1).trimStart().length;
      m.entries.push({ key, index: l.index, value: valueOf(rest, indent, restIndex) });
    }
    return m;
  };

  const seqAt = (indent: number): YSeq => {
    const s: YSeq = { kind: 'seq', items: [], index: all[i]?.index ?? 0 };
    for (;;) {
      skip();
      const l = all[i];
      if (!l || l.indent !== indent || !/^-( |$)/.test(l.text)) break;
      const rest = l.text.slice(1).trimStart();
      if (rest === '') {
        i++;
        skip();
        const n = all[i];
        s.items.push(n && n.indent > indent ? block(n.indent) : { kind: 'scalar', value: '', index: l.index });
        continue;
      }
      const shift = l.text.length - rest.length;
      if (keySep(stripComment(rest)) >= 0) {
        // `- key: v` starts a mapping whose indent is the column of `key`.
        all[i] = { ...l, indent: l.indent + shift, text: rest, index: l.index + shift };
        s.items.push(mapAt(l.indent + shift));
      } else {
        i++;
        const v = stripComment(rest);
        s.items.push(/^[|>][-+0-9]*$/.test(v) ? blockScalar(indent, v, l.index + shift) : scalar(v, l.index + shift));
      }
    }
    return s;
  };

  const block = (indent: number): YNode => (/^-( |$)/.test(all[i]!.text) ? seqAt(indent) : mapAt(indent));

  skip();
  if (i >= all.length) return undefined;
  return block(all[i]!.indent);
}

export const get = (n: YNode | undefined, key: string): YNode | undefined => (n?.kind === 'map' ? n.entries.find((e) => e.key === key)?.value : undefined);
export const str = (n: YNode | undefined): string | undefined => (n?.kind === 'scalar' ? n.value : undefined);
export const items = (n: YNode | undefined): YNode[] => (n?.kind === 'seq' ? n.items : []);
export const entries = (n: YNode | undefined) => (n?.kind === 'map' ? n.entries : []);

export interface Step {
  node: YMap;
  uses?: string;
  run?: YScalar;
  with: YMap | undefined;
  index: number;
}

export interface Job {
  id: string;
  node: YMap;
  index: number;
  steps: Step[];
  /** `uses:` of a reusable workflow call. */
  uses?: string;
}

export interface Workflow {
  file: string;
  text: string;
  root: YMap;
  /** Trigger event names. */
  triggers: string[];
  jobs: Job[];
  loc(index: number, length?: number): SourceLocation;
  rel: string;
}

/** Events whose workflows run with secrets / a write token while processing contributor-controlled data. */
export const PRIVILEGED_TRIGGERS = ['pull_request_target', 'workflow_run', 'issue_comment', 'issues', 'pull_request_review_comment', 'discussion', 'discussion_comment'];

function triggerNames(on: YNode | undefined): string[] {
  if (!on) return [];
  if (on.kind === 'scalar') return on.value ? [on.value] : [];
  if (on.kind === 'seq') return on.items.flatMap((x) => (x.kind === 'scalar' ? [x.value] : []));
  return on.entries.map((e) => e.key);
}

/** GitHub Actions workflows of the project and the workspace root (`.github/workflows/*.yml|yaml`). */
export function workflows(ctx: AnalysisContext): Workflow[] {
  const files = new Set([...ctx.findFiles('.github/workflows/*.{yml,yaml}'), ...ctx.findWorkspaceFiles('.github/workflows/*.{yml,yaml}')]);
  const out: Workflow[] = [];
  for (const file of [...files].sort()) {
    const text = ctx.readFile(file);
    if (text === undefined) continue;
    const root = parseYaml(text);
    if (root?.kind !== 'map') continue;
    // YAML 1.1 turns a bare `on:` key into `true`; the key text is still `on`.
    const triggers = triggerNames(get(root, 'on') ?? get(root, 'true'));
    const jobs = entries(get(root, 'jobs')).flatMap((j): Job[] => {
      if (j.value.kind !== 'map') return [];
      const steps = items(get(j.value, 'steps')).flatMap((s): Step[] => {
        if (s.kind !== 'map') return [];
        const run = get(s, 'run');
        const w = get(s, 'with');
        return [{ node: s, index: s.index, uses: str(get(s, 'uses')), ...(run?.kind === 'scalar' ? { run } : {}), with: w?.kind === 'map' ? w : undefined }];
      });
      return [{ id: j.key, node: j.value, index: j.index, steps, uses: str(get(j.value, 'uses')) }];
    });
    const rel = file.startsWith(ctx.project.workspaceRoot) ? file.slice(ctx.project.workspaceRoot.length + 1) : file;
    out.push({ file, text, root, triggers, jobs, rel, loc: (index, length = 0) => textLocation(file, text, index, length) });
  }
  return out;
}

/** Line length of the YAML node's first line (for locations). */
export function lineLength(w: Workflow, index: number): number {
  const end = w.text.indexOf('\n', index);
  return (end < 0 ? w.text.length : end) - index;
}

/** `${{ … }}` expressions in a scalar, located in the workflow text. */
export function expressions(w: Workflow, n: YScalar): { expr: string; index: number }[] {
  const out: { expr: string; index: number }[] = [];
  let from = n.index;
  for (const m of n.value.matchAll(/\$\{\{([\s\S]*?)\}\}/g)) {
    const at = w.text.indexOf(m[0], from);
    const index = at < 0 ? n.index : at;
    if (at >= 0) from = at + m[0].length;
    out.push({ expr: m[1]!.trim(), index });
  }
  return out;
}

/**
 * Contexts an outside contributor controls (GitHub Security Lab list): issue / PR / comment / review /
 * discussion text, branch names, commit messages and author fields, wiki page names.
 */
export const UNTRUSTED_CONTEXT = new RegExp(
  '\\bgithub\\.(head_ref\\b|event\\.(' + [
    'issue\\.(title|body)',
    'pull_request\\.(title|body|head\\.ref|head\\.label|head\\.repo\\.default_branch)',
    '(comment|review|review_comment|discussion_comment)\\.body',
    'discussion\\.(title|body)',
    'pages\\b[^\\s}]*\\.page_name',
    'commits\\b[^\\s}]*\\.(message|author\\.(email|name))',
    'head_commit\\.(message|author\\.(email|name))',
    'workflow_run\\.(head_branch|display_title|head_commit\\.(message|author\\.(email|name))|pull_requests\\b[^\\s}]*\\.head\\.ref)',
  ].join('|') + '))',
);

/** Files of the project and the workspace root matching `glob`, outside build output / dependencies. */
export function configFiles(ctx: AnalysisContext, glob: string): string[] {
  const all = new Set([...ctx.findFiles(glob), ...ctx.findWorkspaceFiles(glob)]);
  return [...all].filter((f) => !/[/\\](node_modules|dist|\.angular|coverage|tmp|out-tsc)[/\\]/.test(f)).sort();
}

/** Line-located `key <sep> value` pairs of an ini / rc / simple YAML file (comments skipped). */
export function rcEntries(text: string): { key: string; value: string; index: number; length: number }[] {
  const out: { key: string; value: string; index: number; length: number }[] = [];
  let offset = 0;
  for (const line of text.slice(0, 1_000_000).split('\n')) {
    const m = /^\s*(?![#;])(?:export\s+)?"?([@\w./:-]+)"?\s*(?:=|:|\s)\s*(.*?)\s*$/.exec(line.replace(/\r$/, ''));
    if (m) out.push({ key: m[1]!.replace(/:$/, ''), value: m[2]!.replace(/^(["'])(.*)\1$/, '$2'), index: offset + line.search(/\S/), length: line.trim().length });
    offset += line.length + 1;
  }
  return out;
}
