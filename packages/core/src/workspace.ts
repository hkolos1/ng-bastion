import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import ts from 'typescript';

export interface ProjectTarget {
  name: string;
  root: string;
  sourceRoot: string;
  /** tsconfig used to build the program, when one exists. */
  tsconfig?: string;
  indexHtml?: string;
  angularProject?: Record<string, unknown>;
  kind: 'angular-json' | 'tsconfig' | 'directory';
}

export interface WorkspaceDiagnostic {
  code: string;
  level: 'error' | 'warning' | 'info';
  message: string;
  file?: string;
}

export interface Workspace {
  root: string;
  angularJson?: string;
  /** Installed (or declared) @angular/core version. */
  angularVersion?: string;
  projects: ProjectTarget[];
  diagnostics: WorkspaceDiagnostic[];
}

export const SUPPORTED_ANGULAR_MAJORS = [20, 21, 22];
/** Hidden directories that hold security-relevant configuration (CI workflows). */
const VISIBLE_DOT_DIRS = new Set(['.github']);

export const IGNORED_DIRS = new Set(['node_modules', 'dist', '.angular', '.git', 'coverage', '.nx', 'out-tsc', 'tmp']);

function readJsonWithComments(file: string): unknown {
  const parsed = ts.parseConfigFileTextToJson(file, readFileSync(file, 'utf8'));
  if (parsed.error) throw new Error(ts.flattenDiagnosticMessageText(parsed.error.messageText, '\n'));
  return parsed.config;
}

const asRecord = (v: unknown): Record<string, unknown> | undefined =>
  typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;

export function detectAngularVersion(root: string): string | undefined {
  const installed = path.join(root, 'node_modules', '@angular', 'core', 'package.json');
  try {
    if (existsSync(installed)) return (JSON.parse(readFileSync(installed, 'utf8')) as { version?: string }).version;
    const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')) as Record<string, Record<string, string> | undefined>;
    const declared = pkg.dependencies?.['@angular/core'] ?? pkg.devDependencies?.['@angular/core'] ?? pkg.peerDependencies?.['@angular/core'];
    return declared?.replace(/^[^\d]*/, '') || undefined;
  } catch {
    return undefined;
  }
}

/**
 * Discovers analyzable projects. Order of preference: angular.json projects,
 * then a root tsconfig, then all `.ts` files in the directory.
 */
export function discoverWorkspace(cwd: string): Workspace {
  const root = path.resolve(cwd);
  const diagnostics: WorkspaceDiagnostic[] = [];
  if (!existsSync(root) || !statSync(root).isDirectory()) {
    return { root, projects: [], diagnostics: [{ code: 'workspace-not-found', level: 'error', message: `directory not found: ${root}` }] };
  }
  const ws: Workspace = { root, projects: [], diagnostics };
  const angularVersion = detectAngularVersion(root);
  if (angularVersion) ws.angularVersion = angularVersion;

  const angularJson = path.join(root, 'angular.json');
  if (existsSync(angularJson)) {
    ws.angularJson = angularJson;
    try {
      const json = asRecord(readJsonWithComments(angularJson));
      const projects = asRecord(json?.projects) ?? {};
      for (const [name, value] of Object.entries(projects)) {
        const p = asRecord(value);
        if (!p) continue;
        const projRoot = path.resolve(root, typeof p.root === 'string' ? p.root : '');
        const sourceRoot = path.resolve(root, typeof p.sourceRoot === 'string' ? p.sourceRoot : path.join(typeof p.root === 'string' ? p.root : '', 'src'));
        const targets = asRecord(p.architect) ?? asRecord(p.targets);
        const build = asRecord(asRecord(targets?.build)?.options);
        const target: ProjectTarget = { name, root: projRoot, sourceRoot, angularProject: p, kind: 'angular-json' };
        const tsConfig = typeof build?.tsConfig === 'string' ? path.resolve(root, build.tsConfig) : undefined;
        if (tsConfig && existsSync(tsConfig)) target.tsconfig = tsConfig;
        else if (tsConfig) diagnostics.push({ code: 'tsconfig-not-found', level: 'warning', message: `project '${name}': tsConfig ${tsConfig} not found; scanning ${path.relative(root, sourceRoot) || '.'} without compiler options`, file: angularJson });
        const index = build?.index;
        const indexPath = typeof index === 'string' ? index : typeof asRecord(index)?.input === 'string' ? (asRecord(index)!.input as string) : undefined;
        if (indexPath) target.indexHtml = path.resolve(root, indexPath);
        else if (existsSync(path.join(sourceRoot, 'index.html'))) target.indexHtml = path.join(sourceRoot, 'index.html');
        ws.projects.push(target);
      }
    } catch (e) {
      diagnostics.push({ code: 'workspace-invalid', level: 'error', message: `cannot parse angular.json: ${(e as Error).message}`, file: angularJson });
    }
    if (!ws.projects.length && !diagnostics.some((d) => d.level === 'error')) {
      diagnostics.push({ code: 'workspace-empty', level: 'warning', message: 'angular.json defines no projects', file: angularJson });
    }
    return ws;
  }

  const tsconfig = path.join(root, 'tsconfig.json');
  const indexHtml = [path.join(root, 'src', 'index.html'), path.join(root, 'index.html')].find((f) => existsSync(f));
  if (existsSync(tsconfig)) {
    ws.projects.push({ name: path.basename(root), root, sourceRoot: root, tsconfig, kind: 'tsconfig', ...(indexHtml ? { indexHtml } : {}) });
  } else {
    ws.projects.push({ name: path.basename(root), root, sourceRoot: root, kind: 'directory', ...(indexHtml ? { indexHtml } : {}) });
    diagnostics.push({ code: 'angular-workspace-not-found', level: 'info', message: 'no angular.json or tsconfig.json found; analyzing all .ts files with default compiler options' });
  }
  return ws;
}

export function listFiles(dir: string, predicate: (file: string) => boolean, out: string[] = []): string[] {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    if (e.isDirectory()) {
      if (!IGNORED_DIRS.has(e.name) && (!e.name.startsWith('.') || VISIBLE_DOT_DIRS.has(e.name))) listFiles(path.join(dir, e.name), predicate, out);
    } else if (e.isFile() && predicate(path.join(dir, e.name))) out.push(path.join(dir, e.name));
  }
  return out;
}
