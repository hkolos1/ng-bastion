import { readFileSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { severityRank, type Severity } from '@ngbastion/plugin-api';
import { DEFAULT_LIMITS, PRESETS } from './presets.js';
import type {
  ConfigDiagnostic,
  NgBastionConfig,
  ResolvedConfig,
  ResolvedPolicy,
  ResolvedRuleSetting,
} from './types.js';
import { isIsoDate, validateConfig } from './validate.js';

export const CONFIG_FILE_NAMES = [
  'ngbastion.config.json',
  'ngbastion.config.ts',
  'ngbastion.config.mts',
  'ngbastion.config.js',
  'ngbastion.config.mjs',
];

export class ConfigError extends Error {
  constructor(message: string, readonly file?: string) {
    super(file ? `${file}: ${message}` : message);
    this.name = 'ConfigError';
  }
}

export interface ConfigOverrides {
  failOn?: Severity | 'none';
  minConfidence?: ResolvedConfig['minConfidence'];
  projects?: string[];
}

/** Finds the config file in `dir`. Throws when more than one candidate exists. */
export function findConfigFile(dir: string): string | undefined {
  const found = CONFIG_FILE_NAMES.map((n) => path.join(dir, n)).filter((f) => existsSync(f));
  if (found.length > 1) {
    throw new ConfigError(`multiple config files found (${found.map((f) => path.basename(f)).join(', ')}); keep exactly one`);
  }
  return found[0];
}

/**
 * Reads one config file. JSON is parsed; `.ts`/`.mts`/`.js`/`.mjs` files are
 * imported and therefore EXECUTE CODE (TypeScript via Node's built-in type
 * stripping). Only load configuration you trust.
 */
export async function readConfigFile(file: string): Promise<NgBastionConfig> {
  let raw: unknown;
  if (file.endsWith('.json')) {
    let text: string;
    try {
      text = readFileSync(file, 'utf8');
    } catch (e) {
      throw new ConfigError(`cannot read config: ${(e as Error).message}`, file);
    }
    try {
      raw = JSON.parse(text);
    } catch (e) {
      throw new ConfigError(`invalid JSON: ${(e as Error).message}`, file);
    }
  } else {
    try {
      const mod = (await import(pathToFileURL(file).href)) as { default?: unknown };
      raw = mod.default;
    } catch (e) {
      throw new ConfigError(`failed to load config module: ${(e as Error).message}`, file);
    }
    if (raw === undefined) throw new ConfigError('config module has no default export', file);
  }
  const errors = validateConfig(raw);
  if (errors.length) throw new ConfigError(`invalid configuration\n  ${errors.join('\n  ')}`, file);
  return raw as NgBastionConfig;
}

interface Layer {
  config: NgBastionConfig;
  source: string;
  dir: string;
}

async function collectLayers(config: NgBastionConfig, source: string, dir: string, chain: string[]): Promise<Layer[]> {
  const layers: Layer[] = [];
  for (const ext of config.extends ?? []) {
    if (Object.hasOwn(PRESETS, ext)) {
      const key = `preset:${ext}`;
      if (chain.includes(key)) continue;
      layers.push(...(await collectLayers(PRESETS[ext]!, key, dir, [...chain, key])));
      continue;
    }
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(ext)) {
      throw new ConfigError(`remote configuration '${ext}' is not supported; install it as a package or copy it locally`, source);
    }
    let file: string;
    try {
      file = ext.startsWith('.') || path.isAbsolute(ext)
        ? path.resolve(dir, ext)
        : createRequire(path.join(dir, 'noop.js')).resolve(ext);
    } catch {
      throw new ConfigError(`cannot resolve extended config '${ext}' (only locally installed packages and files are supported)`, source);
    }
    if (!existsSync(file)) throw new ConfigError(`extended config '${ext}' not found at ${file}`, source);
    if (chain.includes(file)) throw new ConfigError(`circular 'extends' chain: ${[...chain, file].join(' -> ')}`, source);
    const extConfig = await readConfigFile(file);
    layers.push(...(await collectLayers(extConfig, file, path.dirname(file), [...chain, file])));
  }
  layers.push({ config, source, dir });
  return layers;
}

const DAY = 86_400_000;

/**
 * Resolves a user config (and its `extends` chain) into the internal schema.
 * Precedence: presets/shared configs in `extends` order < the config itself <
 * CLI overrides < organizational policy constraints (applied last).
 * When `extends` is omitted, `['recommended']` is assumed.
 */
export async function resolveConfig(
  config: NgBastionConfig,
  options: { file?: string; cwd: string; overrides?: ConfigOverrides; now?: Date },
): Promise<ResolvedConfig> {
  const effective: NgBastionConfig = { ...config, extends: config.extends ?? ['recommended'] };
  const source = options.file ?? '<defaults>';
  const dir = options.file ? path.dirname(options.file) : options.cwd;
  const layers = await collectLayers(effective, source, dir, options.file ? [options.file] : []);
  const diagnostics: ConfigDiagnostic[] = [];

  const resolved: ResolvedConfig = {
    rules: {},
    include: [],
    exclude: [],
    projects: [],
    failOn: 'high',
    minConfidence: 'medium',
    limits: { ...DEFAULT_LIMITS },
    trustedSanitizers: [],
    plugins: [],
    exceptions: [],
    policy: {
      sources: [],
      mandatoryRules: new Map(),
      allowInlineSuppressions: true,
      requireExceptionExpiry: false,
    },
    sources: layers.map((l) => l.source),
    diagnostics,
  };

  for (const { config: c, source: src, dir: d } of layers) {
    for (const [id, setting] of Object.entries(c.rules ?? {})) {
      const prev: ResolvedRuleSetting = resolved.rules[id] ?? { level: 'error', options: {} };
      resolved.rules[id] = typeof setting === 'string'
        ? { ...prev, level: setting }
        : {
            level: setting.level ?? prev.level,
            ...((setting.severity ?? prev.severity) ? { severity: setting.severity ?? prev.severity } : {}),
            options: { ...prev.options, ...setting.options },
          };
    }
    resolved.include.push(...(c.include ?? []));
    resolved.exclude.push(...(c.exclude ?? []));
    if (c.projects) resolved.projects = [...c.projects];
    if (c.failOn) resolved.failOn = c.failOn;
    if (c.minConfidence) resolved.minConfidence = c.minConfidence;
    Object.assign(resolved.limits, c.limits);
    resolved.trustedSanitizers.push(...(c.trustedSanitizers ?? []));
    for (const p of c.plugins ?? []) {
      if (!resolved.plugins.some((x) => x.specifier === p)) resolved.plugins.push({ specifier: p, from: d });
    }
    for (const e of c.exceptions ?? []) resolved.exceptions.push({ ...e, source: src });
    if (c.policy) mergePolicy(resolved.policy, c.policy, src);
  }

  const o = options.overrides ?? {};
  if (o.failOn) resolved.failOn = o.failOn;
  if (o.minConfidence) resolved.minConfidence = o.minConfidence;
  if (o.projects?.length) resolved.projects = o.projects;
  resolved.exclude = [...new Set(resolved.exclude)];

  enforcePolicy(resolved, options.now ?? new Date());
  return resolved;
}

function mergePolicy(target: ResolvedPolicy, p: NonNullable<NgBastionConfig['policy']>, src: string) {
  target.sources.push(p.name ? `${p.name} (${src})` : src);
  for (const id of p.mandatoryRules ?? []) if (!target.mandatoryRules.has(id)) target.mandatoryRules.set(id, p.name ?? src);
  // Policies only ever tighten: a later layer cannot loosen an earlier policy.
  if (p.maxFailOn && (!target.maxFailOn || severityRank(p.maxFailOn) < severityRank(target.maxFailOn))) {
    target.maxFailOn = p.maxFailOn;
  }
  if (p.allowInlineSuppressions === false) target.allowInlineSuppressions = false;
  if (p.requireExceptionExpiry) target.requireExceptionExpiry = true;
  if (p.maxExceptionDays && (!target.maxExceptionDays || p.maxExceptionDays < target.maxExceptionDays)) {
    target.maxExceptionDays = p.maxExceptionDays;
  }
}

function enforcePolicy(c: ResolvedConfig, now: Date) {
  const p = c.policy;
  for (const [id, owner] of p.mandatoryRules) {
    const r = c.rules[id];
    if (!r || r.level !== 'error') {
      c.diagnostics.push({
        code: 'policy-violation',
        level: 'warning',
        message: `${id} is mandatory under policy '${owner}' and cannot be set to '${r?.level ?? 'off'}'; it stays enabled as 'error'`,
      });
      c.rules[id] = { level: 'error', options: r?.options ?? {}, ...(r?.severity ? { severity: r.severity } : {}) };
    }
  }
  if (p.maxFailOn && (c.failOn === 'none' || severityRank(c.failOn) > severityRank(p.maxFailOn))) {
    c.diagnostics.push({
      code: 'policy-violation',
      level: 'warning',
      message: `failOn '${c.failOn}' is looser than the policy maximum '${p.maxFailOn}'; using '${p.maxFailOn}'`,
    });
    c.failOn = p.maxFailOn;
  }
  c.exceptions = c.exceptions.filter((e) => {
    const reject = (why: string) => {
      c.diagnostics.push({ code: 'exception-invalid', level: 'warning', message: `exception for ${e.rule} ignored: ${why}`, file: e.source });
      return false;
    };
    if (e.files.some((f) => /^(\*\*\/?)+\*?$/.test(f.trim()))) return reject(`'files' must not match the whole workspace`);
    if (e.expires && !isIsoDate(e.expires)) return reject('invalid expiry date');
    if (p.requireExceptionExpiry && !e.expires) return reject('policy requires an expiry date');
    if (p.maxExceptionDays && e.expires) {
      const limit = now.getTime() + p.maxExceptionDays * DAY;
      if (Date.parse(`${e.expires}T00:00:00Z`) > limit) return reject(`expiry exceeds the policy maximum of ${p.maxExceptionDays} days`);
    }
    return true;
  });
}

/** Locates and resolves configuration for `cwd`. Zero-config falls back to `recommended`. */
export async function loadConfig(options: {
  cwd: string;
  configFile?: string;
  overrides?: ConfigOverrides;
  now?: Date;
}): Promise<{ config: ResolvedConfig; file?: string }> {
  let file: string | undefined;
  if (options.configFile) {
    file = path.resolve(options.cwd, options.configFile);
    if (!existsSync(file)) throw new ConfigError('config file not found', file);
  } else {
    file = findConfigFile(options.cwd);
  }
  const raw = file ? await readConfigFile(file) : {};
  const config = await resolveConfig(raw, {
    cwd: options.cwd,
    ...(file ? { file } : {}),
    ...(options.overrides ? { overrides: options.overrides } : {}),
    ...(options.now ? { now: options.now } : {}),
  });
  return file ? { config, file } : { config };
}
