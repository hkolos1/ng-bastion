import { createRequire } from 'node:module';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { PLUGIN_API_VERSION, SEVERITIES, type NgBastionPlugin, type SecurityRule } from '@ngbastion/plugin-api';
import type { ResolvedPlugin } from '@ngbastion/config';

export class PluginError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PluginError';
  }
}

/**
 * Loads explicitly configured plugins. Plugins are trusted code: importing
 * one executes it with the scanner's permissions. Nothing is downloaded.
 */
export async function loadPlugins(plugins: ResolvedPlugin[], builtinIds: ReadonlySet<string>): Promise<{ rules: SecurityRule[]; plugins: NgBastionPlugin[] }> {
  const rules: SecurityRule[] = [];
  const loaded: NgBastionPlugin[] = [];
  const ids = new Set(builtinIds);
  for (const p of plugins) {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(p.specifier)) throw new PluginError(`plugin '${p.specifier}': remote plugins are not supported`);
    let file: string;
    try {
      file = p.specifier.startsWith('.') || path.isAbsolute(p.specifier)
        ? path.resolve(p.from, p.specifier)
        : createRequire(path.join(p.from, 'noop.js')).resolve(p.specifier);
    } catch {
      throw new PluginError(`plugin '${p.specifier}' could not be resolved from ${p.from} (install it locally)`);
    }
    let mod: Record<string, unknown>;
    try {
      mod = (await import(pathToFileURL(file).href)) as Record<string, unknown>;
    } catch (e) {
      throw new PluginError(`plugin '${p.specifier}' failed to load: ${(e as Error).message}`);
    }
    const plugin = (mod.default ?? mod.plugin) as NgBastionPlugin | undefined;
    const problems = validatePlugin(plugin);
    if (problems.length) throw new PluginError(`plugin '${p.specifier}' is invalid:\n  ${problems.join('\n  ')}`);
    for (const rule of plugin!.rules) {
      if (ids.has(rule.meta.id)) throw new PluginError(`plugin '${plugin!.name}': rule id ${rule.meta.id} is already registered`);
      ids.add(rule.meta.id);
      rules.push(rule);
    }
    loaded.push(plugin!);
  }
  return { rules, plugins: loaded };
}

export function validatePlugin(plugin: unknown): string[] {
  const errors: string[] = [];
  if (!plugin || typeof plugin !== 'object') return ['expected a default export created with definePlugin()'];
  const p = plugin as Partial<NgBastionPlugin>;
  if (p.apiVersion !== PLUGIN_API_VERSION) errors.push(`apiVersion ${String(p.apiVersion)} is not compatible with this scanner (plugin API ${PLUGIN_API_VERSION})`);
  if (typeof p.name !== 'string' || !p.name) errors.push('name must be a non-empty string');
  if (!Array.isArray(p.rules) || !p.rules.length) errors.push('rules must be a non-empty array');
  for (const [i, r] of (Array.isArray(p.rules) ? p.rules : []).entries()) {
    const id = r?.meta?.id;
    if (typeof id !== 'string' || !/^[A-Z][A-Z0-9_-]*\d+$/.test(id)) errors.push(`rules[${i}].meta.id must look like ACME001`);
    else if (id.startsWith('NGB')) errors.push(`rules[${i}].meta.id: the NGB prefix is reserved for built-in rules`);
    if (typeof r?.analyze !== 'function') errors.push(`rules[${i}].analyze must be a function`);
    if (!r?.meta?.name || !SEVERITIES.includes(r?.meta?.defaultSeverity)) errors.push(`rules[${i}].meta needs name and a valid defaultSeverity`);
    if (!r?.meta?.docs?.description || !r?.meta?.docs?.remediation) errors.push(`rules[${i}].meta.docs needs description and remediation`);
  }
  return errors;
}
