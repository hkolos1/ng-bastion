export * from './types.js';
export { validateConfig, assertConfig, isIsoDate } from './validate.js';
export { PRESETS, DEFAULT_LIMITS, BUILTIN_RULE_IDS } from './presets.js';
export {
  CONFIG_FILE_NAMES,
  ConfigError,
  findConfigFile,
  readConfigFile,
  resolveConfig,
  loadConfig,
  type ConfigOverrides,
} from './resolve.js';

import type { NgBastionConfig } from './types.js';

/** Type-safe identity helper for `ngbastion.config.ts`. */
export const defineConfig = (config: NgBastionConfig): NgBastionConfig => config;
