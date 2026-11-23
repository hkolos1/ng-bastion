export { run, HELP, EXIT_OK, EXIT_GATE_FAILED, EXIT_ERROR, type Io } from './run.js';
export { VERSION } from './version.js';
export { renderJson, toJsonReport, JSON_SCHEMA_VERSION } from './reporters/json.js';
export { renderSarif, toSarif } from './reporters/sarif.js';
export { renderTerminal, createColors } from './reporters/terminal.js';
export { loadPlugins, validatePlugin, PluginError } from './plugins.js';

export { renderHtml } from './reporters/html.js';
export { loadReportAssets } from './report-assets.js';
export type { Comparison, ReportingContext, Snapshot, Status } from './comparison.js';
export type { GitClassification } from './git-diff.js';
