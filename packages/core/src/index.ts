export { scan, ENGINE_VERSION } from './scan.js';
export type {
  Finding,
  FindingTraceStep,
  RelativeLocation,
  ScanDiagnostic,
  ScanOptions,
  ScanResult,
  EnabledRule,
  ProjectSummary,
  Suppression,
} from './scan.js';
export { discoverWorkspace, detectAngularVersion, SUPPORTED_ANGULAR_MAJORS, type Workspace, type ProjectTarget, type WorkspaceDiagnostic } from './workspace.js';
export { resolveProjectFiles, createProjectProgram, createInMemoryProgram, DEFAULT_COMPILER_OPTIONS } from './program.js';
export { Symbols, originIs, moduleMatches } from './symbols.js';
export { TaintEngine } from './taint/engine.js';
export { matchSource, matchObservableSource } from './taint/sources.js';
export { FINGERPRINT_VERSION } from './fingerprint.js';
