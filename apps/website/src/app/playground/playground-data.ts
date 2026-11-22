import data from '../../generated/playground.json';
import type { CodeSnippet } from '../ui/code-block';

export interface PgStep { kind: string; file: string; line: number; description: string }
export interface PgFinding {
  ruleId: string;
  ruleName: string;
  severity: string;
  confidence: string;
  evidenceKind: string;
  message: string;
  location: { file: string; line: number };
  trace?: PgStep[];
}
export interface PgVariant { files: (CodeSnippet & { name: string })[]; findings: PgFinding[] }
export interface PgExample { id: string; title: string; blurb: string; variants: { unsafe: PgVariant; safe: PgVariant } }
export interface PgData { examples: PgExample[]; rules: Record<string, { name: string; rationale: string; remediation: string }> }

/** Results produced by NgBastion at build time for the fixtures in playground-fixtures/. */
export const PLAYGROUND = data as PgData;
