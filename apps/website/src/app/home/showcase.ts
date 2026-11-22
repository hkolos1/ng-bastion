import data from '../../generated/showcase.json';

export interface TraceStep {
  kind: string;
  file: string;
  line: number;
  column: number;
  description: string;
}
export interface ShowcaseFinding {
  ruleId: string;
  ruleName: string;
  severity: string;
  confidence: string;
  message: string;
  location: { file: string; line: number; column: number };
  trace?: TraceStep[];
}
export interface Showcase {
  note: string;
  version: string;
  files: number;
  templates: number;
  total: number;
  rulesTriggered: number;
  ruleCount: number;
  summary: Record<string, number>;
  gate: { failOn: string; failed: boolean };
  featured: ShowcaseFinding[];
}

/** Real `ngbastion scan` output on examples/vulnerable-showcase, captured by scripts/generate.mjs. */
export const SHOWCASE = data as Showcase;
