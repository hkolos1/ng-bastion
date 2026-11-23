import data from '../../generated/showcase.json';
import landingData from '../../generated/landing.json';
import type { CodeSnippet } from '../ui/code-block';

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
  /** The NGB001 finding walked through the real showcase source, line by line. */
  flow: {
    ruleId: string;
    ruleName: string;
    severity: string;
    confidence: string;
    steps: { kind: string; file: string; line: number; description: string; snippet: CodeSnippet }[];
  };
}

/** Real `ngbastion scan` output on examples/vulnerable-showcase, captured by scripts/generate.mjs. */
export const SHOWCASE = data as unknown as Showcase;

export interface LandingData {
  comparison: (CodeSnippet & { id: string; title: string; caption: string; findings: { ruleId: string; ruleName: string; severity: string; confidence: string; message: string }[] })[];
  commands: { npx: CodeSnippet; install: CodeSnippet };
}

/** Snippets and verdicts produced by scanning them at build time. */
export const LANDING = landingData as LandingData;
