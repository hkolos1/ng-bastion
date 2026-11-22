import { resolveConfig } from '@ngbastion/config';
import { scan, type Finding, type ScanResult } from '@ngbastion/core';
import { builtinRules } from '../src/index.js';

export const ROOT = '/virtual/app';

/** Angular-flavoured preamble for fixtures (dependencies are unresolved in-memory: declaration fallback). */
export const NG = `import { Component, ElementRef, Renderer2, inject, signal, computed } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import { ActivatedRoute, Router } from '@angular/router';
import { HttpClient } from '@angular/common/http';
`;

export async function scanFiles(files: Record<string, string>, ruleIds?: string[]): Promise<ScanResult> {
  const ids = ruleIds ?? builtinRules.map((r) => r.meta.id);
  const config = await resolveConfig(
    { extends: [], rules: Object.fromEntries(ids.map((id) => [id, 'error'])), minConfidence: 'low', failOn: 'none' },
    { cwd: ROOT },
  );
  return scan({ cwd: ROOT, config, rules: builtinRules, files });
}

/** Findings of a single rule for the given files. */
export async function findings(ruleId: string, files: Record<string, string>): Promise<Finding[]> {
  const result = await scanFiles(files, [ruleId]);
  const failed = result.diagnostics.filter((d) => d.code === 'rule-failed');
  if (failed.length) throw new Error(failed.map((d) => d.message).join('\n'));
  return result.findings;
}

/** Single-file shortcut: `component.ts`. */
export const one = (ruleId: string, code: string) => findings(ruleId, { 'src/app/component.ts': code });
