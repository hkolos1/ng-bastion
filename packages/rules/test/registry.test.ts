import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { BUILTIN_RULE_IDS, PRESETS } from '@ngbastion/config';
import { CONFIDENCES } from '@ngbastion/plugin-api';
import { builtinRules } from '../src/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const ids = builtinRules.map((r) => r.meta.id);

describe('built-in rule registry', () => {
  it('has unique, sequential IDs matching the config package', () => {
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toEqual(Array.from({ length: ids.length }, (_, i) => `NGB${String(i + 1).padStart(3, '0')}`));
    expect(BUILTIN_RULE_IDS).toEqual(ids);
  });

  it('every rule is enabled by the recommended and strict presets', () => {
    for (const id of ids) {
      expect(PRESETS.recommended!.rules?.[id], id).toMatch(/error|warn/);
      expect(PRESETS.strict!.rules?.[id], id).toBe('error');
    }
  });

  it.each(builtinRules.map((r) => [r.meta.id, r] as const))('%s has complete documentation and a test file', (id, rule) => {
    const m = rule.meta;
    expect(m.name.length).toBeGreaterThan(3);
    expect(m.docs.description.length).toBeGreaterThan(60);
    expect(m.docs.rationale.length).toBeGreaterThan(60);
    expect(m.docs.remediation.length).toBeGreaterThan(30);
    expect(m.docs.patterns.length).toBeGreaterThan(0);
    expect(m.docs.limitations.length).toBeGreaterThan(0);
    expect(m.docs.falsePositives.length).toBeGreaterThan(0);
    expect(m.docs.example.unsafe).not.toBe(m.docs.example.safe);
    expect(m.cwe?.every((c) => /^CWE-\d+$/.test(c)) ?? true).toBe(true);
    expect(existsSync(path.join(here, `${id.toLowerCase()}.test.ts`))).toBe(true);
    expect(CONFIDENCES.length).toBe(3);
  });

  it('new rules (NGB021+) carry CWE mappings and references', () => {
    for (const r of builtinRules.filter((x) => Number(x.meta.id.slice(3)) > 20)) {
      expect(r.meta.cwe?.length, r.meta.id).toBeGreaterThan(0);
      expect(r.meta.docs.references?.length, r.meta.id).toBeGreaterThan(0);
    }
  });
});
