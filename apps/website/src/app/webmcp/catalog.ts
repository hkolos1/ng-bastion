import type { EnabledRule } from '@ngbastion/core';
import metadata from '../../generated/rule-metadata.json';
import { boundedString, InputError, integer, parameters } from './validation';

export const rules = (metadata as EnabledRule['meta'][]).slice().sort((a, b) => a.id.localeCompare(b.id));
export function documentation(id: string) { return '/rules/' + id.toLowerCase() + '/'; }

function summary(rule: EnabledRule['meta']) {
  return { id: rule.id, name: rule.name, severity: rule.defaultSeverity, category: rule.category,
    description: rule.docs.description, documentation: documentation(rule.id) };
}

export function explainRule(input: unknown) {
  const { ruleId } = parameters(input, ['ruleId']);
  const id = boundedString(ruleId, 'ruleId', 32).trim().toUpperCase();
  const rule = rules.find(r => r.id === id);
  if (!rule) return { status: 'unknown_rule', ruleId: id };
  return { status: 'ok', ...summary(rule), ...rule.docs, references: rule.docs.references ?? [], autofix: null };
}

function filtered(input: Record<string, unknown>) {
  for (const field of ['severity', 'category'] as const) {
    const value = input[field];
    if (value !== undefined && !rules.some(r => (field === 'severity' ? r.defaultSeverity : r.category) === value)) {
      throw new InputError('Unknown ' + field);
    }
  }
  return rules.filter(r => (input['severity'] === undefined || r.defaultSeverity === input['severity']) &&
    (input['category'] === undefined || r.category === input['category']));
}

export function getRules(input: unknown) {
  const args = parameters(input, ['severity', 'category', 'offset', 'limit']);
  const rows = filtered(args);
  const offset = integer(args['offset'], 'offset', 0, 10000, 0);
  const limit = integer(args['limit'], 'limit', 1, 25, 10);
  return { status: 'ok', total: rows.length, offset, rules: rows.slice(offset, offset + limit).map(summary) };
}

export function searchRules(input: unknown) {
  const args = parameters(input, ['query', 'severity', 'category', 'limit']);
  const query = boundedString(args['query'], 'query', 200).trim().toLowerCase();
  const words = [...new Set(query.match(/[a-z0-9]+/g) ?? [])].filter(w => !['how','do','i','a','the','is','for','to','in','of','and','can','what','rules','find'].includes(w));
  const limit = integer(args['limit'], 'limit', 1, 25, 10);
  const hits = filtered(args).map(rule => {
    const title = [rule.id, rule.name, rule.category].join(' ').toLowerCase();
    const details = [rule.docs.description, ...rule.docs.patterns, ...(rule.cwe ?? [])].join(' ').toLowerCase();
    const score = words.reduce((n, w) => n + (title.includes(w) ? 4 : details.includes(w) ? 1 : 0), 0);
    return { rule, score: score + (title.includes(query) ? 10 : 0) };
  }).filter(hit => hit.score > 0).sort((a, b) => b.score - a.score || a.rule.id.localeCompare(b.rule.id));
  return { status: 'ok', total: hits.length, rules: hits.slice(0, limit).map(hit => summary(hit.rule)) };
}
