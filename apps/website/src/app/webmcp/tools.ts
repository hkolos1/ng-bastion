import { provideExperimentalWebMcpTools, type WebMcpToolDescriptor } from '@angular/core';
import { getInstallation } from './installation';
import { InputError } from './validation';

const text = (maxLength: number) => ({ type: 'string', minLength: 1, maxLength });
const filters = { category: text(64), severity: text(16), limit: { type: 'integer', minimum: 1, maximum: 25 } };

function tool(name: string, description: string, properties: object, required: string[],
  handler: (args: unknown, signal: AbortSignal) => unknown, readOnly = true, untrusted = false): WebMcpToolDescriptor {
  return { name: 'ngbastion_' + name, description,
    inputSchema: { type: 'object', properties, required, additionalProperties: false },
    annotations: { readOnlyHint: readOnly, untrustedContentHint: untrusted },
    execute: async (args, client) => {
      try {
        if (client.signal.aborted) return { status: 'error', message: 'Cancelled.' };
        return await handler(args, client.signal);
      } catch (error) {
        return { status: 'error', message: error instanceof InputError ? error.message : 'Tool execution failed.' };
      }
    } };
}

const tools = [
  tool('get_rules', 'List rule metadata in ID order. Filter by canonical category or severity.', {
    ...filters, offset: { type: 'integer', minimum: 0, maximum: 10000 },
  }, [], async args => (await import('./catalog')).getRules(args)),
  tool('explain_rule', 'Read detection criteria, examples, limitations and remediation for a rule.', { ruleId: text(32) },
    ['ruleId'], async args => (await import('./catalog')).explainRule(args)),
  tool('search_rules', 'Find rules by keywords, API names, CWE or rule ID.', { ...filters, query: text(200) },
    ['query'], async args => (await import('./catalog')).searchRules(args)),
  tool('analyze_snippet', 'Analyze one TypeScript snippet locally for NGB018 source literals. Retains four recent results for reporting.',
    { code: text(32768), filename: text(100), language: { type: 'string', enum: ['typescript'] },
      ruleIds: { type: 'array', items: text(32), minItems: 1, maxItems: 100, uniqueItems: true } },
    ['code'], async (args, signal) => (await import('./analysis')).analyzeSnippet(args, signal), false, true),
  tool('generate_report', 'Return a standalone HTML document for a recent analysis ID. The caller can save the returned text.',
    { analysisId: text(64) }, ['analysisId'], async args => (await import('./report')).generateReport(args), true, true),
  tool('get_installation', 'Read installation, configuration and usage instructions for the CLI.', {}, [], getInstallation),
];
export const provideNgBastionTools = () => provideExperimentalWebMcpTools(tools);
