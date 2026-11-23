import ts from 'typescript';
import { inspectSecretLiterals } from '@ngbastion/rules/snippet';
import type { Finding } from '@ngbastion/core';

export interface SourceInput { code: string; filename: string }
export type SnippetFinding = Pick<Finding, 'location' | 'confidence' | 'message' | 'evidence' | 'evidenceKind'> & { severity?: Finding['severity'] };
export type Inspection = { status: 'ok'; findings: SnippetFinding[] } | { status: 'error'; message: string };

export function inspect({ code, filename }: SourceInput): Inspection {
  const file = ts.createSourceFile(filename, code, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  // Supply a closed compiler host. Even triple-slash references and imports cannot load other files.
  const program = ts.createProgram([filename], { noLib: true, noResolve: true }, {
    getSourceFile: name => name === filename ? file : undefined,
    fileExists: name => name === filename, readFile: name => name === filename ? code : undefined,
    getDefaultLibFileName: () => '', getCurrentDirectory: () => '', getDirectories: () => [],
    getCanonicalFileName: name => name, useCaseSensitiveFileNames: () => true, getNewLine: () => '\n',
    writeFile: () => { throw new Error('Emit disabled'); },
  });
  const diagnostic = program.getSyntacticDiagnostics(file)[0];
  if (diagnostic) {
    const pos = file.getLineAndCharacterOfPosition(diagnostic.start ?? 0);
    return { status: 'error', message: `TypeScript syntax error TS${diagnostic.code} at ${pos.line + 1}:${pos.character + 1}.` };
  }
  const literals: ts.StringLiteralLike[] = [];
  function visit(node: ts.Node) {
    if (ts.isStringLiteralLike(node)) literals.push(node);
    ts.forEachChild(node, visit);
  }
  visit(file);
  const hits = inspectSecretLiterals({ ts }, literals);
  if (hits.length > 50) return { status: 'error', message: 'More than 50 findings. Analyze a smaller snippet.' };
  return { status: 'ok', findings: hits.map(hit => {
    const node = hit.node!;
    const start = file.getLineAndCharacterOfPosition(node.getStart(file));
    const end = file.getLineAndCharacterOfPosition(node.getEnd());
    return { message: hit.message.slice(0, 800), severity: hit.severity, confidence: hit.confidence,
      evidenceKind: hit.evidenceKind, evidence: (hit.evidence ?? []).map(s => s.slice(0, 800)),
      location: { file: filename, line: start.line + 1, column: start.character + 1, endLine: end.line + 1, endColumn: end.character + 1 } };
  }) };
}
