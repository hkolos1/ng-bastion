import { createHash } from 'node:crypto';
import path from 'node:path';
import ts from 'typescript';

export const FINGERPRINT_VERSION = 2;

export function hashIdentity(parts: unknown): string {
  return createHash('sha256').update(JSON.stringify(parts)).digest('hex');
}

/** Preserve significant token text, including whitespace inside literal values. */
export function operationAnchor(text: string, node?: ts.Node): string {
  const scanner = ts.createScanner(ts.ScriptTarget.Latest, true, ts.LanguageVariant.Standard, text);
  const tokens: [number, string][] = [];
  for (let token = scanner.scan(); token !== ts.SyntaxKind.EndOfFileToken; token = scanner.scan()) {
    tokens.push([token, scanner.getTokenText()]);
  }
  const scope: string[] = [];
  for (let parent = node?.parent; parent; parent = parent.parent) {
    if (ts.isClassDeclaration(parent) || ts.isMethodDeclaration(parent) || ts.isFunctionDeclaration(parent)) {
      scope.push(parent.name?.getText() ?? '');
    }
  }
  return hashIdentity([scope, tokens]);
}

export function fingerprintBase(rule: string, file: string, anchor: string, endpoints: string[]) {
  return hashIdentity([FINGERPRINT_VERSION, rule, path.posix.normalize(file.replaceAll('\\', '/')), anchor, endpoints]);
}
