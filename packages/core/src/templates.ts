import path from 'node:path';
import ts from 'typescript';
import {
  parseTemplate,
  Binary,
  Call,
  ImplicitReceiver,
  PropertyRead,
  ThisReceiver,
  TmplAstRecursiveVisitor,
  tmplAstVisitAll,
  type AST,
  type ASTWithSource,
  type ParseSourceSpan,
  type TmplAstElement,
} from '@angular/compiler';
import type { AnalysisDiagnostic, ComponentTemplate, SourceLocation, TemplateElement } from '@ngbastion/plugin-api';
import type { Symbols } from './symbols.js';
import { skipOuter } from './util.js';

/** Template-originated user input reaching component members. */
export interface TemplateUserInput {
  /** Component properties written from user input (`[(ngModel)]="p"`, `(input)="p = $event.target.value"`). */
  properties: Map<string, SourceLocation[]>;
  /** Component methods called with user input (`(input)="search($event.target.value)"`). */
  methodArgs: Map<string, { argIndex: number; location: SourceLocation }[]>;
}

const INPUT_EVENTS = new Set(['input', 'change', 'keyup', 'keydown', 'keypress', 'paste', 'blur', 'ngModelChange', 'valueChange']);
const BINDING_PROPERTY = 0;
const BINDING_ATTRIBUTE = 1;
const BINDING_TWO_WAY = 5;

export function getComponentDecorator(cls: ts.ClassDeclaration, symbols: Symbols): ts.ObjectLiteralExpression | undefined {
  for (const d of ts.getDecorators(cls) ?? []) {
    const call = d.expression;
    if (!ts.isCallExpression(call) || !ts.isIdentifier(call.expression) || call.expression.text !== 'Component') continue;
    const origin = symbols.importOrigin(call.expression);
    if (origin && origin.module !== '@angular/core') continue;
    const arg = call.arguments[0] && skipOuter(call.arguments[0]);
    if (arg && ts.isObjectLiteralExpression(arg)) return arg;
  }
  return undefined;
}

function prop(obj: ts.ObjectLiteralExpression, name: string): ts.Expression | undefined {
  for (const p of obj.properties) {
    if (ts.isPropertyAssignment(p) && (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name)) && p.name.text === name) return p.initializer;
  }
  return undefined;
}

export function extractTemplates(
  classes: readonly ts.ClassDeclaration[],
  symbols: Symbols,
  readFile: (file: string) => string | undefined,
  report: (d: AnalysisDiagnostic) => void,
): { templates: ComponentTemplate[]; userInput: Map<ts.ClassDeclaration, TemplateUserInput> } {
  const templates: ComponentTemplate[] = [];
  const userInput = new Map<ts.ClassDeclaration, TemplateUserInput>();

  for (const cls of classes) {
    const meta = getComponentDecorator(cls, symbols);
    if (!meta) continue;
    const sf = cls.getSourceFile();
    const component = cls.name?.text ?? '<anonymous>';
    let text: string | undefined;
    let file = sf.fileName;
    let inline = true;
    let toLocation: (span: ParseSourceSpan) => SourceLocation;

    const tpl = prop(meta, 'template');
    const tplUrl = prop(meta, 'templateUrl');
    if (tpl) {
      const lit = skipOuter(tpl);
      if (ts.isStringLiteral(lit) || ts.isNoSubstitutionTemplateLiteral(lit)) {
        text = lit.text;
        const base = lit.getStart(sf) + 1;
        toLocation = (span) => {
          const s = sf.getLineAndCharacterOfPosition(base + span.start.offset);
          const e = sf.getLineAndCharacterOfPosition(base + span.end.offset);
          return { file, line: s.line + 1, column: s.character + 1, endLine: e.line + 1, endColumn: e.character + 1 };
        };
      } else {
        report({ code: 'unsupported-template', level: 'info', message: `${component}: template is not a static string literal; template analysis skipped`, file });
        continue;
      }
    } else if (tplUrl) {
      const url = symbols.constantString(tplUrl);
      if (!url) {
        report({ code: 'unsupported-template', level: 'info', message: `${component}: templateUrl is not a constant string; template analysis skipped`, file });
        continue;
      }
      file = path.resolve(path.dirname(sf.fileName), url);
      text = readFile(file);
      inline = false;
      if (text === undefined) {
        report({ code: 'template-not-found', level: 'warning', message: `${component}: template ${url} not found`, file: sf.fileName });
        continue;
      }
      toLocation = (span) => ({ file, line: span.start.line + 1, column: span.start.col + 1, endLine: span.end.line + 1, endColumn: span.end.col + 1 });
    } else continue;

    const parsed = parseTemplate(text, file, { preserveWhitespaces: false });
    if (parsed.errors?.length) {
      report({
        code: 'template-parse-error',
        level: 'warning',
        message: `${component}: template has ${parsed.errors.length} parse error(s) (first: ${parsed.errors[0]!.msg}); results for this template may be incomplete`,
        file,
      });
    }

    const elements: TemplateElement[] = [];
    const input: TemplateUserInput = { properties: new Map(), methodArgs: new Map() };
    const loc = toLocation!;

    class Visitor extends TmplAstRecursiveVisitor {
      override visitElement(el: TmplAstElement): void {
        const attributes = el.attributes.map((a) => ({ name: a.name, value: a.value, bound: false, location: loc(a.sourceSpan) }));
        for (const b of el.inputs) {
          if (b.type !== BINDING_PROPERTY && b.type !== BINDING_ATTRIBUTE && b.type !== BINDING_TWO_WAY) continue;
          attributes.push({ name: b.name, value: (b.value as ASTWithSource).source ?? '', bound: true, location: loc(b.sourceSpan) });
          if (b.type === BINDING_TWO_WAY) {
            const target = memberRead((b.value as ASTWithSource).ast);
            if (target) addTo(input.properties, target, loc(b.sourceSpan));
          }
        }
        for (const o of el.outputs) {
          if (!INPUT_EVENTS.has(o.name)) continue;
          recordHandler(o.handler as ASTWithSource, o.name, loc(o.sourceSpan), input);
        }
        elements.push({ name: el.name, attributes, location: loc(el.startSourceSpan) });
        super.visitElement(el);
      }
    }
    tmplAstVisitAll(new Visitor(), parsed.nodes);
    templates.push({ component, classNode: cls, file, inline, elements });
    userInput.set(cls, input);
  }
  return { templates, userInput };
}

function memberRead(ast: AST): string | undefined {
  // Unwrap ASTWithSource
  const a = (ast as unknown as { ast?: AST }).ast ?? ast;
  if (a instanceof PropertyRead && (a.receiver instanceof ImplicitReceiver || a.receiver instanceof ThisReceiver)) return a.name;
  return undefined;
}

function recordHandler(handler: ASTWithSource, eventName: string, location: SourceLocation, input: TemplateUserInput) {
  const source = handler.source ?? '';
  const textOf = (ast: AST) => source.slice(ast.span.start, ast.span.end);
  const carriesInput = (ast: AST) => {
    const t = textOf(ast);
    return t.includes('$event') && (eventName === 'ngModelChange' || eventName === 'valueChange' || /\.value\b/.test(t));
  };
  const visit = (ast: AST) => {
    if (ast instanceof Binary && ast.operation === '=') {
      const target = memberRead(ast.left);
      if (target && carriesInput(ast.right)) addTo(input.properties, target, location);
    } else if (ast instanceof Call) {
      const method = memberRead(ast.receiver);
      if (method) {
        ast.args.forEach((arg, argIndex) => {
          if (carriesInput(arg)) addTo(input.methodArgs, method, { argIndex, location });
        });
      }
    }
  };
  const root = handler.ast;
  // Multiple statements `a(); b()` are represented as a Chain.
  const exprs = (root as unknown as { expressions?: AST[] }).expressions ?? [root];
  exprs.forEach(visit);
}

function addTo<V>(map: Map<string, V[]>, key: string, v: V) {
  const list = map.get(key);
  if (list) list.push(v);
  else map.set(key, [v]);
}
