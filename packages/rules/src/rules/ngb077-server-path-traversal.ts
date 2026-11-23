import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { memberName, strip } from '../shared/common.js';
import { objectProp } from '../shared/http.js';
import { moduleCall, nodeModules, responseCall } from '../shared/server.js';
import { flowFinding, REQUEST_KINDS, taintedFlow } from '../shared/server-flow.js';

const FS = [...nodeModules('fs', 'fs/promises'), 'fs-extra', 'graceful-fs'];
const READ = ['readFile', 'readFileSync', 'createReadStream', 'readdir', 'readdirSync', 'open', 'openSync', 'opendir', 'readJson', 'readJsonSync', 'readJSON'];
const WRITE = ['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream', 'outputFile', 'outputFileSync', 'writeJson', 'writeJsonSync', 'outputJson'];
const DELETE = ['unlink', 'unlinkSync', 'rm', 'rmSync', 'rmdir', 'rmdirSync', 'remove', 'removeSync', 'emptyDir', 'emptyDirSync'];
/** Both path arguments matter. */
const TWO_PATHS = ['copyFile', 'copyFileSync', 'rename', 'renameSync', 'cp', 'cpSync', 'copy', 'copySync', 'move', 'moveSync', 'symlink', 'symlinkSync', 'link', 'linkSync'];
/** `path.basename()` drops directories; `sanitize-filename` and similar strip separators. */
const SANITIZERS = /\b(basename|sanitize\w*|filenamify|slugify)\(\)/i;
/** Guards that contain the resolved path or reject traversal sequences. */
const GUARD = /\.startsWith\(|\.relative\(|\.\.|isAbsolute|\bisInside|\bisSubPath|\/\^\[|\.test\(/;

const PATH_FNS = ['join', 'resolve', 'normalize', 'format'];

/**
 * Path operands: `path.join(a, b)` → [a, b] (also through `const p = path.join(…)`), otherwise the value.
 * Each operand is traced on its own so a sanitized operand does not hide an unsanitized one.
 */
function pathOperands(ctx: AnalysisContext, e: ts.Expression, depth = 0): ts.Expression[] {
  const t = ctx.ts;
  const x = strip(ctx, e);
  if (depth < 4 && t.isCallExpression(x) && moduleCall(ctx, x, nodeModules('path', 'path/posix', 'path/win32'), PATH_FNS)) {
    return x.arguments.flatMap((a) => pathOperands(ctx, a, depth + 1));
  }
  if (depth < 4 && t.isIdentifier(x)) {
    const d = ctx.symbols.declarationOf(x);
    if (d && t.isVariableDeclaration(d) && d.initializer && t.isVariableDeclarationList(d.parent) && d.parent.flags & t.NodeFlags.Const) {
      const init = strip(ctx, d.initializer);
      if (t.isCallExpression(init) && moduleCall(ctx, init, nodeModules('path', 'path/posix', 'path/win32'), PATH_FNS)) return pathOperands(ctx, init, depth + 1);
    }
  }
  return [x];
}

function guarded(ctx: AnalysisContext, node: ts.Node): string | undefined {
  for (const g of ctx.flow.guards(node)) {
    const text = g.condition.getText();
    if (GUARD.test(text)) return text.length > 80 ? `${text.slice(0, 77)}…` : text;
  }
  return undefined;
}

export const ngb077 = defineRule({
  meta: {
    id: 'NGB077',
    name: 'Path traversal in server code',
    category: 'ssr',
    defaultSeverity: 'high',
    cwe: ['CWE-22', 'CWE-73'],
    docs: {
      description:
        "Traces request data from Express / Node handlers (query, route params, body, cookies, path) into file-system paths in server code: `fs` / `fs/promises` / `fs-extra` reads, writes, deletes, copies and renames, and Express `res.sendFile()` / `res.download()` without a `root` option.",
      rationale:
        "`path.join(__dirname, 'files', req.params.name)` does not confine the result: `../../.env` or an absolute path escapes the folder. SSR servers then disclose `.env`, private keys and source code, or — for writes and deletes — overwrite application files.",
      patterns: [
        '`fs.readFile(p)`, `readFileSync`, `createReadStream`, `readdir`, `open` … (high), `writeFile`, `appendFile`, `createWriteStream`, `rm`, `unlink` … (high), `copyFile` / `rename` / `cp` (both paths), from `fs`, `node:fs`, `fs/promises`, `fs-extra` (import or `require()`)',
        '`res.sendFile(p)` / `res.download(p)` on Express responses without `{ root }` (Express rejects `..` below `root`)',
        'Recognized mitigation: `path.basename()` / `sanitize-filename` on the value, numeric conversion, and a dominating containment or traversal check (`resolved.startsWith(baseDir)`, `path.relative()`, `.includes("..")`, an anchored regex `.test()`)',
      ],
      limitations: [
        'Only request data is considered (not file names from databases or other services).',
        'Containment checks are recognized by shape; a check that is present but wrong (e.g. `startsWith(base)` without a trailing separator) is accepted.',
        'Static file middleware (`express.static`) is not analyzed — it confines paths itself.',
      ],
      falsePositives: [
        'Paths validated in a helper function before reaching the sink are reported; inline the check or document an exception.',
      ],
      remediation:
        'Never use request data as a path. Map identifiers to known files, or reduce the value to a file name (`path.basename()`), resolve it against a fixed directory and verify `path.relative(baseDir, resolved)` does not start with `..` and is not absolute. For downloads use `res.sendFile(name, { root: baseDir })`.',
      example: {
        unsafe: "res.sendFile(path.join(__dirname, 'invoices', req.params.file));",
        safe: "res.sendFile(path.basename(req.params.file), { root: path.join(__dirname, 'invoices') });",
      },
      references: [
        { title: 'OWASP — Path Traversal', url: 'https://owasp.org/www-community/attacks/Path_Traversal' },
        { title: 'Express — res.sendFile()', url: 'https://expressjs.com/en/api.html#res.sendFile' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    const check = (call: ts.CallExpression, value: ts.Expression | undefined, what: string, impact: string) => {
      if (!value) return false;
      let tv;
      for (const operand of pathOperands(ctx, value)) if ((tv = taintedFlow(ctx, operand, { kinds: REQUEST_KINDS, sanitizers: SANITIZERS }))) break;
      if (!tv || guarded(ctx, call)) return false;
      findings.push(flowFinding(ctx, call, tv, what, `Request data (${tv.flow.source.description}) chooses the file path of ${what}; '../' sequences or absolute paths ${impact}.`));
      return true;
    };
    for (const call of ctx.index.calls) {
      const [a0, a1] = call.arguments;
      const fn = moduleCall(ctx, call, FS, [...READ, ...WRITE, ...DELETE, ...TWO_PATHS]);
      if (fn) {
        const impact = READ.includes(fn) ? 'read files outside the intended folder' : DELETE.includes(fn) ? 'delete arbitrary files' : 'write or move files outside the intended folder';
        if (!check(call, a0, `fs.${fn}()`, impact) && TWO_PATHS.includes(fn)) check(call, a1, `fs.${fn}()`, impact);
        continue;
      }
      if (responseCall(ctx, call, ['sendFile', 'download'])) {
        const options = call.arguments.slice(1).find((a) => !!objectProp(ctx, a, 'root'));
        if (options) continue;
        check(call, a0, `res.${memberName(ctx, call.expression)}()`, 'send arbitrary server files to the client');
      }
    }
    return findings;
  },
});
