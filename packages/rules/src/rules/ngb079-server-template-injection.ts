import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { moduleCall } from '../shared/server.js';
import { flowFinding, taintedFlow } from '../shared/server-flow.js';

/** Template engines and the functions that compile their first argument as template source. */
const ENGINES: [modules: string[], fns: string[]][] = [
  [['ejs'], ['render', 'compile']],
  [['pug', 'jade'], ['render', 'compile', 'compileClient']],
  [['handlebars', 'hbs'], ['compile', 'precompile']],
  [['nunjucks'], ['renderString', 'compile']],
  [['lodash', 'lodash-es', 'underscore', 'lodash.template'], ['template']],
  [['mustache'], ['render', 'parse']],
  [['dot', 'dot-template'], ['template', 'compile']],
  [['eta'], ['renderString', 'renderStringAsync', 'compile']],
  [['liquidjs'], ['parseAndRender', 'parseAndRenderSync', 'parse']],
  [['twig'], ['twig']],
];

export const ngb079 = defineRule({
  meta: {
    id: 'NGB079',
    name: 'Server-side template injection',
    category: 'ssr',
    defaultSeverity: 'critical',
    cwe: ['CWE-1336', 'CWE-94'],
    docs: {
      description:
        "Traces untrusted data into the *template source* compiled by server-side template engines: `ejs.render/compile`, `pug.render/compile`, `Handlebars.compile`, `nunjucks.renderString`, lodash / underscore `_.template`, `Mustache.render`, doT, Eta, LiquidJS and Twig. Data passed as template variables (the second argument) is not reported.",
      rationale:
        "Template languages are programming languages: EJS, Pug, doT and lodash templates execute embedded JavaScript, and Handlebars / Nunjucks have known sandbox escapes. A request value that becomes part of the template text is code execution on the server (or at least full control of the rendered page), unlike the same value passed as data, which the engine escapes.",
      patterns: [
        "`ejs.render(`<h1>${req.query.title}</h1>`)`, `pug.compile(req.body.layout)`, `Handlebars.compile(tpl)`, `_.template(req.body.text)` … where the template source contains traced untrusted data (import, namespace / default import or `require()`)",
        'Not reported: constant templates with request values as data (`ejs.render(TEMPLATE, { title: req.query.title })`), `res.render(view, data)` (view files)',
      ],
      limitations: [
        'Template engines reached through framework adapters (`app.engine`, `consolidate`) are not modeled; `res.render()` with a request-chosen view name is not reported.',
        'Templates loaded from the database or CMS (stored template injection) are only reported when the HTTP response source is traced.',
      ],
      falsePositives: [
        'Engines configured as logic-less with escaping (e.g. Mustache) are less dangerous; the finding still means users can rewrite the page markup.',
      ],
      remediation:
        'Keep templates constant (files or literals in the code base) and pass request values only as template data. If users must author templates, use a logic-less engine in a sandboxed process and treat the output as untrusted HTML.',
      example: {
        unsafe: "res.send(ejs.render(`<h1>Hello ${req.query.name}</h1>`));",
        safe: "res.send(ejs.render('<h1>Hello <%= name %></h1>', { name: req.query.name }));",
      },
      references: [
        { title: 'PortSwigger — Server-side template injection', url: 'https://portswigger.net/web-security/server-side-template-injection' },
        { title: 'OWASP WSTG — Testing for Server-side Template Injection', url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const call of ctx.index.calls) {
      const source = call.arguments[0];
      if (!source) continue;
      for (const [modules, fns] of ENGINES) {
        const fn = moduleCall(ctx, call, modules, fns);
        if (!fn) continue;
        const tv = taintedFlow(ctx, source, { context: 'code' });
        if (tv) findings.push(flowFinding(ctx, call, tv, `${modules[0]} ${fn}() template source`, `Untrusted data (${tv.flow.source.description}) becomes part of the ${modules[0]} template compiled by ${fn}(); template syntax in it runs on the server (template injection). Pass it as template data instead.`));
        break;
      }
    }
    return findings;
  },
});
