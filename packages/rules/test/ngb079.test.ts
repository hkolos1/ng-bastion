import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const EXPRESS = `import type { Request, Response } from 'express';\n`;

describe('NGB079 server-side template injection', () => {
  it('reports template sources built from request data (ejs, Handlebars, lodash, pug via require)', async () => {
    const res = await findings('NGB079', {
      'src/server.ts': `${EXPRESS}import ejs from 'ejs';
import Handlebars from 'handlebars';
import _ from 'lodash';
const pug = require('pug');
export function h(req: Request, res: Response) {
  res.send(ejs.render(\`<h1>Hello \${req.query.name}</h1>\`));
  Handlebars.compile(req.body.template);
  _.template('<p>' + req.body.text + '</p>');
  pug.render(req.query.layout as string);
}`,
    });
    expect(res).toHaveLength(4);
    expect(res.every((r) => r.severity === undefined || r.severity === 'critical')).toBe(true);
  });

  it('safe: constant templates with request values as data; res.render', async () => {
    expect(await findings('NGB079', {
      'src/server.ts': `${EXPRESS}import ejs from 'ejs';
import { template } from 'lodash';
const tpl = template('<p><%- text %></p>');
export function h(req: Request, res: Response) {
  res.send(ejs.render('<h1>Hello <%= name %></h1>', { name: req.query.name }));
  res.send(tpl({ text: req.body.text }));
  res.render('profile', { name: req.query.name });
}`,
    })).toEqual([]);
  });

  it('false-positive regression: render/compile methods of other objects', async () => {
    expect(await findings('NGB079', {
      'src/server.ts': `${EXPRESS}declare const renderer: { render(s: string): string; compile(s: string): string };
export function h(req: Request) { renderer.render(req.query.q as string); renderer.compile(req.body.x); }`,
    })).toEqual([]);
  });
});
