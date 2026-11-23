// Test the hydrated site both without the API and with native experimental WebMCP.
/* global document, navigator */
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, resolve, sep } from 'node:path';
import { chromium } from 'playwright-core';

const root = resolve('apps/website/dist/analog/public');
const types = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };
const server = createServer(async (req, res) => {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  const path = resolve(root, '.' + pathname, pathname.endsWith('/') ? 'index.html' : '');
  if (!path.startsWith(root + sep)) { res.writeHead(403).end(); return; }
  try {
    const bytes = await readFile(path);
    res.writeHead(200, { 'Content-Type': types[extname(path)] ?? 'application/octet-stream' }).end(bytes);
  } catch { res.writeHead(404).end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
  browser = await chromium.launch({ channel: 'chrome', args: ['--enable-features=WebMCP'] });
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', msg => { if (msg.type() === 'error') errors.push(msg.text()); });
  await page.addInitScript(() => {
    for (const host of [document, navigator]) Object.defineProperty(host, 'modelContext', { value: undefined });
  });
  await page.goto('http://127.0.0.1:' + server.address().port + '/');
  await page.getByRole('link', { name: 'Open the playground' }).click();
  const editor = page.locator('ngb-snippet-editor');
  await editor.getByText('Analyze snippet', { exact: true }).click();
  await editor.getByText('NGB018', { exact: true }).waitFor();
  const downloaded = page.waitForEvent('download');
  await editor.getByText('Download HTML report').click();
  const report = await downloaded;
  assert.equal(report.suggestedFilename(), 'ngbastion-snippet.html');
  const html = await readFile(await report.path(), 'utf8');
  assert.ok(html.includes('data-rule="NGB018"'));
  assert.ok(!html.includes('BlueFern-84-Orbit-27'));
  await editor.getByText('Load safe example').click();
  await editor.getByText('Analyze snippet', { exact: true }).click();
  await editor.getByText(/0 findings · NGB018/).waitFor();
  assert.deepEqual(errors, []);
  console.log('Verified hydrated playground navigation, worker analysis, HTML download and zero findings in Chrome without WebMCP.');
  const native = await browser.newPage();
  native.setDefaultTimeout(15000);
  native.on('pageerror', error => errors.push(error.message));
  const loaded = [];
  native.on('request', req => loaded.push(req.url()));
  await native.goto('http://127.0.0.1:' + server.address().port + '/');
  const registered = await native.webmcp.tools();
  assert.deepEqual(registered.map(tool => tool.name).sort(), [
    'ngbastion_analyze_snippet', 'ngbastion_explain_rule', 'ngbastion_generate_report',
    'ngbastion_get_installation', 'ngbastion_get_rules', 'ngbastion_search_rules',
  ]);
  const call = (name, input = {}) => native.webmcp.callTool('ngbastion_' + name, input);
  assert.equal((await call('get_installation')).package, 'ngbastion');
  assert.equal((await call('get_rules', { limit: 1 })).total, 100);
  assert.equal((await call('explain_rule', { ruleId: 'NGB018' })).id, 'NGB018');
  assert.equal((await call('search_rules', { query: 'NGB018' })).rules[0].id, 'NGB018');
  assert.ok(!loaded.some(url => /\/(inspect\.worker|report)-/.test(url)));
  const analysis = await call('analyze_snippet', { code: "const clientSecret = 'BlueFern-84-Orbit-27';" });
  assert.equal(analysis.status, 'ok', JSON.stringify(analysis));
  assert.equal(analysis.findings[0].ruleId, 'NGB018');
  await native.getByRole('link', { name: 'Open the playground' }).click();
  await native.locator('ngb-snippet-editor').waitFor();
  assert.equal((await native.webmcp.tools()).length, 6);
  const artifact = await call('generate_report', { analysisId: analysis.analysisId });
  assert.ok(artifact.html.includes('data-rule="NGB018"'));
  assert.deepEqual(errors, []);
  console.log('Verified six native WebMCP tools across navigation in Chrome ' + browser.version());

} finally {
  await browser?.close();
  server.close();
}
