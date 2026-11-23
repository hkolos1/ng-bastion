/* global window, Event, document */
// Run against the built package with locally installed Chrome.
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { chromium } from 'playwright-core';
import { renderHtml } from 'ngbastion';

const marker = '</script><b id="injected" onclick="window.reportInjected=true">fixture</b>';
const location = { file: 'src/' + marker + '.ts', line: 3, column: 7, endLine: 3, endColumn: 13 };
const finding = {
  ruleId: 'NGB003', ruleName: 'DOM injection', category: '__proto__', severity: 'high',
  confidence: 'medium', evidenceKind: 'heuristic', level: 'error', message: marker,
  location, fingerprint: '000001', project: 'sample', snippet: 'const text = "' + marker + '";',
  evidence: [marker], trace: ['source', 'transform', 'sink'].map(kind => ({ ...location, kind, description: marker })),
};
const result = {
  tool: { name: 'NgBastion', version: 'fixture', pluginApiVersion: 1 }, workspaceRoot: '/fixture',
  startedAt: '2026-01-01T00:00:00Z', durationMs: 18, projects: [{ name: marker }], rules: [],
  suppressed: [], diagnostics: [], stats: { filesAnalyzed: 1, hiddenBelowConfidence: 0 },
  gate: { failOn: 'high', failed: true },
};
const tmp = await mkdtemp(path.join(tmpdir(), 'ngb-browser-'));
const browser = await chromium.launch({ channel: 'chrome' });
try {
  const page = await browser.newPage({ offline: true });
  const cdp = await page.context().newCDPSession(page);
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  page.on('console', msg => { if (msg.type() === 'error') errors.push(msg.text()); });
  page.on('request', req => { if (/^https?:/.test(req.url())) errors.push(req.url()); });
  for (const size of [0, 4, 350, 2000]) {
    const findings = Array.from({ length: size }, (_, i) => ({
      ...finding, severity: i % 2 ? 'medium' : 'high', confidence: i % 2 ? 'high' : 'medium',
      ruleId: i % 2 ? 'NGB001' : 'NGB003', location: { ...location, line: i + 1 }, fingerprint: 'sample-' + i,
    }));
    if (size) findings.at(-1).location.file = 'zz/' + 'long-folder/'.repeat(90) + 'main.ts';
    if (size) findings[0].trace = Array.from({ length: 60 }, (_, i) => ({ ...location,
      kind: i === 0 ? 'source' : i === 59 ? 'sink' : 'transform', description: 'Step ' + i }));
    const ids = findings.map((f, i) => { f.fingerprintV2 = f.fingerprint; return [f.fingerprint, i % 2 ? 'new' : 'existing']; });
    const context = { comparison: { new: size / 2, existing: size / 2, uncertain: 0, unverified: [], resolved: [], warnings: [], statuses: Object.fromEntries(ids) } };
    const rss = process.memoryUsage().rss;
    const start = performance.now();
    const html = renderHtml({ ...result, findings }, context);
    const generation = performance.now() - start;
    const generationRssDelta = process.memoryUsage().rss - rss;
    const file = path.join(tmp, 'report-' + size + '.html');
    await writeFile(file, html);
    const loading = performance.now();
    await page.goto(pathToFileURL(file).href);
    const load = performance.now() - loading;
    assert.equal(await page.locator('.finding').count(), Math.min(50, size));
    assert.equal(await page.locator('#injected').count(), 0);
    assert.equal(await page.evaluate(() => window.reportInjected), undefined);
    const search = await page.locator('#search').evaluate(input => {
      input.value = 'sample-1';
      const start = performance.now();
      input.dispatchEvent(new Event('input', { bubbles: true }));
      return performance.now() - start;
    });
    if (size) assert.match(await page.locator('#matches').innerText(), /Showing/);
    await page.locator('#reset').click();
    if (size) {
      for (const [id, value] of [['confidence', 'high'], ['rule', 'NGB001'], ['category', '__proto__'], ['status', 'new'], ['file', location.file]]) {
        await page.locator('#' + id).selectOption(value);
        const visible = await page.locator('.finding').evaluateAll((elements, id) => elements.map(el => el.dataset[id]), id);
        assert.ok(visible.length && visible.every(v => v === value));
        await page.locator('#reset').click();
      }
      if (size > 50) {
        await page.locator('#next').click();
        assert.match(await page.locator('#matches').innerText(), /Showing 51/);
        await page.locator('#prev').click();
      }
      await page.locator('#severity').selectOption('medium');
      assert.equal(await page.locator('.finding[data-severity=high]').count(), 0);
      await page.locator('#reset').click();
      await page.locator('#sort').selectOption('Rule ID');
      assert.equal(await page.locator('.finding').first().getAttribute('data-rule'), 'NGB001');
      await page.locator('#reset').click();
      await page.locator('.finding summary').first().focus();
      await page.keyboard.press('Enter');
      assert.equal(await page.locator('.finding[open] .trace li').count(), 60);
      await page.locator('#theme').click();
      assert.ok(await page.locator('html').getAttribute('data-theme'));
      await page.evaluate(() => window.dispatchEvent(new Event('beforeprint')));
      assert.equal(await page.locator('.finding[open]').count(), size);
      if (size === 4) assert.ok((await page.pdf({ preferCSSPageSize: true })).length > 1000);
      await page.evaluate(() => window.dispatchEvent(new Event('afterprint')));
    }
    const { usedSize: heap } = await cdp.send('Runtime.getHeapUsage');
    console.log(JSON.stringify({ findings: size, bytes: Buffer.byteLength(html), generationMs: Math.round(generation), loadMs: Math.round(load), searchMs: Math.round(search), heapBytes: heap, generationRssDelta }));
  }
  const fallback = await browser.newPage({ javaScriptEnabled: false, offline: true, viewport: { width: 390, height: 844 } });
  await fallback.goto(pathToFileURL(path.join(tmp, 'report-4.html')).href);
  assert.equal(await fallback.locator('.finding').count(), 4);
  assert.equal(await fallback.locator('#controls').isVisible(), false);
  await fallback.locator('.finding summary').first().click();
  assert.equal(await fallback.locator('.finding[open] .trace li').count(), 60);
  assert.ok(await fallback.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
  await fallback.close();
  assert.deepEqual(errors, []);
} finally {
  await browser.close();
  await rm(tmp, { recursive: true, force: true });
}
