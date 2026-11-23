import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const directory = new URL('../report-assets/', import.meta.url);

export function loadReportAssets() {
  const read = (file: string) => readFileSync(new URL(file, directory));
  const font = read('code.woff2').toString('base64');
  const assets = {
    style: `/* ${read('FONT-LICENSE.txt').toString()} */\n` + read('report.css').toString().replace('FONT_DATA', font),
    script: read('explorer.js').toString(),
    mark: read('mark.svg').toString(),
  };
  const digest = (text: string) => createHash('sha256').update(text).digest('base64');
  const csp = `default-src 'none'; script-src 'sha256-${digest(assets.script)}'; style-src 'sha256-${digest(assets.style)}'; font-src data:; base-uri 'none'; form-action 'none'; object-src 'none'`;
  return { ...assets, csp };
}
