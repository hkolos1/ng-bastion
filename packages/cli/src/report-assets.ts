import { readFileSync } from 'node:fs';

const directory = new URL('../report-assets/', import.meta.url);

export function loadReportAssets() {
  const read = (file: string) => readFileSync(new URL(file, directory));
  const font = read('code.woff2').toString('base64');
  return {
    style: `/* ${read('FONT-LICENSE.txt').toString()} */\n` + read('report.css').toString().replace('FONT_DATA', font),
    script: read('explorer.js').toString(),
    mark: read('mark.svg').toString(),
  };
}
