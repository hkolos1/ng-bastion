import { describe, expect, it } from 'vitest';
import { findings, one } from './helpers.js';

const IMP = `import { provideHttpClient, withNoXsrfProtection, withXsrfConfiguration, HttpClientXsrfModule } from '@angular/common/http';\n`;

describe('NGB021 disabled XSRF protection', () => {
  it('reports withNoXsrfProtection() with high confidence when cookies are sent', async () => {
    const res = await findings('NGB021', {
      'src/app/app.config.ts': `${IMP}export const appConfig = { providers: [provideHttpClient(withNoXsrfProtection())] };`,
      'src/app/api.ts': `export const opts = { withCredentials: true };`,
    });
    expect(res).toHaveLength(1);
    expect(res[0]!.confidence).toBe('high');
    expect(res[0]!.evidence.join()).toMatch(/cookies are sent/);
  });

  it('reports HttpClientXsrfModule.disable() (medium without auth evidence)', async () => {
    const res = await one('NGB021', `${IMP}export const imports = [HttpClientXsrfModule.disable()];`);
    expect(res).toHaveLength(1);
    expect(res[0]!.confidence).toBe('medium');
  });

  it('lowers confidence for bearer-token applications', async () => {
    const res = await one('NGB021', `${IMP}export const p = provideHttpClient(withNoXsrfProtection());\nexport const h = { Authorization: 'Bearer x' };`);
    expect(res[0]!.confidence).toBe('low');
  });

  it('safe: XSRF configuration and enabled defaults are not reported', async () => {
    expect(await one('NGB021', `${IMP}export const p = provideHttpClient(withXsrfConfiguration({ cookieName: 'XSRF', headerName: 'X-XSRF' }));`)).toEqual([]);
  });

  it('false-positive regression: a project function named withNoXsrfProtection is not Angular', async () => {
    expect(await one('NGB021', `function withNoXsrfProtection() { return 1; }\nexport const x = withNoXsrfProtection();\nconst m = { disable: () => 0 };\nm.disable();`)).toEqual([]);
  });
});
