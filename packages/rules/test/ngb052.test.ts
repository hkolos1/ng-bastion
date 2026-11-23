import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const pre = `import { Injectable, Sanitizer, SecurityContext } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';
import DOMPurify from 'dompurify';
`;

describe('NGB052 unsafe custom Angular sanitizer', () => {
  it('reports pass-through and partial replacements of Sanitizer / DomSanitizer', async () => {
    const res = await findings('NGB052', {
      'src/app/app.config.ts': `${pre}
@Injectable() class NoopSanitizer extends Sanitizer { sanitize(_c: SecurityContext, value: string | null) { return value; } }
class Partial { sanitize(c: SecurityContext, value: string) { if (c === SecurityContext.HTML) { return value; } return null; } }
export const a = [{ provide: Sanitizer, useClass: NoopSanitizer }];
export const b = [{ provide: DomSanitizer, useClass: Partial }];
export const c = [{ provide: Sanitizer, useValue: { sanitize: (_c: SecurityContext, v: string) => String(v) } }];`,
    });
    expect(res.map((f) => `${f.severity}/${f.confidence}`).sort()).toEqual(['high/high', 'high/high', 'high/medium']);
    expect(res.find((f) => f.confidence === 'medium')!.message).toMatch(/Partial.*1 of 2 paths/);
    expect(res.some((f) => /NoopSanitizer/.test(f.message))).toBe(true);
  });

  it('reports custom logic with low confidence', async () => {
    const [f, ...rest] = await findings('NGB052', {
      'src/app/app.config.ts': `${pre}
class Stripper { sanitize(_c: SecurityContext, v: string) { return v.replace(/<script>/g, ''); } }
export const p = [{ provide: Sanitizer, useClass: Stripper }];`,
    });
    expect(rest).toEqual([]);
    expect(f!.confidence).toBe('low');
    expect(f!.severity).toBe('medium');
  });

  it('safe: delegation to DOMPurify or Angular DomSanitizer', async () => {
    expect(await findings('NGB052', {
      'src/app/app.config.ts': `${pre}
class Purify { sanitize(_c: SecurityContext, v: string) { return DOMPurify.sanitize(v); } }
@Injectable() class Wrapping { constructor(private inner: DomSanitizer) {} sanitize(c: SecurityContext, v: string) { return this.inner.sanitize(c, v); } }
export const p = [{ provide: Sanitizer, useClass: Purify }, { provide: DomSanitizer, useClass: Wrapping }];`,
    })).toEqual([]);
  });

  it('false-positive regression: unrelated tokens and project classes named Sanitizer', async () => {
    expect(await findings('NGB052', {
      'src/app/app.config.ts': `import { InjectionToken } from '@angular/core';
class Sanitizer { sanitize(v: string) { return v; } }
const TEXT_CLEANER = new InjectionToken<unknown>('cleaner');
class Echo { sanitize(_c: number, v: string) { return v; } }
export const p = [{ provide: Sanitizer, useClass: Echo }, { provide: TEXT_CLEANER, useClass: Echo }];`,
    })).toEqual([]);
  });
});
