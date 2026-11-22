import { TestBed } from '@angular/core/testing';
import { CodeBlock, type CodeSnippet } from './code-block';

const ts: CodeSnippet = { lang: 'ts', label: 'TypeScript', code: 'const a = 1;\nconst b = 2;\nconst c = 3;\nconst d = 4;', lines: ['<span class="sk-1">const</span> a = 1;', 'const b = 2;', 'const c = 3;', 'const d = 4;'] };
const sh: CodeSnippet = { lang: 'sh', label: 'Shell', code: 'pnpm install\npnpm build\npnpm test\npnpm lint', lines: ['pnpm install', 'pnpm build', 'pnpm test', 'pnpm lint'] };

describe('CodeBlock', () => {
  const render = (snippet: CodeSnippet, inputs: Record<string, unknown> = {}) => {
    const fixture = TestBed.createComponent(CodeBlock);
    fixture.componentRef.setInput('snippet', snippet);
    for (const [k, v] of Object.entries(inputs)) fixture.componentRef.setInput(k, v);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  };

  it('renders a language label, highlighted lines and a keyboard-focusable scroll region', () => {
    const el = render(ts, { filename: 'a.ts' });
    expect(el.querySelector('.code-lang')!.textContent).toBe('TypeScript');
    expect(el.querySelector('.code-file')!.textContent).toBe('a.ts');
    expect(el.querySelectorAll('.line')).toHaveLength(4);
    expect(el.querySelector('.line span.sk-1')!.textContent).toBe('const');
    expect(el.querySelector('pre')!.getAttribute('tabindex')).toBe('0');
  });

  it('numbers code lines automatically but not shell commands', () => {
    expect(render(ts).querySelector('.code-block')!.classList).toContain('numbered');
    expect(render(sh).querySelector('.code-block')!.classList).not.toContain('numbered');
    expect(render(sh, { lineNumbers: true }).querySelector('.code-block')!.classList).toContain('numbered');
  });

  it('copies the clean source, never line numbers or labels', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    const el = render(ts, { filename: 'a.ts' });
    el.querySelector<HTMLButtonElement>('.copy-btn')!.click();
    await Promise.resolve();
    expect(writeText).toHaveBeenCalledWith(ts.code);
    // Line numbers are CSS counters: they are not part of the DOM text.
    expect(el.querySelector('code')!.textContent).toBe(ts.code.replace(/\n/g, '').replace('const a', 'const a'));
  });

  it('marks highlighted lines', () => {
    const el = render(ts, { highlight: new Set([2, 4]) });
    expect(Array.from(el.querySelectorAll('.line')).map((l) => l.classList.contains('hit'))).toEqual([false, true, false, true]);
  });
});
