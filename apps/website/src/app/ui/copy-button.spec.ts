import { TestBed } from '@angular/core/testing';
import { CopyButton } from './copy-button';

describe('CopyButton', () => {
  afterEach(() => vi.useRealTimers());

  const render = (text = 'npx ngbastion scan') => {
    const fixture = TestBed.createComponent(CopyButton);
    fixture.componentRef.setInput('text', text);
    fixture.componentRef.setInput('label', 'Shell snippet');
    fixture.detectChanges();
    return { fixture, button: (fixture.nativeElement as HTMLElement).querySelector('button')! };
  };

  it('copies the exact text, shows success, announces it and resets', async () => {
    vi.useFakeTimers();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    const { fixture, button } = render('line 1\nline 2');
    expect(button.getAttribute('aria-label')).toBe('Copy Shell snippet');
    await fixture.componentInstance.copy();
    fixture.detectChanges();
    expect(writeText).toHaveBeenCalledWith('line 1\nline 2');
    expect(button.dataset['state']).toBe('copied');
    expect(button.getAttribute('aria-label')).toBe('Copied Shell snippet');
    expect((fixture.nativeElement as HTMLElement).querySelector('[aria-live]')!.textContent).toBe('Copied to clipboard');
    vi.advanceTimersByTime(1900);
    fixture.detectChanges();
    expect(button.dataset['state']).toBe('idle');
  });

  it('falls back to execCommand when the Clipboard API is unavailable', async () => {
    Object.defineProperty(navigator, 'clipboard', { value: { writeText: () => Promise.reject(new Error('denied')) }, configurable: true });
    const exec = vi.fn().mockReturnValue(true);
    Object.defineProperty(document, 'execCommand', { value: exec, configurable: true });
    const { fixture } = render();
    await fixture.componentInstance.copy();
    expect(exec).toHaveBeenCalledWith('copy');
    expect(fixture.componentInstance.state()).toBe('copied');
    expect(document.querySelector('textarea')).toBeNull();
  });

  it('reports failure when nothing can copy', async () => {
    Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true });
    Object.defineProperty(document, 'execCommand', { value: () => false, configurable: true });
    const { fixture } = render();
    await fixture.componentInstance.copy();
    expect(fixture.componentInstance.state()).toBe('error');
  });
});
