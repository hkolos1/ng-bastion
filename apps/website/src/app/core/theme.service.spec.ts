import { DOCUMENT } from '@angular/common';
import { TestBed } from '@angular/core/testing';
import { ThemeService } from './theme.service';

describe('ThemeService', () => {
  afterEach(() => {
    delete TestBed.inject(DOCUMENT).documentElement.dataset['theme'];
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('respects a theme already applied before boot and toggles it', () => {
    TestBed.inject(DOCUMENT).documentElement.dataset['theme'] = 'light';
    const theme = TestBed.inject(ThemeService);
    expect(theme.theme()).toBe('light');
    theme.toggle();
    expect(theme.theme()).toBe('dark');
    expect(TestBed.inject(DOCUMENT).documentElement.dataset['theme']).toBe('dark');
    expect(localStorage.getItem('ngbastion-theme')).toBe('dark');
  });

  it('keeps working when storage is unavailable', () => {
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    const theme = TestBed.inject(ThemeService);
    const before = theme.theme();
    expect(() => theme.toggle()).not.toThrow();
    expect(theme.theme()).not.toBe(before);
  });
});
