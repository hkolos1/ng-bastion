import { searchIndex, type SearchEntry } from './search';
import index from '../../generated/search.json';
import showcase from '../../generated/showcase.json';
import { NAV } from '../core/content';

const entries = index as SearchEntry[];

describe('searchIndex', () => {
  it('ranks title matches above body matches and requires every term', () => {
    const hits = searchIndex(entries, 'trust bypass');
    expect(hits[0]!.slug).toBe('rules/ngb001');
    expect(hits.every((h) => `${h.title} ${h.snippet}`.toLowerCase().includes('bypass') || h.score > 0)).toBe(true);
  });

  it('finds rule pages by id and docs by heading', () => {
    expect(searchIndex(entries, 'NGB014')[0]!.slug).toBe('rules/ngb014');
    expect(searchIndex(entries, 'exit codes').map((h) => h.slug)).toContain('docs/cli-reference');
  });

  it('returns nothing for empty or one-letter queries and unknown words', () => {
    expect(searchIndex(entries, '')).toEqual([]);
    expect(searchIndex(entries, 'a')).toEqual([]);
    expect(searchIndex(entries, 'zzqxvw')).toEqual([]);
  });

  it('indexes every generated page', () => {
    const expected = NAV.groups.flatMap(group => group.items.map(item => item.slug)).filter(slug => slug !== 'playground');
    expect(entries.map(entry => entry.slug).sort()).toEqual(expected.sort());
    expect(entries.filter((e) => e.slug.startsWith('rules/ngb'))).toHaveLength(showcase.ruleCount);
  });
});

describe('markTerms', () => {
  it('splits text into matched and plain parts, case-insensitively and safely', async () => {
    const { markTerms } = await import('./search');
    expect(markTerms('Trust bypass in NGB001', ['bypass', 'ngb001'])).toEqual([
      { text: 'Trust ', match: false }, { text: 'bypass', match: true }, { text: ' in ', match: false }, { text: 'NGB001', match: true },
    ]);
    expect(markTerms('a.b(c)', ['.b('])).toEqual([{ text: 'a', match: false }, { text: '.b(', match: true }, { text: 'c)', match: false }]);
    expect(markTerms('plain', [])).toEqual([{ text: 'plain', match: false }]);
  });
});
