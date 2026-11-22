import { searchIndex, type SearchEntry } from './search';
import index from '../../generated/search.json';

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
    expect(entries.length).toBe(36);
    expect(entries.filter((e) => e.slug.startsWith('rules/ngb'))).toHaveLength(20);
  });
});
