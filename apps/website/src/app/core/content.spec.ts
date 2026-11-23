import { NAV, hasPage, loadPage, neighbours, slugFromUrl } from './content';
import showcase from '../../generated/showcase.json';

/** Hand-written docs pages + rule index; rule pages come from the registry (showcase.ruleCount). */
const DOC_PAGES = 18;

describe('content model', () => {
  it('normalizes URLs to slugs', () => {
    expect(slugFromUrl('/docs/cli-reference/?x=1#exit-codes')).toBe('docs/cli-reference');
    expect(slugFromUrl('/rules/')).toBe('rules');
  });

  it('has a generated page for every navigation entry (except the playground route)', () => {
    const slugs = NAV.groups.flatMap((g) => g.items.map((i) => i.slug)).filter((s) => s !== 'playground');
    expect(slugs).toHaveLength(DOC_PAGES + showcase.ruleCount);
    expect(slugs).toEqual(expect.arrayContaining(['docs/baselines', 'docs/git-comparison']));
    for (const slug of slugs) expect(hasPage(slug), slug).toBe(true);
  });

  it('loads pages lazily with headings and blocks', async () => {
    const page = await loadPage('rules/ngb001');
    expect(page!.title).toBe('NGB001: Unsafe HTML trust bypass');
    expect(page!.headings.map((h) => h.id)).toContain('what-it-checks');
    expect(page!.blocks.some((b) => b.kind === 'heading')).toBe(true);
    expect(await loadPage('nope')).toBeUndefined();
  });

  it('computes previous/next links in sidebar order', () => {
    expect(neighbours('docs').prev).toBeUndefined();
    expect(neighbours('docs').next!.slug).toBe('docs/getting-started/installation');
    expect(neighbours('rules/ngb001').prev!.slug).toBe('rules');
  });
});
