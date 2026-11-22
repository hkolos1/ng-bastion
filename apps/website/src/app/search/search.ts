export interface SearchEntry {
  slug: string;
  title: string;
  section: string;
  headings: string[];
  text: string;
}

export interface TextPart {
  text: string;
  match: boolean;
}

export interface SearchHit {
  slug: string;
  title: string;
  section: string;
  snippet: string;
  score: number;
  titleParts: TextPart[];
  snippetParts: TextPart[];
}

/** Splits text into plain and matched segments (rendered as <mark>, never as HTML). */
export function markTerms(text: string, terms: readonly string[]): TextPart[] {
  const escaped = terms.filter(Boolean).map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  if (!escaped.length) return [{ text, match: false }];
  // With a capturing group, split() puts the matches at odd indices.
  return text.split(new RegExp(`(${escaped.join('|')})`, 'gi'))
    .map((part, i) => ({ text: part, match: i % 2 === 1 }))
    .filter((p) => p.text);
}

/** Small, dependency-free ranking over the build-time index: title ≫ headings ≫ body. */
export function searchIndex(index: readonly SearchEntry[], query: string, limit = 8): SearchHit[] {
  const terms = query.toLowerCase().split(/\s+/).filter((t) => t.length > 1);
  if (!terms.length) return [];
  const hits: SearchHit[] = [];
  for (const e of index) {
    const title = e.title.toLowerCase();
    const heads = e.headings.join(' ').toLowerCase();
    const text = e.text.toLowerCase();
    let score = 0;
    let all = true;
    for (const t of terms) {
      const s = (title.includes(t) ? 10 : 0) + (heads.includes(t) ? 4 : 0) + (text.includes(t) ? 1 : 0);
      if (!s) all = false;
      score += s;
    }
    if (!all) continue;
    if (title.startsWith(terms[0]!)) score += 5;
    const at = text.indexOf(terms[0]!);
    const snippet = at < 0 ? e.text.slice(0, 140) : `${at > 40 ? '…' : ''}${e.text.slice(Math.max(0, at - 40), at + 100)}…`;
    hits.push({ slug: e.slug, title: e.title, section: e.section, snippet, score, titleParts: markTerms(e.title, terms), snippetParts: markTerms(snippet, terms) });
  }
  return hits.sort((a, b) => b.score - a.score || a.title.localeCompare(b.title)).slice(0, limit);
}
