import navData from '../../generated/nav.json';

export interface Heading {
  depth: 2 | 3;
  id: string;
  text: string;
}

export interface PageData {
  slug: string;
  title: string;
  description: string;
  section: string;
  /** Build-time rendered content: headings are rendered by Angular, HTML blocks via sanitized [innerHTML]. */
  blocks: ContentBlock[];
  headings: Heading[];
}

export type ContentBlock =
  | { kind: 'html'; html: string }
  | { kind: 'heading'; depth: number; id: string; html: string };

export interface NavItem {
  slug: string;
  label: string;
}
export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const NAV: { groups: NavGroup[]; order: string[] } = navData as { groups: NavGroup[]; order: string[] };

/** Lazy chunks: one per page, loaded by the route resolver (prerendered during SSG). */
const PAGES = import.meta.glob<PageData>('../../generated/pages/*.json', { import: 'default' });

export const pageFile = (slug: string) => `../../generated/pages/${slug.replace(/\//g, '__')}.json`;

export function hasPage(slug: string): boolean {
  return pageFile(slug) in PAGES;
}

export async function loadPage(slug: string): Promise<PageData | undefined> {
  const loader = PAGES[pageFile(slug)];
  return loader ? loader() : undefined;
}

/** `/docs/cli-reference/?x#y` → `docs/cli-reference`. */
export function slugFromUrl(url: string): string {
  return url.split(/[?#]/)[0]!.replace(/^\/+|\/+$/g, '');
}

export function neighbours(slug: string): { prev?: NavItem; next?: NavItem } {
  const all = NAV.groups.flatMap((g) => g.items).filter((i) => NAV.order.includes(i.slug));
  const i = all.findIndex((x) => x.slug === slug);
  if (i < 0) return {};
  return { ...(i > 0 ? { prev: all[i - 1] } : {}), ...(i < all.length - 1 ? { next: all[i + 1] } : {}) };
}
