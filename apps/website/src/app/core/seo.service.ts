import { DOCUMENT } from '@angular/common';
import { Injectable, inject } from '@angular/core';
import { Meta, Title } from '@angular/platform-browser';

export const SITE = 'https://ngbastion.dev';
export const SOCIAL_IMAGE = `${SITE}/brand/social-preview.png`;

export interface SeoInput {
  title: string;
  description: string;
  /** Route path, e.g. `/docs/cli-reference`. Canonical URLs always end with a slash. */
  path: string;
  jsonLd?: Record<string, unknown>;
}

export function canonicalUrl(path: string): string {
  const clean = path.split(/[?#]/)[0]!.replace(/\/+$/, '');
  return `${SITE}${clean}/`;
}

/** Title, description, canonical link, Open Graph / Twitter tags and optional JSON-LD — rendered during SSG. */
@Injectable({ providedIn: 'root' })
export class Seo {
  private readonly title = inject(Title);
  private readonly meta = inject(Meta);
  private readonly document = inject(DOCUMENT);

  set({ title, description, path, jsonLd }: SeoInput): void {
    const url = canonicalUrl(path);
    this.title.setTitle(title);
    const tags: [string, string, string][] = [
      ['name', 'description', description],
      ['property', 'og:type', 'website'],
      ['property', 'og:site_name', 'NgBastion'],
      ['property', 'og:title', title],
      ['property', 'og:description', description],
      ['property', 'og:url', url],
      ['property', 'og:image', SOCIAL_IMAGE],
      ['property', 'og:image:width', '1280'],
      ['property', 'og:image:height', '640'],
      ['name', 'twitter:card', 'summary_large_image'],
      ['name', 'twitter:title', title],
      ['name', 'twitter:description', description],
      ['name', 'twitter:image', SOCIAL_IMAGE],
    ];
    for (const [attr, key, content] of tags) this.meta.updateTag({ [attr]: key, content }, `${attr}="${key}"`);

    const head = this.document.head;
    let link = head.querySelector<HTMLLinkElement>('link[rel="canonical"]');
    if (!link) {
      link = this.document.createElement('link');
      link.rel = 'canonical';
      head.appendChild(link);
    }
    link.href = url;

    head.querySelector('script[data-ngb-jsonld]')?.remove();
    if (jsonLd) {
      const script = this.document.createElement('script');
      script.type = 'application/ld+json';
      script.setAttribute('data-ngb-jsonld', '');
      // textContent (not innerHTML): the JSON is never parsed as markup.
      script.textContent = JSON.stringify(jsonLd).replace(/</g, '\\u003c');
      head.appendChild(script);
    }
  }
}
