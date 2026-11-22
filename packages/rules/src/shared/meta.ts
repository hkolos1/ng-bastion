/** Base URL of the per-rule documentation pages. */
export const DOCS_BASE = 'https://ngbastion.dev/rules';
export const docsUrl = (id: string) => `${DOCS_BASE}/${id.toLowerCase()}`;
