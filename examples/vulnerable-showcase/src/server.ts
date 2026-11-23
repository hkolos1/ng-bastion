import type { Request, Response } from 'express';

declare const API_BASE_URL: unknown;
declare const indexHtml: string;

/** SSR request handler (synthetic; the showcase is never deployed). */
export function renderPage(req: Request, res: Response, user: { name: string; email: string }, sessionId: string): unknown[] {
  // NGB042: the client-controlled Host header becomes the API base URL for server-side requests.
  const providers = [{ provide: API_BASE_URL, useValue: `${req.protocol}://${req.get('host')}/api` }];
  // NGB043: session cookie readable by scripts and sent over plain HTTP.
  res.cookie('session', sessionId, { sameSite: 'lax' });
  // NGB041: JSON.stringify does not escape "</script>" — a display name can inject markup.
  res.send(indexHtml.replace('</head>', `<script>window.__USER__ = ${JSON.stringify(user)}</script></head>`));
  return providers;
}
