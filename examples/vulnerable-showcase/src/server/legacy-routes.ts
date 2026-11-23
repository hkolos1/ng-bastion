import type { Request, Response } from 'express';
import { createCipheriv, createHmac } from 'node:crypto';

declare const WEBHOOK_SECRET: string;

/** Synthetic Express handlers next to the SSR engine (the showcase is never deployed). */
export function loginDone(req: Request, res: Response): void {
  // NGB061: open redirect — the `next` parameter is used as the redirect target.
  res.redirect(String(req.query['next']));
}

export function securityHeaders(_req: Request, res: Response): void {
  // NGB062: camera and microphone delegated to every origin.
  res.setHeader('Permissions-Policy', 'camera=*, microphone=*');
}

export function searchPage(req: Request, res: Response): void {
  // NGB069: reflected XSS — the search term is written into HTML without escaping.
  res.send(`<p>No results for ${req.query['q']}</p>`);
}

export function paymentWebhook(req: Request, res: Response): void {
  const expected = createHmac('sha256', WEBHOOK_SECRET).update(JSON.stringify(req.body)).digest('hex');
  // NGB070: string comparison leaks the matching prefix length through timing.
  if (req.get('x-signature') !== expected) {
    res.sendStatus(401);
    return;
  }
  res.sendStatus(204);
}

export function legacyExport(data: string, iv: Buffer): Buffer {
  // NGB065: Triple DES (64-bit block). NGB068: the key is hardcoded.
  const cipher = createCipheriv('des-ede3-cbc', Buffer.from('0123456789abcdef01234567'), iv);
  return Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
}
