import jwt from 'jsonwebtoken';
import type { NextFunction, Request, Response } from 'express';

/** NGB059: the token is decoded, never verified, and its role claim grants admin access. */
export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  const claims = jwt.decode(String(req.headers.authorization).slice(7)) as { role?: string } | null;
  if (claims?.role === 'admin') return next();
  res.sendStatus(403);
}
