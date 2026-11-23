import type { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import { WebSocketServer } from 'ws';
import * as cookie from 'cookie';

declare const app: { use(x: unknown): void; set(k: string, v: unknown): void; post(p: string, h: (req: Request, res: Response) => void): void };
declare const httpServer: unknown;
declare const sessions: Map<string, { id: string }>;
declare function authenticate(body: unknown): Promise<{ id: string }>;
declare function loadOrders(userId: string): Promise<unknown[]>;

// NGB081: reflects every origin while allowing cookies.
app.use(cors({ origin: true, credentials: true }));

// NGB082: X-Forwarded-For is client-controlled.
export function adminOnly(req: Request, res: Response, next: NextFunction) {
  const ip = (req.headers['x-forwarded-for'] as string | undefined)?.split(',')[0]?.trim();
  if (ip !== '127.0.0.1') return res.sendStatus(403);
  next();
}

// NGB083: cookie-authenticated WebSocket without an Origin check.
const wss = new WebSocketServer({ server: httpServer as never });
wss.on('connection', (ws: { send(d: string): void }, req: { headers: Record<string, string | undefined> }) => {
  const user = sessions.get(cookie.parse(req.headers.cookie ?? '')['sid'] ?? '');
  ws.send(JSON.stringify(user));
});

// NGB084: session ID is not regenerated at login.
export async function login(req: Request, res: Response) {
  const user = await authenticate(req.body);
  req.session.userId = user.id;
  res.redirect('/');
}

// NGB085: stack trace sent to the client.
export async function orders(req: Request, res: Response) {
  try {
    res.json(await loadOrders(req.params['id'] ?? ''));
  } catch (err) {
    res.status(500).send((err as Error).stack);
  }
}
