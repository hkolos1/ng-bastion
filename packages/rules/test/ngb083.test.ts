import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

describe('NGB083 cross-site WebSocket hijacking', () => {
  it('reports ws servers that authenticate by cookie without verifyClient / origin checks', async () => {
    const res = await findings('NGB083', {
      'src/server/ws.ts': `import { WebSocketServer } from 'ws';
import * as cookie from 'cookie';
declare const sessions: Map<string, string>;
declare const server: unknown;
const wss = new WebSocketServer({ server: server as never });
wss.on('connection', (ws: { on(e: string, f: (m: unknown) => void): void }, req: { headers: Record<string, string> }) => {
  const user = sessions.get(cookie.parse(req.headers.cookie ?? '').sid!);
  ws.on('message', (m) => console.log(user, m));
});`,
    });
    expect(res).toHaveLength(1);
    expect(res[0]!.confidence).toBe('high');
  });

  it('reports Socket.IO with permissive credentialed CORS and session middleware without allowRequest', async () => {
    const res = await findings('NGB083', {
      'src/server/io.ts': `import { Server } from 'socket.io';
declare const httpServer: unknown;
declare const sessionMiddleware: (req: unknown, res: unknown, next: () => void) => void;
export const io = new Server(httpServer as never, { cors: { origin: true, credentials: true } });
const chat = new Server(httpServer as never);
chat.engine.use(sessionMiddleware);`,
    });
    expect(res).toHaveLength(2);
  });

  it('safe: verifyClient, allowRequest, origin check, token auth', async () => {
    expect(await findings('NGB083', {
      'src/server/ws.ts': `import { WebSocketServer } from 'ws';
import { Server } from 'socket.io';
declare const server: unknown;
const ALLOWED = ['https://app.example.com'];
const a = new WebSocketServer({ server: server as never, verifyClient: (i: { origin: string }) => ALLOWED.includes(i.origin) });
a.on('connection', (ws: unknown, req: { headers: Record<string, string> }) => console.log(req.headers.cookie));
const b = new WebSocketServer({ noServer: true });
b.on('connection', (ws: unknown, req: { headers: Record<string, string> }) => {
  if (!ALLOWED.includes(req.headers.origin!)) return;
  console.log(req.headers.cookie);
});
const c = new WebSocketServer({ port: 8080 });
c.on('connection', (ws: { on(e: string, f: (m: string) => void): void }) => ws.on('message', (m) => verifyToken(JSON.parse(m).token)));
declare function verifyToken(t: string): void;
const io = new Server(server as never, { allowRequest: (req: { headers: { origin?: string } }, cb: (e: null, ok: boolean) => void) => cb(null, ALLOWED.includes(req.headers.origin!)) });
io.use((socket: { request: { headers: { cookie?: string } } }, next: () => void) => { console.log(socket.request.headers.cookie); next(); });`,
    })).toEqual([]);
  });

  it('false-positive regression: browser WebSocket clients and project classes named Server', async () => {
    expect(await findings('NGB083', {
      'src/app/live.ts': `class Server { on(e: string, f: (req: { headers: { cookie: string } }) => void) { return [e, f]; } }
const s = new Server();
s.on('connection', (req) => console.log(req.headers.cookie));
export const ws = new WebSocket('wss://example.com/live');`,
    })).toEqual([]);
  });
});
