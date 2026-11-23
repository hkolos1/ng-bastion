import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';

const EXPRESS = `import type { Request, Response } from 'express';\n`;

describe('NGB080 NoSQL injection in server code', () => {
  it('reports request body / query values and whole filters in Mongoose / MongoDB queries', async () => {
    const res = await findings('NGB080', {
      'src/server.ts': `${EXPRESS}import mongoose from 'mongoose';
const User = mongoose.model('User', new mongoose.Schema({}));
export async function h(req: Request, res: Response, users: import('mongodb').Collection) {
  await User.findOne({ email: req.body.email, password: req.body.password });
  await users.find(req.query);
  await User.find({ $where: \`this.name == '\${req.query.name}'\` });
}`,
    });
    expect(res).toHaveLength(3);
    expect(res.find((r) => r.message.includes('$where'))!.severity).toBe('critical');
  });

  it('safe: String() / template / $eq / route params / sanitizers', async () => {
    expect(await findings('NGB080', {
      'src/server.ts': `${EXPRESS}import mongoose from 'mongoose';
import sanitize from 'mongo-sanitize';
const User = mongoose.model('User', new mongoose.Schema({}));
export async function h(req: Request, res: Response) {
  const email = String(req.body.email);
  await User.findOne({ email });
  await User.findOne({ name: \`\${req.query.name}\` });
  await User.findOne({ email: { $eq: req.body.email } });
  await User.findById(req.params.id);
  await User.findOne({ _id: req.params.id });
  await User.findOne({ token: sanitize(req.body.token) });
}`,
    })).toEqual([]);
  });

  it('safe: express-mongo-sanitize applied globally', async () => {
    expect(await findings('NGB080', {
      'src/server.ts': `${EXPRESS}import express from 'express';
import mongoSanitize from 'express-mongo-sanitize';
import mongoose from 'mongoose';
const app = express();
app.use(mongoSanitize());
const User = mongoose.model('User', new mongoose.Schema({}));
export async function h(req: Request) { await User.findOne({ email: req.body.email }); }`,
    })).toEqual([]);
  });

  it('false-positive regression: Array.find and files without MongoDB', async () => {
    expect(await findings('NGB080', {
      'src/server.ts': `${EXPRESS}const users: { email: string }[] = [];
declare const repo: { findOne(q: object): void };
export function h(req: Request) { users.find((u) => u.email === req.body.email); repo.findOne({ email: req.body.email }); }`,
    })).toEqual([]);
  });
});
