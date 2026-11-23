import type { NextFunction, Request, Response } from 'express';
import { exec } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import axios from 'axios';
import ejs from 'ejs';
import mongoose from 'mongoose';
import { Pool } from 'pg';

/** Synthetic BFF routes next to the SSR server (the showcase is never deployed). */
const pool = new Pool();
const User = mongoose.model('User', new mongoose.Schema({ email: String, password: String }));

// NGB071: every response allows a service worker to control the whole origin.
export function headers(req: Request, res: Response, next: NextFunction): void {
  res.setHeader('Service-Worker-Allowed', '/');
  next();
}

export async function invoices(req: Request, res: Response): Promise<void> {
  // NGB073: request value concatenated into SQL text.
  const rows = await pool.query(`SELECT * FROM invoices WHERE customer = '${req.query['customer']}'`);
  // NGB077: '../' in the route parameter escapes the invoices folder.
  const pdf = readFileSync(path.join(process.cwd(), 'invoices', req.params['file']!));
  res.send({ rows, size: pdf.length });
}

export async function linkPreview(req: Request, res: Response): Promise<void> {
  // NGB076: the client chooses the host the server connects to (SSRF).
  const page = await axios.get(String(req.query['url']));
  // NGB079: request text becomes part of the EJS template source.
  res.send(ejs.render(`<h1>${req.query['title']}</h1>${page.data}`));
}

export function thumbnail(req: Request, res: Response): void {
  // NGB078: shell metacharacters in the file name run commands.
  exec(`convert ${req.body.file} -resize 64x64 thumb.png`, () => res.sendStatus(204));
}

export async function login(req: Request, res: Response): Promise<void> {
  // NGB080: {"password": {"$ne": null}} matches every user.
  const user = await User.findOne({ email: req.body.email, password: req.body.password });
  res.send({ ok: !!user });
}
