// Boots Ward in-process against TEST_PG_URL with throwaway keys, and gives
// tests a tiny browser (cookie jar + CSRF scraping) on top of app.inject.
import { generateKeyPairSync, randomBytes, createHash } from 'node:crypto';
import { Writable } from 'node:stream';

export const enabled = Boolean(process.env.TEST_PG_URL);

const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
Object.assign(process.env, {
  NODE_ENV: 'test',
  PUBLIC_URL: 'http://localhost:3000',
  DATABASE_URL: process.env.TEST_PG_URL || 'postgres://unused',
  WARD_SECRET: randomBytes(48).toString('base64url'),
  WARD_ENCRYPTION_KEY: randomBytes(32).toString('base64'),
  WARD_SIGNING_KEY: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  WARD_ADMIN_KEY: randomBytes(32).toString('base64url'),
  PASSWORD_BREACH_CHECK: 'off',
  GOOGLE_CLIENT_ID: 'g-id', GOOGLE_CLIENT_SECRET: 'g-secret',
});

export const ADMIN = { authorization: `Bearer ${process.env.WARD_ADMIN_KEY}`, 'x-ward-actor': 'test@deltavdevs.com' };
export const mail = [];

export async function start() {
  const { buildApp } = await import('../src/server.js');
  const { migrate, pool } = await import('../src/db.js');
  await migrate();
  await pool.query('TRUNCATE users, clients, sessions, email_tokens, rate_limits, audit_log, tokens, auth_codes, grants, identities, recovery_codes CASCADE');
  // Dev mode (no RESEND_API_KEY) logs mail instead of sending; catch it here.
  const stream = new Writable({ write(chunk, _enc, done) { for (const line of String(chunk).split('\n')) { try { const m = JSON.parse(line).mail; if (m) mail.push(m); } catch {} } done(); } });
  const app = await buildApp({ logger: { level: 'info', stream } });
  await app.ready();
  return { app, pool };
}

export const lastLink = to => {
  const m = [...mail].reverse().find(x => x.to === to);
  return m && m.text.match(/http:\/\/localhost:3000(\/\S+)/)[1];
};

export class Browser {
  constructor(app) { this.app = app; this.jar = new Map(); }
  store(res) {
    for (const c of [res.headers['set-cookie'] || []].flat()) {
      const [pair, ...attrs] = c.split(';');
      const [name, ...v] = pair.split('=');
      const value = v.join('=');
      if (!value || attrs.some(a => /max-age=0\b/i.test(a.trim())) || attrs.some(a => /expires=Thu, 01 Jan 1970/i.test(a))) this.jar.delete(name.trim());
      else this.jar.set(name.trim(), value);
    }
  }
  get cookie() { return [...this.jar].map(([k, v]) => `${k}=${v}`).join('; '); }
  async get(url, headers = {}) {
    const res = await this.app.inject({ method: 'GET', url, headers: { cookie: this.cookie, ...headers } });
    this.store(res);
    return res;
  }
  async post(url, form = {}, headers = {}) {
    const res = await this.app.inject({ method: 'POST', url, payload: new URLSearchParams(form).toString(), headers: { cookie: this.cookie, 'content-type': 'application/x-www-form-urlencoded', origin: 'http://localhost:3000', ...headers } });
    this.store(res);
    return res;
  }
  // Read the CSRF token off a page, the way a real form would carry it.
  async csrf(url = '/login') {
    const res = await this.get(url);
    return res.body.match(/name="_csrf" value="([^"]+)"/)[1];
  }
}

export const pkce = () => {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
};

export const form = (payload, headers = {}) => ({ payload: new URLSearchParams(payload).toString(), headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers } });
