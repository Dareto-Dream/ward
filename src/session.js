import { config } from './config.js';
import { query, one } from './db.js';
import { random, digest, hmac, equal, seal, unseal } from './crypto.js';

// Browser sessions live in Postgres (not in the cookie) so they can be listed,
// revoked one at a time, or wiped by Telescreen. The cookie is a random token;
// the database only has its sha256.
//
// SameSite=Lax on purpose: a client site sends the browser here with a
// top-level GET to /oauth/authorize and the session has to come along.
const host = name => (config.production ? `__Host-${name}` : name);
export const SESSION_COOKIE = host('ward');
export const BROWSER_COOKIE = host('ward-b');
export const cookieOptions = { httpOnly: true, secure: config.production, sameSite: 'lax', path: '/' };

const SENSITIVE_MINUTES = 15;

export async function createSession(request, reply, userId, amr) {
  const token = random();
  const row = await one(`INSERT INTO sessions (token_hash, user_id, amr, expires_at, ip, user_agent)
    VALUES ($1, $2, $3, now() + make_interval(days => $4), $5, $6) RETURNING id`,
    [digest(token), userId, amr, config.sessionDays, request.ip, String(request.headers['user-agent'] || '').slice(0, 300)]);
  await query('UPDATE users SET last_login_at = now() WHERE id = $1', [userId]);
  // Replacing the cookie also retires any session this browser had before.
  const old = request.cookies[SESSION_COOKIE];
  if (old) await query('DELETE FROM sessions WHERE token_hash = $1', [digest(old)]);
  reply.setCookie(SESSION_COOKIE, token, { ...cookieOptions, maxAge: config.sessionDays * 86400 });
  return row.id;
}

export async function loadSession(request) {
  const token = request.cookies[SESSION_COOKIE];
  if (typeof token !== 'string' || token.length > 100) return null;
  const row = await one(`SELECT s.id AS session_id, s.amr, s.auth_time, s.last_seen_at, u.*
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = $1 AND s.expires_at > now() AND u.suspended_at IS NULL`, [digest(token)]);
  if (!row) return null;
  if (Date.now() - new Date(row.last_seen_at).getTime() > 5 * 60_000) {
    await query('UPDATE sessions SET last_seen_at = now(), ip = $2 WHERE id = $1', [row.session_id, request.ip]);
  }
  return row;
}

export async function endSession(request, reply) {
  const token = request.cookies[SESSION_COOKIE];
  if (token) await query('DELETE FROM sessions WHERE token_hash = $1', [digest(token)]);
  reply.clearCookie(SESSION_COOKIE, cookieOptions);
}

export const recentlyAuthenticated = user => Date.now() - new Date(user.auth_time).getTime() < SENSITIVE_MINUTES * 60_000;

// ---------- CSRF ----------
// Every form carries a token bound to a per-browser random cookie. On top of
// that, POSTs must come from our own origin (Origin / Sec-Fetch-Site).
export function browserId(request, reply) {
  let id = request.cookies[BROWSER_COOKIE];
  if (typeof id !== 'string' || !/^[\w-]{43}$/.test(id)) {
    id = random();
    reply.setCookie(BROWSER_COOKIE, id, { ...cookieOptions, maxAge: 365 * 86400 });
    request.cookies[BROWSER_COOKIE] = id;
  }
  return id;
}

export const csrfToken = (request, reply) => hmac('csrf', browserId(request, reply));

export function sameOrigin(request) {
  const site = request.headers['sec-fetch-site'];
  if (site && site !== 'same-origin' && site !== 'none') return false;
  const origin = request.headers.origin;
  return !origin || origin === config.origin;
}

export function csrfOk(request) {
  const id = request.cookies[BROWSER_COOKIE];
  const sent = request.body?._csrf;
  return sameOrigin(request) && typeof id === 'string' && equal(sent, hmac('csrf', id));
}

// ---------- return_to ----------
// Only ever bounce back to a path on Ward itself — never an absolute URL.
export function safeReturn(value, fallback = '/account') {
  if (typeof value !== 'string' || value.length > 4000) return fallback;
  if (!value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\') || /[\r\n\t]/.test(value)) return fallback;
  return value;
}

// ---------- flash ----------
// One-shot message carried across a redirect in a signed cookie, so pages
// never render text taken from the URL.
const FLASH_COOKIE = host('ward-flash');
export const flash = (reply, message, kind = 'ok') => reply.setCookie(FLASH_COOKIE, seal('flash', { message, kind }, 60), { ...cookieOptions, maxAge: 60 });
export function takeFlash(request, reply) {
  const value = unseal('flash', request.cookies[FLASH_COOKIE]);
  if (request.cookies[FLASH_COOKIE]) reply.clearCookie(FLASH_COOKIE, cookieOptions);
  return value;
}
