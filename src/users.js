import { createHash, randomInt } from 'node:crypto';
import { config } from './config.js';
import { query, one } from './db.js';
import { random, digest } from './crypto.js';

export const USERNAME = /^[a-z0-9_]{3,32}$/;
export const normalizeEmail = value => String(value || '').trim().toLowerCase();
export const validEmail = value => value.length <= 254 && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value);

// Turn whatever the provider gave us into a free, valid username.
export async function freeUsername(db, ...candidates) {
  const base = candidates
    .map(c => String(c || '').toLowerCase().normalize('NFKD').replace(/[^a-z0-9_]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 24))
    .find(c => c.length >= 3) || 'user';
  for (let i = 0; i < 20; i++) {
    const name = i === 0 ? base : `${base.slice(0, 24)}_${Math.floor(Math.random() * 10 ** (2 + Math.min(i, 6)))}`;
    if (USERNAME.test(name) && !(await db.query('SELECT 1 FROM users WHERE username = $1', [name])).rowCount) return name;
  }
  return `user_${random(6).toLowerCase().replace(/[^a-z0-9]/g, '')}`.slice(0, 32).padEnd(8, '0');
}

export const findByEmail = email => one('SELECT * FROM users WHERE email = $1', [email]);
export const findById = id => one('SELECT * FROM users WHERE id = $1', [id]);

// Anything that changes who can get into an account (password reset,
// suspension, deletion) calls this: every session and every token dies.
export async function revokeEverything(db, userId, { keepSessionId = null } = {}) {
  await db.query('DELETE FROM sessions WHERE user_id = $1 AND id IS DISTINCT FROM $2', [userId, keepSessionId]);
  await db.query('UPDATE tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL', [userId]);
}

// How many ways can this person still get in? Used to refuse removing the last one.
export async function signInMethods(userId) {
  const row = await one(`SELECT (u.password_hash IS NOT NULL AND u.email IS NOT NULL)::int
    + (SELECT count(*) FROM identities i WHERE i.user_id = u.id)::int AS n FROM users u WHERE u.id = $1`, [userId]);
  return row?.n ?? 0;
}

// ---------- password policy ----------
// Length over composition rules (NIST 800-63B), plus a breach-corpus check.
export async function passwordProblem(password, { email, username } = {}) {
  if (typeof password !== 'string' || password.length < 10) return 'Use at least 10 characters.';
  if (password.length > 200) return 'That password is too long (200 characters max).';
  const lower = password.toLowerCase();
  if ((email && lower.includes(email.split('@')[0])) || (username && lower.includes(username))) return "Don't put your email or username in your password.";
  if (/^(.)\1+$/.test(password)) return 'Pick something less repetitive.';
  if (config.breachCheck && (await breached(password))) return 'That password has shown up in a data breach. Pick a different one.';
  return null;
}

// HIBP range API: only the first 5 hex chars of the SHA-1 leave the server.
// Fails open — if HIBP is down we don't lock people out of signing up.
async function breached(password) {
  const hash = createHash('sha1').update(password).digest('hex').toUpperCase();
  try {
    const response = await fetch(`https://api.pwnedpasswords.com/range/${hash.slice(0, 5)}`, { headers: { 'Add-Padding': 'true', 'User-Agent': 'DeltaVDevs-Ward' }, signal: AbortSignal.timeout(3000) });
    if (!response.ok) return false;
    const body = await response.text();
    return body.split('\n').some(line => { const [suffix, count] = line.trim().split(':'); return suffix === hash.slice(5) && Number(count) > 0; });
  } catch {
    return false;
  }
}

// ---------- recovery codes ----------
const CODE_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';

export async function newRecoveryCodes(db, userId) {
  // 10 chars from an unambiguous alphabet (~49 bits each), shown as xxxxx-xxxxx.
  const pick = () => Array.from({ length: 10 }, () => CODE_ALPHABET[randomInt(CODE_ALPHABET.length)]).join('');
  const codes = Array.from({ length: 10 }, () => pick().replace(/(.{5})/, '$1-'));
  await db.query('DELETE FROM recovery_codes WHERE user_id = $1', [userId]);
  for (const code of codes) await db.query('INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)', [userId, digest(code)]);
  return codes;
}

export async function useRecoveryCode(userId, input) {
  const code = String(input || '').trim().toLowerCase();
  if (!/^[a-z0-9]{5}-[a-z0-9]{5}$/.test(code)) return false;
  const row = await one('UPDATE recovery_codes SET used_at = now() WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL RETURNING id', [userId, digest(code)]);
  return Boolean(row);
}

export const unusedRecoveryCodes = async userId => Number((await one('SELECT count(*) FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL', [userId])).count);

export const publicProfile = user => ({ id: user.id, username: user.username, display_name: user.display_name, email: user.email, avatar_url: user.avatar_url });

export { query };
