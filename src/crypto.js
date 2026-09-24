import { createHash, createHmac, randomBytes, timingSafeEqual, scrypt as scryptCb, createCipheriv, createDecipheriv, hkdfSync } from 'node:crypto';
import { promisify } from 'node:util';
import { config } from './config.js';

const scrypt = promisify(scryptCb);

export const random = (bytes = 32) => randomBytes(bytes).toString('base64url');
export const digest = value => createHash('sha256').update(String(value)).digest();
export const s256 = verifier => createHash('sha256').update(verifier).digest('base64url');

export function equal(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

// ---------- passwords ----------
// scrypt at OWASP's N=2^15 r=8 p=3 (~32 MiB each). Parameters ride along in
// the hash so they can be raised later without breaking old ones.
const SCRYPT = { N: 2 ** 15, r: 8, p: 3 };

export async function hashPassword(password) {
  const salt = randomBytes(16);
  const key = await scrypt(password.normalize('NFKC'), salt, 32, { ...SCRYPT, maxmem: 64 * 1024 * 1024 });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64url')}$${key.toString('base64url')}`;
}

// A real-looking hash to burn time against when the account doesn't exist,
// so response timing doesn't reveal which emails are registered.
let decoy = null;
export async function verifyPassword(password, stored) {
  decoy ||= await hashPassword(random());
  const [scheme, N, r, p, salt, key] = (stored || decoy).split('$');
  if (scheme !== 'scrypt') return false;
  const expected = Buffer.from(key, 'base64url');
  const actual = await scrypt(String(password).normalize('NFKC'), Buffer.from(salt, 'base64url'), expected.length, { N: Number(N), r: Number(r), p: Number(p), maxmem: 256 * 1024 * 1024 });
  return Boolean(stored) && timingSafeEqual(expected, actual);
}

// ---------- data at rest (TOTP secrets) ----------
const dataKey = () => Buffer.from(config.encryptionKey, 'base64');

export function encrypt(plaintext, context) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', dataKey(), iv);
  cipher.setAAD(Buffer.from(context));
  const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return ['v1', iv, cipher.getAuthTag(), body].map(v => (typeof v === 'string' ? v : v.toString('base64url'))).join('.');
}

export function decrypt(sealed, context) {
  const [version, iv, tag, body] = String(sealed).split('.');
  if (version !== 'v1') throw new Error('unknown ciphertext version');
  const decipher = createDecipheriv('aes-256-gcm', dataKey(), Buffer.from(iv, 'base64url'));
  decipher.setAAD(Buffer.from(context));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(body, 'base64url')), decipher.final()]).toString('utf8');
}

// ---------- signed cookies ----------
// Short-lived, purpose-bound HMAC envelopes for state that has to survive a
// redirect: OAuth state, a half-finished 2FA sign-in, the CSRF secret.
const macKey = () => hkdfSync('sha256', config.secret, 'ward', 'cookie-mac-v1', 32);
const mac = (purpose, body) => createHmac('sha256', Buffer.from(macKey())).update(`${purpose}.${body}`).digest('base64url');

export function seal(purpose, payload, ttlSeconds) {
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + ttlSeconds * 1000 })).toString('base64url');
  return `${body}.${mac(purpose, body)}`;
}

export function unseal(purpose, value) {
  if (typeof value !== 'string' || value.length > 4096) return null;
  const [body, tag, extra] = value.split('.');
  if (!body || !tag || extra !== undefined || !equal(tag, mac(purpose, body))) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    return typeof payload.exp === 'number' && payload.exp > Date.now() ? payload : null;
  } catch {
    return null;
  }
}

export const hmac = (purpose, value) => createHmac('sha256', Buffer.from(macKey())).update(`${purpose}.${value}`).digest('base64url');
