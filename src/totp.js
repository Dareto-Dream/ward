import { createHmac, randomBytes } from 'node:crypto';

// RFC 6238 TOTP (SHA-1, 6 digits, 30s) — what every authenticator app speaks.
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function newSecret() {
  const bytes = randomBytes(20);
  let bits = '', out = '';
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');
  for (let i = 0; i + 5 <= bits.length; i += 5) out += ALPHABET[parseInt(bits.slice(i, i + 5), 2)];
  return out;
}

function decode(secret) {
  let bits = '';
  for (const c of secret.replace(/=+$/, '').toUpperCase()) {
    const v = ALPHABET.indexOf(c);
    if (v < 0) throw new Error('bad base32');
    bits += v.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

export function code(secret, step) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac('sha1', decode(secret)).update(counter).digest();
  const offset = mac[mac.length - 1] & 0xf;
  const n = (mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return String(n).padStart(6, '0');
}

export const currentStep = (now = Date.now()) => Math.floor(now / 30_000);

// Accepts one step of clock drift either way. Returns the matching step so the
// caller can refuse a code that was already used (replay).
export function verify(secret, input, now = Date.now()) {
  const clean = String(input || '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(clean)) return null;
  const step = currentStep(now);
  for (const s of [step - 1, step, step + 1]) if (code(secret, s) === clean) return s;
  return null;
}

export const uri = (secret, account) =>
  `otpauth://totp/${encodeURIComponent(`Ward:${account}`)}?secret=${secret}&issuer=Ward&algorithm=SHA1&digits=6&period=30`;
