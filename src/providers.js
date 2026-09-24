import { config } from './config.js';

// Upstream sign-in providers. Each one turns an authorization code into the
// same shape: { subject, email (only if the provider says it's verified),
// handle, name, avatar }. Unverified emails are dropped here so nothing
// downstream can be tricked into matching on them.
async function json(url, options = {}) {
  const response = await fetch(url, { ...options, redirect: 'error', signal: AbortSignal.timeout(10_000) });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`${new URL(url).host} responded ${response.status}`);
  return body;
}

const form = body => ({ method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: new URLSearchParams(body) });
const clean = (value, max = 100) => (typeof value === 'string' && value.trim() ? value.trim().slice(0, max) : null);
const cleanEmail = value => (typeof value === 'string' && value.length <= 254 && /^[^@\s]+@[^@\s]+$/.test(value) ? value.toLowerCase() : null);

export const PROVIDER_CONFIG = {
  google: {
    authorize: 'https://accounts.google.com/o/oauth2/v2/auth',
    scope: 'openid email profile',
    extra: { prompt: 'select_account' },
    async profile(code, verifier, redirectUri) {
      const { id, secret } = config.providers.google;
      const token = await json('https://oauth2.googleapis.com/token', form({ client_id: id, client_secret: secret, grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: redirectUri }));
      // Straight from Google over TLS with a token we just exchanged server-side,
      // so the claims are trusted without verifying the ID token signature.
      const p = await json('https://openidconnect.googleapis.com/v1/userinfo', { headers: { Authorization: `Bearer ${token.access_token}` } });
      return { subject: String(p.sub), email: p.email_verified === true ? cleanEmail(p.email) : null, handle: null, name: clean(p.name), avatar: clean(p.picture, 500) };
    },
  },
  github: {
    authorize: 'https://github.com/login/oauth/authorize',
    scope: 'read:user user:email',
    extra: { allow_signup: 'true' },
    async profile(code, verifier, redirectUri) {
      const { id, secret } = config.providers.github;
      const token = await json('https://github.com/login/oauth/access_token', form({ client_id: id, client_secret: secret, code, code_verifier: verifier, redirect_uri: redirectUri }));
      if (!token.access_token) throw new Error(`github: ${token.error || 'no token'}`);
      const headers = { Authorization: `Bearer ${token.access_token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'DeltaVDevs-Ward' };
      const [p, emails] = await Promise.all([json('https://api.github.com/user', { headers }), json('https://api.github.com/user/emails', { headers }).catch(() => [])]);
      const primary = Array.isArray(emails) ? emails.find(e => e.primary && e.verified) : null;
      return { subject: String(p.id), email: cleanEmail(primary?.email), handle: clean(p.login, 40), name: clean(p.name) || clean(p.login), avatar: clean(p.avatar_url, 500) };
    },
  },
  discord: {
    authorize: 'https://discord.com/oauth2/authorize',
    scope: 'identify email',
    extra: { prompt: 'consent' },
    async profile(code, verifier, redirectUri) {
      const { id, secret } = config.providers.discord;
      const token = await json('https://discord.com/api/oauth2/token', form({ client_id: id, client_secret: secret, grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: redirectUri }));
      const p = await json('https://discord.com/api/users/@me', { headers: { Authorization: `Bearer ${token.access_token}` } });
      const avatar = p.avatar && /^[\w]+$/.test(p.avatar) ? `https://cdn.discordapp.com/avatars/${p.id}/${p.avatar}.png?size=256` : null;
      return { subject: String(p.id), email: p.verified === true ? cleanEmail(p.email) : null, handle: clean(p.username, 40), name: clean(p.global_name) || clean(p.username), avatar };
    },
  },
};

export const enabledProviders = () => Object.keys(PROVIDER_CONFIG).filter(p => config.providers[p]);
export const callbackUrl = provider => `${config.publicUrl}/auth/${provider}/callback`;
