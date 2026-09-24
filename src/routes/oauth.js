import { config } from '../config.js';
import { query, one, transaction, limited } from '../db.js';
import { random, digest, s256, equal } from '../crypto.js';
import { loadSession, endSession, csrfToken, csrfOk } from '../session.js';
import { html, send, csrfField, errorPage } from '../views.js';
import { signJwt, jwks, atHash } from '../keys.js';
import { audit } from '../audit.js';

// Ward as an OAuth 2.0 / OpenID Connect provider for the other DeltaVDevs sites.
//  - authorization code only, PKCE (S256) required for every client
//  - redirect URIs match exactly, never by prefix
//  - codes are single-use; replaying one revokes everything it issued
//  - refresh tokens rotate; replaying an old one revokes the whole family
// What each scope actually hands over, in the words the consent screen uses.
export const SCOPES = {
  openid: 'Know it’s you (your Ward account ID)',
  profile: 'Your username and public profile (display name and picture)',
  email: 'Your email address',
  offline_access: 'Stay connected while you’re away',
  // Read-only: DeltaTime accepts these tokens on its stats API (see resource_scopes).
  deltatime: 'Your DeltaTime statistics and hours (read-only)',
};
const CODE_SECONDS = 120;
const VERIFIER = /^[A-Za-z0-9\-._~]{43,128}$/;
const CHALLENGE = /^[A-Za-z0-9\-_]{43}$/;

const str = (v, max = 2000) => (typeof v === 'string' && v.length <= max ? v : undefined);

// ---------- /authorize validation (shared by GET and the consent POST) ----------
async function validate(params) {
  const clientId = str(params.client_id, 100);
  const client = clientId ? await one('SELECT * FROM clients WHERE id = $1 AND disabled_at IS NULL', [clientId]) : null;
  if (!client) return { page: ['Unknown app', 'The app that sent you here isn’t registered with Ward.'] };
  const redirectUri = str(params.redirect_uri);
  // Until the redirect URI is proven, errors are shown here, never redirected.
  if (!redirectUri || !client.redirect_uris.includes(redirectUri)) return { page: ['Bad redirect', `${client.name} asked to send you somewhere it isn’t allowed to. Nothing was shared.`] };

  const state = str(params.state, 1000);
  const fail = (error, description) => {
    const url = new URL(redirectUri);
    url.searchParams.set('error', error);
    if (description) url.searchParams.set('error_description', description);
    if (state) url.searchParams.set('state', state);
    url.searchParams.set('iss', config.issuer);
    return { redirect: url.toString() };
  };
  if (params.response_type !== 'code') return fail('unsupported_response_type', 'only response_type=code is supported');
  if (params.response_mode && params.response_mode !== 'query') return fail('invalid_request', 'only response_mode=query is supported');
  if (params.request || params.request_uri) return fail('request_not_supported');
  const challenge = str(params.code_challenge, 200);
  if (!challenge || params.code_challenge_method !== 'S256' || !CHALLENGE.test(challenge)) return fail('invalid_request', 'PKCE with code_challenge_method=S256 is required');
  const scopes = [...new Set((str(params.scope, 500) || '').split(' ').filter(Boolean))];
  if (!scopes.length) return fail('invalid_scope', 'scope is required');
  const bad = scopes.find(s => !SCOPES[s] || !client.scopes.includes(s));
  if (bad) return fail('invalid_scope', `scope not allowed: ${bad}`);
  const nonce = str(params.nonce, 500);
  const prompt = (str(params.prompt, 100) || '').split(' ').filter(Boolean);
  const maxAge = params.max_age !== undefined && /^\d{1,9}$/.test(String(params.max_age)) ? Number(params.max_age) : null;
  return { client, redirectUri, state, challenge, scopes, nonce, prompt, maxAge, fail };
}

const AUTHORIZE_PARAMS = ['client_id', 'redirect_uri', 'response_type', 'response_mode', 'scope', 'state', 'code_challenge', 'code_challenge_method', 'nonce', 'prompt', 'max_age'];

function pick(source, drop = []) {
  const out = {};
  for (const k of AUTHORIZE_PARAMS) if (!drop.includes(k) && typeof source[k] === 'string') out[k] = source[k];
  return out;
}

async function issueCode(reply, user, v) {
  const code = random();
  await query(`INSERT INTO auth_codes (code_hash, client_id, user_id, redirect_uri, scopes, code_challenge, nonce, amr, auth_time, expires_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now() + make_interval(secs => $10))`,
    [digest(code), v.client.id, user.id, v.redirectUri, v.scopes, v.challenge, v.nonce ?? null, user.amr, user.auth_time, CODE_SECONDS]);
  const url = new URL(v.redirectUri);
  url.searchParams.set('code', code);
  if (v.state) url.searchParams.set('state', v.state);
  url.searchParams.set('iss', config.issuer); // RFC 9207 mix-up defence
  return reply.redirect(url.toString());
}

function consentPage(request, reply, user, v, raw) {
  const fields = pick(raw);
  const origin = new URL(v.redirectUri).origin;
  const csrf = csrfToken(request, reply);
  // "Not you?" signs out and comes straight back here to pick another account.
  const here = `/oauth/authorize?${new URLSearchParams(pick(raw, ['prompt', 'max_age']))}`;
  return send(reply, 200, {
    title: `Authorize ${v.client.name}`,
    user: { ...user, csrf },
    body: html`<section class="card narrow consent">
      <p class="eyebrow">sign in with ward</p>
      <h1 class="headline"><span class="app-name">${v.client.name}</span> wants to access your Ward account</h1>
      ${v.client.first_party ? html`<p class="caption official">✓ Official DeltaVDevs app</p>` : html`<p class="caption">Only continue if you trust this app.</p>`}
      <div class="who">
        ${user.avatar_url ? html`<img class="who-avatar" src="${user.avatar_url}" alt="" referrerpolicy="no-referrer" />` : html`<span class="who-avatar blank">${user.display_name.slice(0, 1).toUpperCase()}</span>`}
        <div class="who-text"><strong>${user.display_name}</strong><span class="caption">@${user.username}${user.email ? ` · ${user.email}` : ''}</span></div>
        <form method="post" action="/logout" class="who-switch">${csrfField(csrf)}<input type="hidden" name="return_to" value="${here}" /><button class="linkish" type="submit">Not you?</button></form>
      </div>
      <div>
        <p class="caption">${v.client.name} will be able to see:</p>
        <ul class="scopes">${v.scopes.map(s => html`<li>${SCOPES[s]}</li>`)}</ul>
        <p class="caption">It won’t get your password, your 2FA, or your other connected apps.</p>
      </div>
      <form method="post" action="/oauth/authorize" class="consent-actions">
        ${csrfField(csrf)}
        ${Object.entries(fields).map(([k, val]) => html`<input type="hidden" name="${k}" value="${val}" />`)}
        <button class="outline" type="submit" name="decision" value="deny">Take me back</button>
        <button class="cta" type="submit" name="decision" value="allow">Authorize</button>
      </form>
      <p class="caption">You’ll go back to <code>${origin}</code>. ${v.client.name} uses this under its own policies; see <a href="/privacy">Ward’s Privacy Policy</a>. You can disconnect it any time from <a href="/account#apps">your account</a>.</p>
    </section>`,
  });
}

// ---------- tokens ----------
async function mintTokens(db, { client, user, scopes, refreshScopes = scopes, amr, authTime, family, nonce }) {
  const access = `wat_${random()}`;
  const expiresIn = config.accessTokenMinutes * 60;
  await db.query(`INSERT INTO tokens (token_hash, kind, family, client_id, user_id, scopes, amr, auth_time, expires_at)
    VALUES ($1, 'access', $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8))`, [digest(access), family, client.id, user.id, scopes, amr, authTime, expiresIn]);
  const body = { access_token: access, token_type: 'Bearer', expires_in: expiresIn, scope: scopes.join(' ') };
  // A rotated refresh token keeps the original grant's scope (RFC 6749 §6),
  // even when this access token was narrowed.
  if (refreshScopes.includes('offline_access')) {
    const refresh = `wrt_${random()}`;
    await db.query(`INSERT INTO tokens (token_hash, kind, family, client_id, user_id, scopes, amr, auth_time, expires_at)
      VALUES ($1, 'refresh', $2, $3, $4, $5, $6, $7, now() + make_interval(days => $8))`, [digest(refresh), family, client.id, user.id, refreshScopes, amr, authTime, config.refreshTokenDays]);
    body.refresh_token = refresh;
  }
  if (scopes.includes('openid')) {
    const now = Math.floor(Date.now() / 1000);
    body.id_token = signJwt({
      iss: config.issuer, sub: user.id, aud: client.id, azp: client.id, iat: now, exp: now + 3600,
      auth_time: Math.floor(new Date(authTime).getTime() / 1000), amr, at_hash: atHash(access),
      ...(nonce ? { nonce } : {}), ...claims(user, scopes),
    });
  }
  await db.query('UPDATE grants SET last_used_at = now() WHERE user_id = $1 AND client_id = $2', [user.id, client.id]);
  return body;
}

export function claims(user, scopes) {
  const out = { sub: user.id };
  if (scopes.includes('profile')) Object.assign(out, { name: user.display_name, preferred_username: user.username, picture: user.avatar_url || undefined, updated_at: Math.floor(new Date(user.updated_at).getTime() / 1000) });
  if (scopes.includes('email') && user.email) Object.assign(out, { email: user.email, email_verified: true });
  return out;
}

const revokeFamily = (db, family) => db.query('UPDATE tokens SET revoked_at = now() WHERE family = $1 AND revoked_at IS NULL', [family]);

// client_secret_basic, client_secret_post, or none (public client + PKCE).
async function authenticateClient(request) {
  let id, secret;
  const header = request.headers.authorization;
  if (typeof header === 'string' && header.startsWith('Basic ')) {
    const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
    const i = decoded.indexOf(':');
    if (i < 0) return null;
    try { id = decodeURIComponent(decoded.slice(0, i)); secret = decodeURIComponent(decoded.slice(i + 1)); } catch { return null; }
  } else {
    id = str(request.body?.client_id, 100);
    secret = str(request.body?.client_secret, 200);
  }
  if (!id) return null;
  const client = await one('SELECT * FROM clients WHERE id = $1 AND disabled_at IS NULL', [id]);
  if (!client) return null;
  if (client.secret_hash) {
    if (!secret || !equal(digest(secret).toString('base64url'), client.secret_hash.toString('base64url'))) return null;
  } else if (secret) {
    return null; // public clients don't have secrets; one showing up means something's misconfigured
  }
  return client;
}

const tokenError = (reply, status, error, description) => reply.code(status).header('Cache-Control', 'no-store').send({ error, ...(description ? { error_description: description } : {}) });

export async function bearer(request) {
  const header = request.headers.authorization;
  const token = typeof header === 'string' && header.startsWith('Bearer ') ? header.slice(7).trim() : str(request.body?.access_token, 200);
  if (!token || !token.startsWith('wat_')) return null;
  return one(`SELECT t.*, row_to_json(u.*) AS user FROM tokens t JOIN users u ON u.id = t.user_id
    WHERE t.token_hash = $1 AND t.kind = 'access' AND t.revoked_at IS NULL AND t.expires_at > now() AND u.suspended_at IS NULL`, [digest(token)]);
}

const cors = reply => reply.header('Access-Control-Allow-Origin', '*').header('Access-Control-Allow-Headers', 'Authorization, Content-Type').header('Access-Control-Allow-Methods', 'GET, POST');

export async function oauthRoutes(app) {
  app.get('/.well-known/openid-configuration', async (_request, reply) => {
    cors(reply).header('Cache-Control', 'public, max-age=3600');
    const base = config.issuer;
    return {
      issuer: base,
      authorization_endpoint: `${base}/oauth/authorize`,
      token_endpoint: `${base}/oauth/token`,
      userinfo_endpoint: `${base}/oauth/userinfo`,
      revocation_endpoint: `${base}/oauth/revoke`,
      introspection_endpoint: `${base}/oauth/introspect`,
      end_session_endpoint: `${base}/oauth/logout`,
      jwks_uri: `${base}/.well-known/jwks.json`,
      scopes_supported: Object.keys(SCOPES),
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['ES256'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      claims_supported: ['sub', 'name', 'preferred_username', 'picture', 'updated_at', 'email', 'email_verified', 'auth_time', 'amr', 'nonce'],
      authorization_response_iss_parameter_supported: true,
      request_parameter_supported: false,
      request_uri_parameter_supported: false,
    };
  });

  app.get('/.well-known/jwks.json', async (_request, reply) => {
    cors(reply).header('Cache-Control', 'public, max-age=3600');
    return jwks();
  });

  app.get('/oauth/authorize', async (request, reply) => {
    const v = await validate(request.query);
    if (v.page) return errorPage(reply, 400, ...v.page);
    if (v.redirect) return reply.redirect(v.redirect);
    const user = await loadSession(request);
    const here = `/oauth/authorize?${new URLSearchParams(pick(request.query, ['prompt', 'max_age']))}`;
    if (!user) {
      if (v.prompt.includes('none')) return reply.redirect(v.fail('login_required').redirect);
      return reply.redirect(`/login?return_to=${encodeURIComponent(here)}`);
    }
    // prompt=login / max_age: make them sign in again, then come back without the flag.
    const age = (Date.now() - new Date(user.auth_time).getTime()) / 1000;
    if ((v.prompt.includes('login') && age > 60) || (v.maxAge !== null && age > v.maxAge)) {
      if (v.prompt.includes('none')) return reply.redirect(v.fail('login_required').redirect);
      return reply.redirect(`/login?reauth=1&return_to=${encodeURIComponent(here)}`);
    }
    // Never sign someone into an app just because a link was opened: an
    // interactive request always shows the consent screen, first-party or not.
    // The only silent path is prompt=none, and only for scopes the person has
    // already approved for this exact app; it never creates new consent.
    if (v.prompt.includes('none')) {
      const grant = await one('SELECT scopes FROM grants WHERE user_id = $1 AND client_id = $2', [user.id, v.client.id]);
      if (grant && v.scopes.every(s => grant.scopes.includes(s))) return issueCode(reply, user, v);
      return reply.redirect(v.fail('consent_required').redirect);
    }
    return consentPage(request, reply, user, v, request.query);
  });

  app.post('/oauth/authorize', async (request, reply) => {
    const v = await validate(request.body || {});
    if (v.page) return errorPage(reply, 400, ...v.page);
    if (v.redirect) return reply.redirect(v.redirect);
    if (!csrfOk(request)) return errorPage(reply, 403, 'Try again', 'That form expired. Go back to the app and sign in again.');
    const user = await loadSession(request);
    if (!user) return reply.redirect(`/login?return_to=${encodeURIComponent(`/oauth/authorize?${new URLSearchParams(pick(request.body))}`)}`);
    if (request.body.decision !== 'allow') {
      await audit(request, 'oauth.denied', { userId: user.id, clientId: v.client.id, actor: `user:${user.id}` });
      return reply.redirect(v.fail('access_denied', 'the user said no').redirect);
    }
    await query('INSERT INTO grants (user_id, client_id, scopes) VALUES ($1, $2, $3) ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = ARRAY(SELECT DISTINCT unnest(grants.scopes || EXCLUDED.scopes))', [user.id, v.client.id, v.scopes]);
    await audit(request, 'oauth.consent', { userId: user.id, clientId: v.client.id, actor: `user:${user.id}`, scopes: v.scopes });
    return issueCode(reply, user, v);
  });

  app.post('/oauth/token', async (request, reply) => {
    if (await limited(`token:ip:${request.ip}`, 300, 60)) return tokenError(reply, 429, 'slow_down');
    const client = await authenticateClient(request);
    if (!client) {
      if (request.headers.authorization?.startsWith('Basic ')) reply.header('WWW-Authenticate', 'Basic realm="ward"');
      return tokenError(reply, 401, 'invalid_client');
    }
    const body = request.body || {};

    if (body.grant_type === 'authorization_code') {
      const code = str(body.code, 200), verifier = str(body.code_verifier, 200);
      if (!code || !verifier || !VERIFIER.test(verifier)) return tokenError(reply, 400, 'invalid_request', 'code and a valid code_verifier are required');
      const result = await transaction(async db => {
        const row = (await db.query('SELECT * FROM auth_codes WHERE code_hash = $1 FOR UPDATE', [digest(code)])).rows[0];
        if (!row || row.client_id !== client.id) return { error: 'invalid_grant' };
        if (row.used_at) { await revokeFamily(db, row.family); return { error: 'invalid_grant', replay: row }; }
        await db.query('UPDATE auth_codes SET used_at = now() WHERE code_hash = $1', [digest(code)]);
        if (new Date(row.expires_at) < new Date()) return { error: 'invalid_grant' };
        if (row.redirect_uri !== body.redirect_uri) return { error: 'invalid_grant', description: 'redirect_uri mismatch' };
        if (!equal(s256(verifier), row.code_challenge)) return { error: 'invalid_grant', description: 'PKCE verification failed' };
        const user = (await db.query('SELECT * FROM users WHERE id = $1 AND suspended_at IS NULL', [row.user_id])).rows[0];
        if (!user) return { error: 'invalid_grant' };
        return { tokens: await mintTokens(db, { client, user, scopes: row.scopes, amr: row.amr, authTime: row.auth_time, family: row.family, nonce: row.nonce }), user };
      });
      if (result.replay) await audit(request, 'oauth.code_replay', { userId: result.replay.user_id, clientId: client.id, actor: `client:${client.id}` });
      if (result.error) return tokenError(reply, 400, result.error, result.description);
      reply.header('Cache-Control', 'no-store').header('Pragma', 'no-cache');
      return result.tokens;
    }

    if (body.grant_type === 'refresh_token') {
      const token = str(body.refresh_token, 200);
      if (!token || !token.startsWith('wrt_')) return tokenError(reply, 400, 'invalid_grant');
      const requested = str(body.scope, 500)?.split(' ').filter(Boolean);
      const result = await transaction(async db => {
        const row = (await db.query("SELECT * FROM tokens WHERE token_hash = $1 AND kind = 'refresh' FOR UPDATE", [digest(token)])).rows[0];
        if (!row || row.client_id !== client.id) return { error: 'invalid_grant' };
        if (row.used_at || row.revoked_at) {
          // A rotated-out token came back. Someone has a copy: burn the family.
          if (row.used_at && !row.revoked_at) { await revokeFamily(db, row.family); return { error: 'invalid_grant', replay: row }; }
          return { error: 'invalid_grant' };
        }
        if (new Date(row.expires_at) < new Date()) return { error: 'invalid_grant' };
        const scopes = requested?.length ? requested : row.scopes;
        if (!scopes.every(s => row.scopes.includes(s))) return { error: 'invalid_scope' };
        const user = (await db.query('SELECT * FROM users WHERE id = $1 AND suspended_at IS NULL', [row.user_id])).rows[0];
        if (!user) return { error: 'invalid_grant' };
        await db.query('UPDATE tokens SET used_at = now() WHERE token_hash = $1', [row.token_hash]);
        return { tokens: await mintTokens(db, { client, user, scopes, refreshScopes: row.scopes, amr: row.amr, authTime: row.auth_time, family: row.family }) };
      });
      if (result.replay) await audit(request, 'oauth.refresh_replay', { userId: result.replay.user_id, clientId: client.id, actor: `client:${client.id}` });
      if (result.error) return tokenError(reply, 400, result.error);
      reply.header('Cache-Control', 'no-store').header('Pragma', 'no-cache');
      return result.tokens;
    }

    return tokenError(reply, 400, 'unsupported_grant_type');
  });

  const userinfo = async (request, reply) => {
    cors(reply).header('Cache-Control', 'no-store');
    const row = await bearer(request);
    if (!row) return reply.code(401).header('WWW-Authenticate', 'Bearer error="invalid_token"').send({ error: 'invalid_token' });
    return claims(row.user, row.scopes);
  };
  app.get('/oauth/userinfo', userinfo);
  app.post('/oauth/userinfo', userinfo);
  app.options('/oauth/userinfo', async (_request, reply) => cors(reply).code(204).send());

  // RFC 7009. Always 200 so it can't be used to probe tokens.
  app.post('/oauth/revoke', async (request, reply) => {
    const client = await authenticateClient(request);
    if (!client) return tokenError(reply, 401, 'invalid_client');
    const token = str(request.body?.token, 200);
    if (token) {
      const row = await one('SELECT * FROM tokens WHERE token_hash = $1', [digest(token)]);
      if (row && row.client_id === client.id) {
        if (row.kind === 'refresh') await revokeFamily({ query }, row.family);
        else await query('UPDATE tokens SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL', [row.token_hash]);
      }
    }
    return reply.code(200).header('Cache-Control', 'no-store').send({});
  });

  // RFC 7662, confidential clients only, and only for their own tokens.
  app.post('/oauth/introspect', async (request, reply) => {
    const client = await authenticateClient(request);
    if (!client || !client.secret_hash) return tokenError(reply, 401, 'invalid_client');
    reply.header('Cache-Control', 'no-store');
    const token = str(request.body?.token, 200);
    const row = token ? await one(`SELECT t.*, u.username FROM tokens t JOIN users u ON u.id = t.user_id
      WHERE t.token_hash = $1 AND t.revoked_at IS NULL AND t.expires_at > now() AND u.suspended_at IS NULL
        AND (t.kind = 'access' OR t.used_at IS NULL)`, [digest(token)]) : null;
    if (!row) return { active: false };
    // Your own tokens, or — for a resource server like DeltaTime — another
    // app's *access* token, seen only through the scopes you're responsible for.
    const own = row.client_id === client.id;
    const served = row.kind === 'access' ? (client.resource_scopes || []).filter(s => row.scopes.includes(s)) : [];
    if (!own && !served.length) return { active: false };
    return {
      active: true, scope: (own ? row.scopes : served).join(' '), client_id: row.client_id, sub: row.user_id, username: row.username,
      token_type: row.kind === 'access' ? 'Bearer' : 'refresh_token', iss: config.issuer,
      iat: Math.floor(new Date(row.created_at).getTime() / 1000), exp: Math.floor(new Date(row.expires_at).getTime() / 1000),
    };
  });

  // RP-initiated logout. A client can only bounce the user back to a
  // post_logout_redirect_uri it registered.
  async function logoutTarget(params) {
    const clientId = str(params.client_id, 100), target = str(params.post_logout_redirect_uri);
    if (!clientId || !target) return null;
    const client = await one('SELECT post_logout_redirect_uris FROM clients WHERE id = $1 AND disabled_at IS NULL', [clientId]);
    if (!client?.post_logout_redirect_uris.includes(target)) return null;
    const url = new URL(target);
    const state = str(params.state, 1000);
    if (state) url.searchParams.set('state', state);
    return url.toString();
  }

  app.get('/oauth/logout', async (request, reply) => {
    const target = await logoutTarget(request.query);
    const user = await loadSession(request);
    if (!user) return reply.redirect(target || '/login?notice=signed_out');
    const keep = ['client_id', 'post_logout_redirect_uri', 'state'].filter(k => typeof request.query[k] === 'string');
    return send(reply, 200, {
      title: 'Sign out',
      user: { ...user, csrf: csrfToken(request, reply) },
      body: html`<section class="card narrow"><p class="eyebrow">ward</p><h1 class="headline">Sign out of Ward?</h1>
        <p>You’re signed in as <strong>${user.display_name}</strong>. This signs you out of Ward on this browser.</p>
        <form method="post" action="/oauth/logout" class="row end">${csrfField(csrfToken(request, reply))}
          ${keep.map(k => html`<input type="hidden" name="${k}" value="${request.query[k]}" />`)}
          <button class="cta" type="submit">Sign out</button></form></section>`,
    });
  });

  app.post('/oauth/logout', async (request, reply) => {
    const target = await logoutTarget(request.body || {});
    if (!csrfOk(request)) return reply.redirect('/account');
    const user = await loadSession(request);
    await endSession(request, reply);
    if (user) await audit(request, 'logout', { userId: user.id, actor: `user:${user.id}`, via: 'oidc' });
    return reply.redirect(target || '/login?notice=signed_out');
  });
}
