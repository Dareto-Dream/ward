import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, verify } from 'node:crypto';
import { enabled, start, Browser, ADMIN, mail, lastLink, pkce, form } from './harness.js';

const skip = enabled ? false : 'set TEST_PG_URL to run';
let app, pool;
before(async () => { if (enabled) ({ app, pool } = await start()); });
after(async () => { if (app) await app.close(); });

const PASSWORD = 'correct horse battery staple';
const { POLICY_VERSION: POLICY } = enabled ? await import('../src/legal.js') : {};

async function register(email, name = 'Test Person') {
  const b = new Browser(app);
  const csrf = await b.csrf('/register');
  const res = await b.post('/register', { _csrf: csrf, email, display_name: name, password: PASSWORD, accept_policies: POLICY });
  assert.equal(res.statusCode, 200);
  const link = lastLink(email);
  assert.match(link, /^\/verify\?token=/);
  // GET only shows a button; the POST is what uses the token.
  const page = await b.get(link);
  const token = page.body.match(/name="token" value="([^"]+)"/)[1];
  const done = await b.post('/verify', { _csrf: await b.csrf('/login?reauth=1'), token });
  assert.equal(done.statusCode, 302);
  assert.equal(done.headers.location, '/account');
  return b;
}

async function login(email, password = PASSWORD) {
  const b = new Browser(app);
  const res = await b.post('/login', { _csrf: await b.csrf(), email, password, return_to: '/account' });
  return { b, res };
}

async function makeClient(overrides = {}) {
  const res = await app.inject({ method: 'POST', url: '/admin/v1/clients', headers: ADMIN, payload: {
    name: 'Blog', redirect_uris: ['https://blog.example.com/callback'], post_logout_redirect_uris: ['https://blog.example.com/'], ...overrides,
  } });
  assert.equal(res.statusCode, 201, res.body);
  return res.json();
}

function authorizeUrl(client, extra = {}) {
  const p = pkce();
  const params = new URLSearchParams({ response_type: 'code', client_id: client.id, redirect_uri: 'https://blog.example.com/callback', scope: 'openid profile email offline_access', state: 'st4te', nonce: 'n0nce', code_challenge: p.challenge, code_challenge_method: 'S256', ...extra });
  return { url: `/oauth/authorize?${params}`, verifier: p.verifier };
}

const codeFrom = location => new URL(location).searchParams.get('code');

// Load the consent screen for `url` and press Authorize (or Take me back).
async function decide(b, url, decision = 'allow') {
  const page = await b.get(url);
  assert.equal(page.statusCode, 200, 'every interactive authorize shows the consent screen');
  const form = page.body.slice(page.body.indexOf('action="/oauth/authorize"'));
  const fields = Object.fromEntries([...form.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)"/g)].map(m => [m[1], m[2].replace(/&amp;/g, '&')]));
  return b.post('/oauth/authorize', { ...fields, decision });
}
const approve = async (b, url) => (await decide(b, url)).headers.location;

function verifyJwt(jwt, jwks) {
  const [h, p, s] = jwt.split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url'));
  const key = createPublicKey({ key: jwks.keys.find(k => k.kid === header.kid), format: 'jwk' });
  assert.ok(verify('sha256', Buffer.from(`${h}.${p}`), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(s, 'base64url')), 'signature');
  return JSON.parse(Buffer.from(p, 'base64url'));
}

test('discovery and jwks', { skip }, async () => {
  const d = (await app.inject('/.well-known/openid-configuration')).json();
  assert.equal(d.issuer, 'http://localhost:3000');
  assert.deepEqual(d.code_challenge_methods_supported, ['S256']);
  const k = (await app.inject('/.well-known/jwks.json')).json();
  assert.equal(k.keys[0].alg, 'ES256');
  assert.equal(k.keys[0].d, undefined, 'private key must never be published');
});

test('register, verify, sign out, sign back in', { skip }, async () => {
  const b = await register('alice@example.com', 'Alice');
  const account = await b.get('/account');
  assert.equal(account.statusCode, 200);
  assert.match(account.body, /Alice/);
  assert.match(account.body, /@alice/);

  const out = await b.post('/logout', { _csrf: account.body.match(/name="_csrf" value="([^"]+)"/)[1] });
  assert.equal(out.headers.location, '/login?notice=signed_out');
  assert.equal((await b.get('/account')).statusCode, 302);

  const bad = await login('alice@example.com', 'wrong password here');
  assert.equal(bad.res.statusCode, 401);
  const good = await login('alice@example.com');
  assert.equal(good.res.statusCode, 302);
  assert.equal(good.res.headers.location, '/account');
});

test('registering a taken email reveals nothing and mails the owner', { skip }, async () => {
  const b = new Browser(app);
  const res = await b.post('/register', { _csrf: await b.csrf('/register'), email: 'alice@example.com', display_name: 'Mallory', password: PASSWORD, accept_policies: POLICY });
  assert.equal(res.statusCode, 200);
  assert.match(res.body, /Check your inbox/);
  assert.equal(mail.at(-1).subject, 'You already have a Ward account');
});

test('forms without the CSRF token are refused', { skip }, async () => {
  const b = new Browser(app);
  await b.get('/login');
  const res = await b.post('/login', { email: 'alice@example.com', password: PASSWORD });
  assert.equal(res.statusCode, 403);
  const cross = await b.post('/login', { _csrf: await b.csrf(), email: 'alice@example.com', password: PASSWORD }, { origin: 'https://evil.example' });
  assert.equal(cross.statusCode, 403);
  const opaque = await b.post('/login', { _csrf: await b.csrf(), email: 'alice@example.com', password: PASSWORD }, { origin: 'null' });
  assert.equal(opaque.statusCode, 403, 'an opaque origin is not ours');
  assert.equal((await b.get('/login')).headers['referrer-policy'], 'same-origin', 'no-referrer would make real browsers send Origin: null and fail every form');
});

test('return_to never leaves Ward', { skip }, async () => {
  for (const evil of ['//evil.example', 'https://evil.example', '/\\evil.example']) {
    const b = new Browser(app);
    const res = await b.post('/login', { _csrf: await b.csrf(), email: 'alice@example.com', password: PASSWORD, return_to: evil });
    assert.equal(res.headers.location, '/account', evil);
  }
});

test('full oauth flow: consent, code, pkce, id token, userinfo, refresh rotation', { skip }, async () => {
  const { client, client_secret } = await makeClient();
  const { b } = await login('alice@example.com');
  const { url, verifier } = authorizeUrl(client);

  const allowed = await decide(b, url);
  assert.equal(allowed.statusCode, 302);
  const back = new URL(allowed.headers.location);
  assert.equal(back.origin + back.pathname, 'https://blog.example.com/callback');
  assert.equal(back.searchParams.get('state'), 'st4te');
  assert.equal(back.searchParams.get('iss'), 'http://localhost:3000');
  const code = back.searchParams.get('code');

  const basic = `Basic ${Buffer.from(`${client.id}:${client_secret}`).toString('base64')}`;
  const wrongVerifier = await app.inject({ method: 'POST', url: '/oauth/token', ...form({ grant_type: 'authorization_code', code, redirect_uri: 'https://blog.example.com/callback', code_verifier: pkce().verifier }, { authorization: basic }) });
  assert.equal(wrongVerifier.json().error, 'invalid_grant', 'a bad verifier fails and burns the code');

  // Fresh code, this time done right.
  const second = authorizeUrl(client);
  const code2 = codeFrom(await approve(b, second.url));
  const tokenRes = await app.inject({ method: 'POST', url: '/oauth/token', ...form({ grant_type: 'authorization_code', code: code2, redirect_uri: 'https://blog.example.com/callback', code_verifier: second.verifier }, { authorization: basic }) });
  assert.equal(tokenRes.statusCode, 200, tokenRes.body);
  assert.equal(tokenRes.headers['cache-control'], 'no-store');
  const tokens = tokenRes.json();
  assert.ok(tokens.access_token.startsWith('wat_'));
  assert.ok(tokens.refresh_token.startsWith('wrt_'));

  const jwks = (await app.inject('/.well-known/jwks.json')).json();
  const id = verifyJwt(tokens.id_token, jwks);
  assert.equal(id.iss, 'http://localhost:3000');
  assert.equal(id.aud, client.id);
  assert.equal(id.nonce, 'n0nce');
  assert.equal(id.email, 'alice@example.com');
  assert.deepEqual(id.amr, ['pwd']);

  const me = await app.inject({ url: '/oauth/userinfo', headers: { authorization: `Bearer ${tokens.access_token}` } });
  assert.equal(me.json().preferred_username, 'alice');
  assert.equal(me.json().sub, id.sub);

  // Replaying the code burns everything it issued.
  const replay = await app.inject({ method: 'POST', url: '/oauth/token', ...form({ grant_type: 'authorization_code', code: code2, redirect_uri: 'https://blog.example.com/callback', code_verifier: second.verifier }, { authorization: basic }) });
  assert.equal(replay.json().error, 'invalid_grant');
  assert.equal((await app.inject({ url: '/oauth/userinfo', headers: { authorization: `Bearer ${tokens.access_token}` } })).statusCode, 401);

  // New chain for the refresh test.
  const third = authorizeUrl(client);
  const t = (await app.inject({ method: 'POST', url: '/oauth/token', ...form({ grant_type: 'authorization_code', code: codeFrom(await approve(b, third.url)), redirect_uri: 'https://blog.example.com/callback', code_verifier: third.verifier, client_id: client.id, client_secret }) })).json();
  const r1 = (await app.inject({ method: 'POST', url: '/oauth/token', ...form({ grant_type: 'refresh_token', refresh_token: t.refresh_token }, { authorization: basic }) })).json();
  assert.ok(r1.refresh_token && r1.refresh_token !== t.refresh_token, 'refresh rotates');
  const reuse = await app.inject({ method: 'POST', url: '/oauth/token', ...form({ grant_type: 'refresh_token', refresh_token: t.refresh_token }, { authorization: basic }) });
  assert.equal(reuse.json().error, 'invalid_grant');
  const dead = await app.inject({ method: 'POST', url: '/oauth/token', ...form({ grant_type: 'refresh_token', refresh_token: r1.refresh_token }, { authorization: basic }) });
  assert.equal(dead.json().error, 'invalid_grant', 'reusing an old refresh token kills the whole family');

  const introspect = await app.inject({ method: 'POST', url: '/oauth/introspect', ...form({ token: r1.access_token }, { authorization: basic }) });
  assert.equal(introspect.json().active, false);
});

test('authorize refuses bad redirects and missing pkce', { skip }, async () => {
  const { client } = await makeClient({ name: 'Strict' });
  const { b } = await login('alice@example.com');
  const bad = await b.get(authorizeUrl(client, { redirect_uri: 'https://blog.example.com/callback/../evil' }).url);
  assert.equal(bad.statusCode, 400, 'never redirect to an unregistered uri');
  assert.equal(bad.headers.location, undefined);
  const noPkce = new URLSearchParams({ response_type: 'code', client_id: client.id, redirect_uri: 'https://blog.example.com/callback', scope: 'openid' });
  const res = await b.get(`/oauth/authorize?${noPkce}`);
  assert.equal(new URL(res.headers.location).searchParams.get('error'), 'invalid_request');
  const anon = await new Browser(app).get(authorizeUrl(client, { prompt: 'none' }).url);
  assert.equal(new URL(anon.headers.location).searchParams.get('error'), 'login_required');
});

test('opening an authorize link never signs you in by itself, even for our own apps', { skip }, async () => {
  const { client } = await makeClient({ name: 'SynthCity', first_party: true });
  const { b } = await login('alice@example.com');
  for (let i = 0; i < 2; i++) {
    const page = await b.get(authorizeUrl(client).url);
    assert.equal(page.statusCode, 200, `visit ${i + 1}: consent screen, not a redirect with a code`);
    assert.equal(page.headers.location, undefined);
    assert.match(page.body, /SynthCity<\/span> wants to access your Ward account/);
    assert.match(page.body, /Official DeltaVDevs app/);
    assert.match(page.body, /Your username and public profile/);
    assert.match(page.body, /@alice/, 'shows which account is signed in');
    assert.match(page.body, /Not you\?/);
    assert.match(page.body, />Authorize</);
    assert.match(page.body, />Take me back</);
    if (i === 0) assert.ok(codeFrom(await approve(b, authorizeUrl(client).url)));
  }
  // Silent re-auth only when the app asks for it and the person already said yes.
  assert.ok(codeFrom((await b.get(authorizeUrl(client, { prompt: 'none' }).url)).headers.location));
  const other = (await makeClient({ name: 'Never approved' })).client;
  const silent = await b.get(authorizeUrl(other, { prompt: 'none' }).url);
  assert.equal(new URL(silent.headers.location).searchParams.get('error'), 'consent_required');
  const wrong = await app.inject({ method: 'POST', url: '/oauth/token', ...form({ grant_type: 'authorization_code', code: 'x', code_verifier: pkce().verifier, client_id: client.id, client_secret: 'nope' }) });
  assert.equal(wrong.statusCode, 401);
});

test('two-factor: enroll, required at login, codes cannot be replayed', { skip }, async () => {
  const totp = await import('../src/totp.js');
  const b = await register('bob@example.com', 'Bob');
  const acct = await b.get('/account');
  const csrf = acct.body.match(/name="_csrf" value="([^"]+)"/)[1];
  assert.equal((await b.post('/account/2fa/start', { _csrf: csrf })).headers.location, '/account/2fa');
  const setup = await b.get('/account/2fa');
  const secret = setup.body.match(/class="secret">([^<]+)</)[1].replace(/\s+/g, '');
  const now = Date.now();
  const confirm = await b.post('/account/2fa/confirm', { _csrf: csrf, code: totp.code(secret, totp.currentStep(now)) });
  assert.equal(confirm.statusCode, 200);
  const codes = [...confirm.body.matchAll(/<code>([a-z0-9]{5}-[a-z0-9]{5})<\/code>/g)].map(m => m[1]);
  assert.equal(codes.length, 10);

  const { b: b2, res } = await login('bob@example.com');
  assert.equal(res.headers.location, '/login/2fa');
  assert.equal((await b2.get('/account')).statusCode, 302, 'no session before the second factor');
  const csrf2 = await b2.csrf('/login/2fa');
  // The step used at enrollment is burned; the next one works once.
  const used = await b2.post('/login/2fa', { _csrf: csrf2, code: totp.code(secret, totp.currentStep(now)) });
  assert.equal(used.statusCode, 401);
  const next = totp.code(secret, totp.currentStep(now) + 1);
  assert.equal((await b2.post('/login/2fa', { _csrf: csrf2, code: next })).headers.location, '/account');
  const { b: b3 } = await login('bob@example.com');
  assert.equal((await b3.post('/login/2fa', { _csrf: await b3.csrf('/login/2fa'), code: next })).statusCode, 401, 'replay refused');
  assert.equal((await b3.post('/login/2fa', { _csrf: await b3.csrf('/login/2fa'), recovery: codes[0] })).headers.location, '/account');
  const { b: b4 } = await login('bob@example.com');
  assert.equal((await b4.post('/login/2fa', { _csrf: await b4.csrf('/login/2fa'), recovery: codes[0] })).statusCode, 401, 'recovery codes are single use');
});

test('admin api: auth, search, suspend kills sessions and tokens', { skip }, async () => {
  assert.equal((await app.inject({ url: '/admin/v1/users' })).statusCode, 401);
  assert.equal((await app.inject({ url: '/admin/v1/users', headers: { authorization: 'Bearer nope' } })).statusCode, 401);
  const found = (await app.inject({ url: '/admin/v1/users?q=alice', headers: ADMIN })).json();
  assert.equal(found.total, 1);
  const alice = found.users[0];

  const { client, client_secret } = await makeClient({ name: 'Suspend test', first_party: true });
  const { b } = await login('alice@example.com');
  const flow = authorizeUrl(client);
  const t = (await app.inject({ method: 'POST', url: '/oauth/token', ...form({ grant_type: 'authorization_code', code: codeFrom(await approve(b, flow.url)), redirect_uri: 'https://blog.example.com/callback', code_verifier: flow.verifier, client_id: client.id, client_secret }) })).json();

  const s = await app.inject({ method: 'POST', url: `/admin/v1/users/${alice.id}/suspend`, headers: ADMIN, payload: { reason: 'testing' } });
  assert.equal(s.statusCode, 200);
  assert.equal((await b.get('/account')).statusCode, 302, 'session is gone');
  assert.equal((await app.inject({ url: '/oauth/userinfo', headers: { authorization: `Bearer ${t.access_token}` } })).statusCode, 401, 'token is gone');
  assert.equal((await login('alice@example.com')).res.statusCode, 403, 'suspended users cannot sign in');

  await app.inject({ method: 'POST', url: `/admin/v1/users/${alice.id}/unsuspend`, headers: ADMIN });
  assert.equal((await login('alice@example.com')).res.statusCode, 302);

  const detail = (await app.inject({ url: `/admin/v1/users/${alice.id}`, headers: ADMIN })).json();
  assert.ok(detail.activity.some(a => a.action === 'admin.user_suspended' && a.actor === 'admin:test@deltavdevs.com'));
  assert.equal(detail.user.password_hash, undefined);

  const list = (await app.inject({ url: '/admin/v1/clients', headers: ADMIN })).json();
  assert.ok(list.clients.every(c => c.secret_hash === undefined), 'secret hashes never leave');
});

test('policies: pages exist, sign-up needs agreement, acceptance is recorded', { skip }, async () => {
  for (const path of ['/privacy', '/terms']) {
    const res = await app.inject(path);
    assert.equal(res.statusCode, 200);
    assert.match(res.body, new RegExp(`Version ${POLICY}`));
    assert.match(res.body, /contact@deltavdevs\.com/);
  }
  const b = new Browser(app);
  const res = await b.post('/register', { _csrf: await b.csrf('/register'), email: 'nope@example.com', display_name: 'Nope', password: PASSWORD });
  assert.equal(res.statusCode, 400);
  assert.match(res.body, /Agree to the Terms/);
  const stale = await b.post('/register', { _csrf: await b.csrf('/register'), email: 'nope@example.com', display_name: 'Nope', password: PASSWORD, accept_policies: '2000-01-01' });
  assert.equal(stale.statusCode, 400, 'agreeing to an old version does not count');

  const alice = (await app.inject({ url: '/admin/v1/users?q=alice', headers: ADMIN })).json().users[0];
  assert.equal(alice.terms_version, POLICY);
  assert.ok(alice.policies_accepted_at);
});

test('google sign-up waits for policy agreement, then signs straight in next time', { skip }, async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    const u = String(url);
    if (u === 'https://oauth2.googleapis.com/token') {
      const body = new URLSearchParams(options.body);
      assert.ok(body.get('code_verifier'), 'pkce verifier sent upstream');
      return Response.json({ access_token: 'google-token' });
    }
    if (u === 'https://openidconnect.googleapis.com/v1/userinfo') return Response.json({ sub: 'g-123', email: 'carol@example.com', email_verified: true, name: 'Carol G', picture: 'https://lh3.googleusercontent.com/a/x' });
    return realFetch(url, options);
  };
  try {
    const flow = async b => {
      const start = await b.get('/auth/google/start?return_to=/account');
      const state = new URL(start.headers.location).searchParams.get('state');
      return b.get(`/auth/google/callback?state=${state}&code=abc`);
    };
    const b = new Browser(app);
    const cb = await flow(b);
    assert.equal(cb.headers.location, '/signup');
    assert.equal((await app.inject({ url: '/admin/v1/users?q=carol', headers: ADMIN })).json().total, 0, 'no account before agreeing');
    const page = await b.get('/signup');
    assert.match(page.body, /Carol G/);
    const csrf = page.body.match(/name="_csrf" value="([^"]+)"/)[1];
    assert.equal((await b.post('/signup', { _csrf: csrf })).statusCode, 400);
    const done = await b.post('/signup', { _csrf: csrf, accept_policies: POLICY });
    assert.equal(done.headers.location, '/account');
    const acct = await b.get('/account');
    assert.match(acct.body, /@carol_g/);

    // Second time: known identity, straight in, no signup page.
    const again = await flow(new Browser(app));
    assert.equal(again.headers.location, '/account');

    // A forged callback without the state cookie goes nowhere.
    const forged = await new Browser(app).get('/auth/google/callback?state=x&code=abc');
    assert.equal(forged.statusCode, 400);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('social sign-up never merges into an existing account by email', { skip }, async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    const u = String(url);
    if (u === 'https://oauth2.googleapis.com/token') return Response.json({ access_token: 't' });
    if (u === 'https://openidconnect.googleapis.com/v1/userinfo') return Response.json({ sub: 'g-evil', email: 'alice@example.com', email_verified: true, name: 'Not Alice' });
    return realFetch(url, options);
  };
  try {
    const b = new Browser(app);
    const start = await b.get('/auth/google/start');
    const res = await b.get(`/auth/google/callback?state=${new URL(start.headers.location).searchParams.get('state')}&code=x`);
    assert.equal(res.statusCode, 409);
    assert.match(res.body, /already uses alice@example\.com/);
    assert.equal((await b.get('/account')).statusCode, 302, 'not signed in as alice');
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('consent screen: take me back and not you', { skip }, async () => {
  const { client } = await makeClient({ name: 'Blog again' });
  const { b } = await login('alice@example.com');
  const denied = await decide(b, authorizeUrl(client).url, 'deny');
  const back = new URL(denied.headers.location);
  assert.equal(back.origin + back.pathname, 'https://blog.example.com/callback');
  assert.equal(back.searchParams.get('error'), 'access_denied');
  assert.equal(back.searchParams.get('code'), null);

  // Not you? signs out and comes back to the same authorize request after login.
  const { url } = authorizeUrl(client);
  const page = await b.get(url);
  const csrf = page.body.match(/name="_csrf" value="([^"]+)"/)[1];
  const returnTo = page.body.match(/name="return_to" value="([^"]+)"/)[1].replace(/&amp;/g, '&');
  assert.ok(returnTo.startsWith('/oauth/authorize?'));
  const out = await b.post('/logout', { _csrf: csrf, return_to: returnTo });
  assert.equal(out.headers.location, `/login?return_to=${encodeURIComponent(returnTo)}`);
  assert.equal((await b.get('/account')).statusCode, 302, 'signed out');
  const evil = await b.post('/logout', { _csrf: await b.csrf(), return_to: 'https://evil.example' });
  assert.equal(evil.headers.location, '/login?return_to=%2Faccount', 'return_to stays on Ward');
});
