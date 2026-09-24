import { config, mailEnabled } from '../config.js';
import { query, one, transaction, limited, clearLimit } from '../db.js';
import { random, digest, s256, seal, unseal, hashPassword, verifyPassword, decrypt, equal } from '../crypto.js';
import { createSession, endSession, loadSession, csrfToken, csrfOk, safeReturn, cookieOptions, recentlyAuthenticated, flash } from '../session.js';
import { html, send, notice, csrfField, errorPage, PROVIDERS } from '../views.js';
import { PROVIDER_CONFIG, enabledProviders, callbackUrl } from '../providers.js';
import { normalizeEmail, validEmail, freeUsername, findByEmail, findById, passwordProblem, revokeEverything, useRecoveryCode } from '../users.js';
import { sendMail, templates } from '../mail.js';
import * as totp from '../totp.js';
import { audit } from '../audit.js';

const MFA_COOKIE = config.production ? '__Host-ward-mfa' : 'ward-mfa';
const OAUTH_COOKIE = config.production ? '__Host-ward-oauth' : 'ward-oauth';

const field = (body, name, max = 300) => (typeof body?.[name] === 'string' ? body[name].slice(0, max) : '');

// Fixed messages only — nothing from the query string is echoed back.
const NOTICES = {
  signed_out: 'You are signed out.',
  reset: 'Password changed. Sign in with the new one.',
  deleted: 'Your account has been deleted.',
};

// ---------- pages ----------
function loginPage(request, reply, { error = null, email = '', returnTo = '/account', reauth = false, status = 200 } = {}) {
  const csrf = csrfToken(request, reply);
  const providers = enabledProviders();
  const q = new URLSearchParams({ return_to: returnTo, ...(reauth ? { reauth: '1' } : {}) });
  const info = NOTICES[request.query?.notice];
  return send(reply, status, {
    title: reauth ? 'Confirm it’s you' : 'Sign in',
    body: html`<section class="card narrow">
      <p class="eyebrow">deltavdevs account</p>
      <h1 class="headline">${reauth ? 'Confirm it’s you' : 'Sign in to Ward'}</h1>
      <p class="caption">${reauth ? 'This part of your account needs a fresh sign-in.' : 'One account for the blog, DeltaTime, SynthCity and everything after.'}</p>
      ${notice(error)}${info ? notice(info, 'ok') : ''}
      ${providers.length ? html`<div class="providers">${providers.map(p => html`<a class="provider ${p}" href="/auth/${p}/start?${q.toString()}">Continue with ${PROVIDERS[p]}</a>`)}</div><p class="or"><span>or</span></p>` : ''}
      <form method="post" action="/login" class="stack">
        ${csrfField(csrf)}<input type="hidden" name="return_to" value="${returnTo}" />${reauth ? html`<input type="hidden" name="reauth" value="1" />` : ''}
        <label>Email <input type="email" name="email" value="${email}" autocomplete="username" required maxlength="254" /></label>
        <label>Password <input type="password" name="password" autocomplete="current-password" required maxlength="200" /></label>
        <button class="cta" type="submit">Sign in</button>
      </form>
      <p class="caption links"><a href="/forgot">Forgot password?</a>${mailEnabled() ? html` · <a href="/register?return_to=${encodeURIComponent(returnTo)}">Create an account</a>` : ''}</p>
    </section>`,
  });
}

const simplePage = (reply, title, body, status = 200) => send(reply, status, { title, body: html`<section class="card narrow"><p class="eyebrow">ward</p><h1 class="headline">${title}</h1>${body}</section>` });

// Finish a sign-in: straight in, or park it behind the 2FA prompt.
async function completeSignIn(request, reply, user, amr, returnTo) {
  if (user.suspended_at) {
    await audit(request, 'login.suspended', { userId: user.id, method: amr[0] });
    return loginPage(request, reply, { error: 'This account is suspended. Contact DeltaVDevs if you think that’s a mistake.', returnTo, status: 403 });
  }
  if (user.totp_enabled_at) {
    reply.setCookie(MFA_COOKIE, seal('mfa', { uid: user.id, amr, returnTo }, 600), { ...cookieOptions, maxAge: 600 });
    return reply.redirect('/login/2fa');
  }
  await createSession(request, reply, user.id, amr);
  await audit(request, 'login', { userId: user.id, actor: `user:${user.id}`, method: amr.join('+') });
  return reply.redirect(returnTo);
}

export async function loginRoutes(app) {
  app.get('/login', async (request, reply) => {
    const returnTo = safeReturn(request.query.return_to);
    const reauth = request.query.reauth === '1';
    if (!reauth && (await loadSession(request))) return reply.redirect(returnTo);
    return loginPage(request, reply, { returnTo, reauth });
  });

  app.post('/login', async (request, reply) => {
    const returnTo = safeReturn(field(request.body, 'return_to', 4000));
    const reauth = field(request.body, 'reauth') === '1';
    const email = normalizeEmail(field(request.body, 'email', 254));
    const password = field(request.body, 'password', 200);
    if (!csrfOk(request)) return loginPage(request, reply, { error: 'Your session expired. Try again.', email, returnTo, reauth, status: 403 });
    if ((await limited(`login:ip:${request.ip}`, 30, 900)) || (await limited(`login:email:${email}`, 8, 900))) {
      return loginPage(request, reply, { error: 'Too many attempts. Wait 15 minutes and try again.', email, returnTo, reauth, status: 429 });
    }
    const user = validEmail(email) ? await findByEmail(email) : null;
    const ok = await verifyPassword(password, user?.password_hash);
    if (!ok) {
      await audit(request, 'login.failed', { userId: user?.id ?? null, method: 'pwd' });
      return loginPage(request, reply, { error: 'That email and password don’t match.', email, returnTo, reauth, status: 401 });
    }
    await clearLimit(`login:email:${email}`);
    return completeSignIn(request, reply, user, ['pwd'], returnTo);
  });

  // ---------- 2FA ----------
  const mfaPage = (request, reply, error = null, status = 200) => simplePage(reply, 'Two-factor code', html`
    <p>Open your authenticator app and enter the 6-digit code for Ward.</p>${notice(error)}
    <form method="post" action="/login/2fa" class="stack">${csrfField(csrfToken(request, reply))}
      <label>Code <input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="20" autofocus /></label>
      <details><summary class="caption">Lost your device? Use a recovery code</summary><label>Recovery code <input name="recovery" autocomplete="off" maxlength="20" placeholder="xxxxx-xxxxx" /></label></details>
      <button class="cta" type="submit">Verify</button>
    </form>`, status);

  app.get('/login/2fa', async (request, reply) => {
    if (!unseal('mfa', request.cookies[MFA_COOKIE])) return reply.redirect('/login');
    return mfaPage(request, reply);
  });

  app.post('/login/2fa', async (request, reply) => {
    const pending = unseal('mfa', request.cookies[MFA_COOKIE]);
    if (!pending) return reply.redirect('/login');
    if (!csrfOk(request)) return mfaPage(request, reply, 'Your session expired. Try again.', 403);
    if (await limited(`mfa:${pending.uid}`, 8, 900)) return mfaPage(request, reply, 'Too many attempts. Wait 15 minutes.', 429);
    const user = await findById(pending.uid);
    if (!user?.totp_enabled_at) return reply.redirect('/login');
    let passed = false;
    const recovery = field(request.body, 'recovery', 20).trim();
    if (recovery) {
      passed = await useRecoveryCode(user.id, recovery);
      if (passed) await audit(request, 'mfa.recovery_code_used', { userId: user.id });
    } else {
      const step = totp.verify(decrypt(user.totp_secret, `totp:${user.id}`), field(request.body, 'code', 20));
      // Claim the step atomically so the same code can't be used twice.
      passed = step !== null && Boolean(await one('UPDATE users SET totp_last_step = $2 WHERE id = $1 AND (totp_last_step IS NULL OR totp_last_step < $2) RETURNING id', [user.id, step]));
    }
    if (!passed) {
      await audit(request, 'mfa.failed', { userId: user.id });
      return mfaPage(request, reply, 'That code didn’t work.', 401);
    }
    reply.clearCookie(MFA_COOKIE, cookieOptions);
    await clearLimit(`mfa:${user.id}`);
    return completeSignIn(request, reply, { ...user, totp_enabled_at: null }, [...pending.amr, 'otp'], safeReturn(pending.returnTo));
  });

  // ---------- registration ----------
  const registerPage = (request, reply, { error = null, email = '', name = '', returnTo = '/account', status = 200 } = {}) => simplePage(reply, 'Create your account', html`
    ${notice(error)}
    <form method="post" action="/register" class="stack">${csrfField(csrfToken(request, reply))}<input type="hidden" name="return_to" value="${returnTo}" />
      <label>Name <input name="display_name" value="${name}" maxlength="60" autocomplete="name" required /></label>
      <label>Email <input type="email" name="email" value="${email}" maxlength="254" autocomplete="email" required /></label>
      <label>Password <input type="password" name="password" minlength="10" maxlength="200" autocomplete="new-password" required /><span class="caption">10+ characters. Checked against known breaches.</span></label>
      <button class="cta" type="submit">Send confirmation link</button>
    </form>
    <p class="caption">Already have one? <a href="/login">Sign in</a></p>`, status);

  app.get('/register', async (request, reply) => {
    if (!mailEnabled()) return errorPage(reply, 503, 'Sign-up is closed', 'Email sign-up isn’t available right now. Use Google, GitHub or Discord instead.');
    return registerPage(request, reply, { returnTo: safeReturn(request.query.return_to) });
  });

  app.post('/register', async (request, reply) => {
    if (!mailEnabled()) return errorPage(reply, 503, 'Sign-up is closed', 'Email sign-up isn’t available right now.');
    const email = normalizeEmail(field(request.body, 'email', 254));
    const name = field(request.body, 'display_name', 60).trim();
    const password = field(request.body, 'password', 200);
    const returnTo = safeReturn(field(request.body, 'return_to', 4000));
    const again = error => registerPage(request, reply, { error, email, name, returnTo, status: 400 });
    if (!csrfOk(request)) return again('Your session expired. Try again.');
    if (!validEmail(email)) return again('That doesn’t look like an email address.');
    if (!name) return again('Tell us what to call you.');
    if ((await limited(`register:ip:${request.ip}`, 10, 3600)) || (await limited(`register:email:${email}`, 3, 3600))) return again('Too many sign-ups from here. Try again in an hour.');
    const problem = await passwordProblem(password, { email });
    if (problem) return again(problem);

    // Same response — and the same scrypt cost — either way, so neither the page
    // nor its timing tells anyone who has an account.
    const passwordHash = await hashPassword(password);
    const existing = await findByEmail(email);
    const token = random();
    if (existing) {
      await query("INSERT INTO email_tokens (token_hash, purpose, user_id, email, expires_at) VALUES ($1, 'reset', $2, $3, now() + interval '1 hour')", [digest(token), existing.id, email]);
      await sendMail(request.log, { to: email, ...templates.alreadyRegistered(`${config.publicUrl}/reset?token=${token}`) });
    } else {
      await query("INSERT INTO email_tokens (token_hash, purpose, email, data, expires_at) VALUES ($1, 'register', $2, $3, now() + interval '1 hour')",
        [digest(token), email, { password_hash: passwordHash, display_name: name, return_to: returnTo }]);
      await sendMail(request.log, { to: email, ...templates.register(`${config.publicUrl}/verify?token=${token}`) });
    }
    return simplePage(reply, 'Check your inbox', html`<p>We sent a link to <strong>${email}</strong>. Click it within an hour to finish.</p><p class="caption">Nothing there? Check spam, or <a href="/register">try again</a>.</p>`);
  });

  // Email links land on a button instead of acting on GET, so link scanners
  // and prefetchers can't burn them.
  const tokenForm = (reply, request, title, action, token, text) => simplePage(reply, title, html`
    <form method="post" action="${action}" class="stack">${csrfField(csrfToken(request, reply))}<input type="hidden" name="token" value="${token}" /><button class="cta" type="submit">${text}</button></form>`);

  const takeToken = async (db, token, purpose) => {
    if (typeof token !== 'string' || token.length < 20 || token.length > 100) return null;
    return (await db.query('DELETE FROM email_tokens WHERE token_hash = $1 AND purpose = $2 RETURNING *', [digest(token), purpose])).rows.find(r => new Date(r.expires_at) > new Date()) || null;
  };

  app.get('/verify', async (request, reply) => tokenForm(reply, request, 'Confirm your email', '/verify', String(request.query.token || '').slice(0, 100), 'Confirm and continue'));

  app.post('/verify', async (request, reply) => {
    if (!csrfOk(request)) return errorPage(reply, 403, 'Link expired', 'Open the link from your email again.');
    const token = field(request.body, 'token', 100);
    // Registration and email-change links both come through here.
    const result = await transaction(async db => {
      const reg = await takeToken(db, token, 'register');
      if (reg) {
        if ((await db.query('SELECT 1 FROM users WHERE email = $1', [reg.email])).rowCount) return { taken: true };
        const username = await freeUsername(db, reg.email.split('@')[0]);
        const user = (await db.query('INSERT INTO users (email, username, display_name, password_hash, password_changed_at) VALUES ($1, $2, $3, $4, now()) RETURNING *',
          [reg.email, username, reg.data.display_name, reg.data.password_hash])).rows[0];
        return { user, created: true, returnTo: reg.data.return_to };
      }
      const change = await takeToken(db, token, 'email');
      if (change) {
        if ((await db.query('SELECT 1 FROM users WHERE email = $1', [change.email])).rowCount) return { taken: true };
        const before = (await db.query('SELECT email FROM users WHERE id = $1 FOR UPDATE', [change.user_id])).rows[0];
        if (!before) return null;
        await db.query('UPDATE users SET email = $2, updated_at = now() WHERE id = $1', [change.user_id, change.email]);
        return { changed: true, userId: change.user_id, oldEmail: before.email, newEmail: change.email };
      }
      return null;
    });
    if (!result) return errorPage(reply, 400, 'Link expired', 'That link was already used or has expired.');
    if (result.taken) return errorPage(reply, 409, 'Already registered', 'That email already belongs to a Ward account. Sign in instead.');
    if (result.created) {
      await audit(request, 'user.registered', { userId: result.user.id, actor: `user:${result.user.id}`, method: 'email' });
      await createSession(request, reply, result.user.id, ['pwd']);
      return reply.redirect(safeReturn(result.returnTo));
    }
    await audit(request, 'user.email_changed', { userId: result.userId, actor: `user:${result.userId}` });
    if (result.oldEmail) await sendMail(request.log, { to: result.oldEmail, ...templates.emailChanged(result.newEmail) }).catch(() => {});
    flash(reply, `Your email is now ${result.newEmail}.`);
    return reply.redirect('/account');
  });

  // ---------- password reset ----------
  app.get('/forgot', async (request, reply) => {
    if (!mailEnabled()) return errorPage(reply, 503, 'Reset unavailable', 'Password reset email isn’t set up yet.');
    return simplePage(reply, 'Reset your password', html`<form method="post" action="/forgot" class="stack">${csrfField(csrfToken(request, reply))}
      <label>Email <input type="email" name="email" maxlength="254" autocomplete="email" required /></label>
      <button class="cta" type="submit">Send reset link</button></form>`);
  });

  app.post('/forgot', async (request, reply) => {
    if (!mailEnabled()) return errorPage(reply, 503, 'Reset unavailable', 'Password reset email isn’t set up yet.');
    if (!csrfOk(request)) return reply.redirect('/forgot');
    const email = normalizeEmail(field(request.body, 'email', 254));
    const sent = () => simplePage(reply, 'Check your inbox', html`<p>If <strong>${email}</strong> has a Ward account, a reset link is on its way. It expires in an hour.</p>`);
    if (!validEmail(email) || (await limited(`forgot:ip:${request.ip}`, 10, 3600)) || (await limited(`forgot:email:${email}`, 3, 3600))) return sent();
    const user = await findByEmail(email);
    if (user && !user.suspended_at) {
      const token = random();
      await query("INSERT INTO email_tokens (token_hash, purpose, user_id, email, expires_at) VALUES ($1, 'reset', $2, $3, now() + interval '1 hour')", [digest(token), user.id, email]);
      await sendMail(request.log, { to: email, ...templates.reset(`${config.publicUrl}/reset?token=${token}`) });
      await audit(request, 'password.reset_requested', { userId: user.id, actor: null });
    }
    return sent();
  });

  const resetPage = (request, reply, token, error = null, status = 200) => simplePage(reply, 'Choose a new password', html`${notice(error)}
    <form method="post" action="/reset" class="stack">${csrfField(csrfToken(request, reply))}<input type="hidden" name="token" value="${token}" />
      <label>New password <input type="password" name="password" minlength="10" maxlength="200" autocomplete="new-password" required /></label>
      <button class="cta" type="submit">Set password</button></form>
    <p class="caption">This signs you out everywhere, including apps you’ve connected.</p>`, status);

  app.get('/reset', async (request, reply) => resetPage(request, reply, String(request.query.token || '').slice(0, 100)));

  app.post('/reset', async (request, reply) => {
    const token = field(request.body, 'token', 100);
    if (!csrfOk(request)) return resetPage(request, reply, token, 'Your session expired. Try again.', 403);
    const row = await one("SELECT t.*, u.username FROM email_tokens t JOIN users u ON u.id = t.user_id WHERE t.token_hash = $1 AND t.purpose = 'reset' AND t.expires_at > now()", [digest(token)]);
    if (!row) return errorPage(reply, 400, 'Link expired', 'That reset link was already used or has expired. Ask for a new one.');
    const password = field(request.body, 'password', 200);
    const problem = await passwordProblem(password, { email: row.email, username: row.username });
    if (problem) return resetPage(request, reply, token, problem, 400);
    const hash = await hashPassword(password);
    const done = await transaction(async db => {
      const used = await db.query("DELETE FROM email_tokens WHERE token_hash = $1 AND purpose = 'reset' RETURNING user_id", [digest(token)]);
      if (!used.rowCount) return false;
      // Only lands if the address still belongs to this account.
      const updated = await db.query('UPDATE users SET password_hash = $2, password_changed_at = now(), updated_at = now() WHERE id = $1 AND email = $3', [row.user_id, hash, row.email]);
      if (!updated.rowCount) return false;
      await db.query("DELETE FROM email_tokens WHERE user_id = $1 AND purpose = 'reset'", [row.user_id]);
      await revokeEverything(db, row.user_id);
      return true;
    });
    if (!done) return errorPage(reply, 400, 'Link expired', 'That reset link was already used or has expired.');
    await audit(request, 'password.reset', { userId: row.user_id, actor: `user:${row.user_id}` });
    reply.clearCookie(MFA_COOKIE, cookieOptions);
    return reply.redirect('/login?notice=reset');
  });

  // ---------- Google / GitHub / Discord ----------
  app.get('/auth/:provider/start', async (request, reply) => {
    const provider = request.params.provider;
    if (!enabledProviders().includes(provider)) return errorPage(reply, 404, 'Unknown provider', 'That sign-in method isn’t available.');
    const returnTo = safeReturn(request.query.return_to);
    const intent = request.query.intent === 'link' ? 'link' : 'login';
    if (await limited(`social:ip:${request.ip}`, 40, 900)) return loginPage(request, reply, { error: 'Too many sign-in attempts. Wait a few minutes.', returnTo, status: 429 });
    let uid = null;
    if (intent === 'link') {
      const user = await loadSession(request);
      if (!user) return reply.redirect(`/login?return_to=${encodeURIComponent('/account')}`);
      // Adding a way in is as sensitive as changing the password.
      if (!recentlyAuthenticated(user)) return reply.redirect(`/login?reauth=1&return_to=${encodeURIComponent('/account#methods')}`);
      uid = user.id;
    }
    const state = random(), verifier = random(), nonce = random();
    reply.setCookie(OAUTH_COOKIE, seal('oauth', { provider, state, verifier, returnTo, intent, uid }, 600), { ...cookieOptions, maxAge: 600 });
    const { authorize, scope, extra } = PROVIDER_CONFIG[provider];
    const url = new URL(authorize);
    url.search = new URLSearchParams({
      client_id: config.providers[provider].id, redirect_uri: callbackUrl(provider), response_type: 'code', scope, state,
      code_challenge: s256(verifier), code_challenge_method: 'S256', ...(provider === 'google' ? { nonce } : {}), ...extra,
    }).toString();
    return reply.redirect(url.toString());
  });

  app.get('/auth/:provider/callback', async (request, reply) => {
    const provider = request.params.provider;
    const pending = unseal('oauth', request.cookies[OAUTH_COOKIE]);
    reply.clearCookie(OAUTH_COOKIE, cookieOptions);
    const { state, code, error } = request.query || {};
    const returnTo = safeReturn(pending?.returnTo);
    const bounce = (message, status = 400) => {
      if (pending?.intent !== 'link') return loginPage(request, reply, { error: message, returnTo, status });
      flash(reply, message, 'error');
      return reply.redirect('/account#methods');
    };
    if (!enabledProviders().includes(provider)) return errorPage(reply, 404, 'Unknown provider', 'That sign-in method isn’t available.');
    if (error) return bounce(`${PROVIDERS[provider]} sign-in was cancelled.`);
    if (!pending || pending.provider !== provider || typeof state !== 'string' || typeof code !== 'string' || code.length > 2000 || !equal(state, pending.state)) {
      return bounce('Sign-in expired or couldn’t be verified. Try again.');
    }
    let profile;
    try {
      profile = await PROVIDER_CONFIG[provider].profile(code, pending.verifier, callbackUrl(provider));
    } catch (err) {
      request.log.warn({ err: err.message, provider }, 'provider exchange failed');
      return bounce(`${PROVIDERS[provider]} sign-in failed. Try again.`, 502);
    }

    const identity = await one('SELECT * FROM identities WHERE provider = $1 AND subject = $2', [provider, profile.subject]);
    const touch = id => query('UPDATE identities SET last_used_at = now(), email = $2, handle = $3 WHERE id = $1', [id, profile.email, profile.handle]);

    if (pending.intent === 'link') {
      const user = await loadSession(request);
      if (!user || user.id !== pending.uid) return reply.redirect('/login');
      if (identity && identity.user_id !== user.id) return bounce(`That ${PROVIDERS[provider]} account is already linked to a different Ward account.`, 409);
      if (identity) { await touch(identity.id); flash(reply, `${PROVIDERS[provider]} is linked.`); return reply.redirect('/account#methods'); }
      const inserted = await one('INSERT INTO identities (user_id, provider, subject, email, handle, last_used_at) VALUES ($1, $2, $3, $4, $5, now()) ON CONFLICT DO NOTHING RETURNING id',
        [user.id, provider, profile.subject, profile.email, profile.handle]);
      if (!inserted) return bounce(`You already have a ${PROVIDERS[provider]} account linked. Unlink it first.`, 409);
      if (!user.avatar_url && profile.avatar) await query('UPDATE users SET avatar_url = $2 WHERE id = $1', [user.id, profile.avatar]);
      await audit(request, 'identity.linked', { userId: user.id, actor: `user:${user.id}`, provider });
      flash(reply, `${PROVIDERS[provider]} is linked. You can sign in with it now.`);
      return reply.redirect('/account#methods');
    }

    if (identity) {
      await touch(identity.id);
      return completeSignIn(request, reply, await findById(identity.user_id), [provider], returnTo);
    }

    // New to Ward. Never auto-merge into an existing account by email: that's
    // how a hijacked or recycled provider account takes over someone's Ward.
    if (profile.email && (await findByEmail(profile.email))) {
      await audit(request, 'login.email_collision', { provider, actor: null });
      return bounce(`A Ward account already uses ${profile.email}. Sign in the way you usually do, then link ${PROVIDERS[provider]} from your account page.`, 409);
    }
    const user = await transaction(async db => {
      const username = await freeUsername(db, profile.handle, profile.name, profile.email?.split('@')[0]);
      const created = (await db.query('INSERT INTO users (email, username, display_name, avatar_url) VALUES ($1, $2, $3, $4) RETURNING *',
        [profile.email, username, (profile.name || profile.handle || username).slice(0, 60), profile.avatar])).rows[0];
      await db.query('INSERT INTO identities (user_id, provider, subject, email, handle, last_used_at) VALUES ($1, $2, $3, $4, $5, now())',
        [created.id, provider, profile.subject, profile.email, profile.handle]);
      return created;
    }).catch(err => (err.code === '23505' ? null : Promise.reject(err)));
    if (!user) return bounce('That account was just registered. Try signing in again.', 409);
    await audit(request, 'user.registered', { userId: user.id, actor: `user:${user.id}`, method: provider });
    return completeSignIn(request, reply, user, [provider], returnTo);
  });

  app.post('/logout', async (request, reply) => {
    if (!csrfOk(request)) return reply.redirect('/account');
    const user = await loadSession(request);
    await endSession(request, reply);
    if (user) await audit(request, 'logout', { userId: user.id, actor: `user:${user.id}` });
    return reply.redirect('/login?notice=signed_out');
  });
}
