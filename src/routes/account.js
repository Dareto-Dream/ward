import QRCode from 'qrcode';
import { config, mailEnabled } from '../config.js';
import { query, one, transaction, limited } from '../db.js';
import { random, digest, seal, unseal, encrypt, decrypt, hashPassword, verifyPassword } from '../crypto.js';
import { loadSession, csrfToken, csrfOk, recentlyAuthenticated, cookieOptions, flash, takeFlash, SESSION_COOKIE } from '../session.js';
import { html, send, notice, csrfField, PROVIDERS } from '../views.js';
import { enabledProviders } from '../providers.js';
import { USERNAME, normalizeEmail, validEmail, passwordProblem, signInMethods, newRecoveryCodes, unusedRecoveryCodes, revokeEverything } from '../users.js';
import { sendMail, templates } from '../mail.js';
import { SCOPES } from './oauth.js';
import * as totp from '../totp.js';
import { audit } from '../audit.js';

const TOTP_SETUP_COOKIE = config.production ? '__Host-ward-totp' : 'ward-totp';
const field = (body, name, max = 300) => (typeof body?.[name] === 'string' ? body[name].slice(0, max) : '');
const when = d => (d ? new Date(d).toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : '—');

// Every /account route: signed in, and every POST carries the CSRF token.
async function guard(request, reply) {
  const user = await loadSession(request);
  if (!user) return reply.redirect(`/login?return_to=${encodeURIComponent('/account')}`);
  if (request.method === 'POST' && !csrfOk(request)) { flash(reply, 'That form expired. Try again.', 'error'); return reply.redirect('/account'); }
  request.user = user;
}

// Changing how someone gets in needs a sign-in from the last 15 minutes,
// so a borrowed laptop or stolen cookie can't lock the owner out.
function sensitive(request, reply, anchor = '') {
  if (recentlyAuthenticated(request.user)) return false;
  reply.redirect(`/login?reauth=1&return_to=${encodeURIComponent(`/account${anchor}`)}`);
  return true;
}

const back = (reply, message, kind = 'ok', anchor = '') => { flash(reply, message, kind); return reply.redirect(`/account${anchor}`); };

export async function accountRoutes(app) {
  app.addHook('preHandler', guard);

  app.get('/account', async (request, reply) => {
    const user = request.user;
    const csrf = csrfToken(request, reply);
    const flashed = takeFlash(request, reply);
    const [identities, sessions, apps, codesLeft] = await Promise.all([
      query('SELECT provider, handle, email, created_at, last_used_at FROM identities WHERE user_id = $1 ORDER BY created_at', [user.id]).then(r => r.rows),
      query('SELECT id, amr, created_at, last_seen_at, ip, user_agent FROM sessions WHERE user_id = $1 AND expires_at > now() ORDER BY last_seen_at DESC', [user.id]).then(r => r.rows),
      query('SELECT g.client_id, g.scopes, g.created_at, g.last_used_at, c.name, c.homepage_url FROM grants g JOIN clients c ON c.id = g.client_id WHERE g.user_id = $1 ORDER BY g.last_used_at DESC', [user.id]).then(r => r.rows),
      user.totp_enabled_at ? unusedRecoveryCodes(user.id) : 0,
    ]);
    const linked = new Map(identities.map(i => [i.provider, i]));
    const methods = identities.length + (user.password_hash && user.email ? 1 : 0);
    const fresh = recentlyAuthenticated(user);
    const post = (action, label, cls = 'outline small', extra = null) => html`<form method="post" action="${action}" class="inline">${csrfField(csrf)}${extra}<button class="${cls}" type="submit">${label}</button></form>`;

    return send(reply, 200, {
      title: 'Your account', wide: true, user: { ...user, csrf },
      body: html`
      <div class="page-head">
        ${user.avatar_url ? html`<img class="avatar" src="${user.avatar_url}" alt="" referrerpolicy="no-referrer" />` : html`<span class="avatar blank">${user.display_name.slice(0, 1).toUpperCase()}</span>`}
        <div><p class="eyebrow">ward account</p><h1 class="headline">${user.display_name}</h1><p class="caption">@${user.username} · ${user.email || 'no email on file'} · member since ${when(user.created_at).slice(0, 10)}</p></div>
      </div>
      ${flashed ? notice(flashed.message, flashed.kind) : ''}
      ${fresh ? '' : html`<p class="notice info">Security changes need a recent sign-in. You’ll be asked to confirm it’s you.</p>`}

      <div class="sections">
      <section class="card" id="profile"><h2 class="subheadline">Profile</h2>
        <p class="caption">This is what DeltaVDevs sites see when you sign in with Ward.</p>
        <form method="post" action="/account/profile" class="stack">${csrfField(csrf)}
          <label>Display name <input name="display_name" value="${user.display_name}" maxlength="60" required /></label>
          <label>Username <input name="username" value="${user.username}" pattern="[a-z0-9_]{3,32}" maxlength="32" required /><span class="caption">3–32 lowercase letters, numbers or _</span></label>
          <button class="cta small" type="submit">Save</button>
        </form>
      </section>

      <section class="card" id="email"><h2 class="subheadline">Email</h2>
        <p>${user.email ? html`<strong>${user.email}</strong> <span class="pill">verified</span>` : 'No email on file.'}</p>
        ${mailEnabled() ? html`<form method="post" action="/account/email" class="stack">${csrfField(csrf)}
          <label>${user.email ? 'Change to' : 'Add'} <input type="email" name="email" maxlength="254" required /></label>
          <button class="outline small" type="submit">Send confirmation link</button></form>` : html`<p class="caption">Email changes are unavailable until mail is set up.</p>`}
      </section>

      <section class="card" id="methods"><h2 class="subheadline">Ways to sign in</h2>
        <ul class="list">
          <li><span><strong>Email + password</strong><br /><span class="caption">${user.password_hash ? `set ${when(user.password_changed_at)}` : 'not set'}</span></span>
            ${user.password_hash && methods > 1 ? post('/account/password/remove', 'Remove', 'ghost small') : ''}</li>
          ${enabledProviders().concat([...linked.keys()].filter(p => !enabledProviders().includes(p))).map(p => {
            const id = linked.get(p);
            return html`<li><span><strong>${PROVIDERS[p]}</strong><br /><span class="caption">${id ? `${id.handle || id.email || 'linked'} · last used ${when(id.last_used_at)}` : 'not linked'}</span></span>
              ${id ? (methods > 1 ? post(`/account/unlink/${p}`, 'Unlink', 'ghost small') : html`<span class="caption">only way in</span>`) : html`<a class="button-link" href="/auth/${p}/start?intent=link"><button class="outline small" type="button" tabindex="-1">Link</button></a>`}</li>`;
          })}
        </ul>
        <form method="post" action="/account/password" class="stack">${csrfField(csrf)}
          ${user.password_hash ? html`<label>Current password <input type="password" name="current" autocomplete="current-password" maxlength="200" required /></label>` : ''}
          <label>${user.password_hash ? 'New password' : 'Set a password'} <input type="password" name="password" autocomplete="new-password" minlength="10" maxlength="200" required ${user.email ? '' : 'disabled'} /></label>
          ${user.email ? '' : html`<span class="caption">Add an email first. It’s what you’d sign in with.</span>`}
          <button class="outline small" type="submit" ${user.email ? '' : 'disabled'}>${user.password_hash ? 'Change password' : 'Set password'}</button>
        </form>
      </section>

      <section class="card" id="2fa"><h2 class="subheadline">Two-factor authentication</h2>
        ${user.totp_enabled_at
          ? html`<p><span class="pill ok">on</span> since ${when(user.totp_enabled_at)} · ${codesLeft} recovery codes left</p>
              <div class="row">${post('/account/2fa/recovery', 'New recovery codes')}${post('/account/2fa/disable', 'Turn off', 'ghost small')}</div>`
          : html`<p>Add an authenticator app (1Password, Aegis, Google Authenticator…). Ward will ask for a code after every sign-in, whatever method you use.</p>${post('/account/2fa/start', 'Set up', 'cta small')}`}
      </section>

      <section class="card span" id="sessions"><h2 class="subheadline">Where you’re signed in</h2>
        <ul class="list">${sessions.map(s => html`<li><span><strong>${s.id === user.session_id ? 'This browser' : describeAgent(s.user_agent)}</strong><br />
          <span class="caption">${s.amr.join(' + ')} · ${s.ip || 'unknown ip'} · signed in ${when(s.created_at)} · seen ${when(s.last_seen_at)}</span></span>
          ${s.id === user.session_id ? '' : post(`/account/sessions/${s.id}/revoke`, 'Sign out', 'ghost small')}</li>`)}</ul>
        ${sessions.length > 1 ? post('/account/sessions/revoke-others', 'Sign out everywhere else') : ''}
      </section>

      <section class="card span" id="apps"><h2 class="subheadline">Connected apps</h2>
        ${apps.length ? html`<ul class="list">${apps.map(a => html`<li><span><strong>${a.homepage_url ? html`<a href="${a.homepage_url}" rel="noopener">${a.name}</a>` : a.name}</strong><br />
          <span class="caption">${a.scopes.map(s => SCOPES[s] || s).join(' · ')} · last used ${when(a.last_used_at)}</span></span>
          ${post(`/account/apps/${encodeURIComponent(a.client_id)}/revoke`, 'Disconnect', 'ghost small')}</li>`)}</ul>` : html`<p class="caption">You haven’t used Ward to sign in anywhere yet.</p>`}
      </section>

      <section class="card span danger-zone" id="delete"><h2 class="subheadline">Your data</h2>
        <p><a href="/account/export.json" download>Download everything Ward stores about you</a> (JSON).</p>
        <form method="post" action="/account/delete" class="stack">${csrfField(csrf)}
          <label><span>Delete your Ward account. Type <code>${user.username}</code> to confirm.</span><input name="confirm" autocomplete="off" maxlength="40" /></label>
          <span class="caption">Signs you out of every app. Sites keep whatever they stored themselves; ask them separately.</span>
          <button class="danger small" type="submit">Delete account</button>
        </form>
      </section>
      </div>`,
    });
  });

  app.post('/account/profile', async (request, reply) => {
    const name = field(request.body, 'display_name', 60).trim();
    const username = field(request.body, 'username', 32).trim().toLowerCase();
    if (!name) return back(reply, 'Display name can’t be empty.', 'error', '#profile');
    if (!USERNAME.test(username)) return back(reply, 'Usernames are 3–32 lowercase letters, numbers or _.', 'error', '#profile');
    const taken = await one('SELECT 1 FROM users WHERE username = $1 AND id <> $2', [username, request.user.id]);
    if (taken) return back(reply, `@${username} is taken.`, 'error', '#profile');
    await query('UPDATE users SET display_name = $2, username = $3, updated_at = now() WHERE id = $1', [request.user.id, name, username]);
    if (username !== request.user.username) await audit(request, 'user.username_changed', { userId: request.user.id, from: request.user.username, to: username });
    return back(reply, 'Profile saved.', 'ok', '#profile');
  });

  app.post('/account/email', async (request, reply) => {
    if (sensitive(request, reply, '#email')) return;
    if (!mailEnabled()) return back(reply, 'Email isn’t set up yet.', 'error', '#email');
    const email = normalizeEmail(field(request.body, 'email', 254));
    if (!validEmail(email)) return back(reply, 'That doesn’t look like an email address.', 'error', '#email');
    if (await limited(`email-change:${request.user.id}`, 5, 3600)) return back(reply, 'Too many tries. Wait an hour.', 'error', '#email');
    // Don't reveal whether the address is taken; /verify refuses it later if so.
    const token = random();
    await query("INSERT INTO email_tokens (token_hash, purpose, user_id, email, expires_at) VALUES ($1, 'email', $2, $3, now() + interval '1 hour')", [digest(token), request.user.id, email]);
    await sendMail(request.log, { to: email, ...templates.changeEmail(`${config.publicUrl}/verify?token=${token}`) });
    await audit(request, 'user.email_change_requested', { userId: request.user.id });
    return back(reply, `Check ${email} for a confirmation link.`, 'ok', '#email');
  });

  app.post('/account/password', async (request, reply) => {
    const user = request.user;
    const password = field(request.body, 'password', 200);
    if (!user.email) return back(reply, 'Add an email before setting a password.', 'error', '#methods');
    if (user.password_hash) {
      if (await limited(`pwchange:${user.id}`, 8, 900)) return back(reply, 'Too many tries. Wait 15 minutes.', 'error', '#methods');
      if (!(await verifyPassword(field(request.body, 'current', 200), user.password_hash))) return back(reply, 'Current password is wrong.', 'error', '#methods');
    } else if (sensitive(request, reply, '#methods')) return;
    const problem = await passwordProblem(password, { email: user.email, username: user.username });
    if (problem) return back(reply, problem, 'error', '#methods');
    await transaction(async db => {
      await db.query('UPDATE users SET password_hash = $2, password_changed_at = now(), updated_at = now() WHERE id = $1', [user.id, await hashPassword(password)]);
      await db.query('DELETE FROM sessions WHERE user_id = $1 AND id <> $2', [user.id, user.session_id]);
    });
    await audit(request, user.password_hash ? 'password.changed' : 'password.set', { userId: user.id });
    return back(reply, 'Password saved. Other browsers were signed out.', 'ok', '#methods');
  });

  app.post('/account/password/remove', async (request, reply) => {
    if (sensitive(request, reply, '#methods')) return;
    if ((await signInMethods(request.user.id)) < 2) return back(reply, 'That’s your only way in. Link another first.', 'error', '#methods');
    await query('UPDATE users SET password_hash = NULL, password_changed_at = now(), updated_at = now() WHERE id = $1', [request.user.id]);
    await audit(request, 'password.removed', { userId: request.user.id });
    return back(reply, 'Password removed.', 'ok', '#methods');
  });

  app.post('/account/unlink/:provider', async (request, reply) => {
    if (sensitive(request, reply, '#methods')) return;
    const provider = request.params.provider;
    if (!PROVIDERS[provider]) return back(reply, 'Unknown provider.', 'error', '#methods');
    // Count and delete in one transaction so two tabs can't unlink the last two methods at once.
    const ok = await transaction(async db => {
      await db.query('SELECT 1 FROM users WHERE id = $1 FOR UPDATE', [request.user.id]);
      const n = (await db.query(`SELECT (u.password_hash IS NOT NULL AND u.email IS NOT NULL)::int + (SELECT count(*) FROM identities WHERE user_id = u.id)::int AS n FROM users u WHERE u.id = $1`, [request.user.id])).rows[0].n;
      if (n < 2) return false;
      return (await db.query('DELETE FROM identities WHERE user_id = $1 AND provider = $2', [request.user.id, provider])).rowCount > 0;
    });
    if (!ok) return back(reply, 'That’s your only way in. Link another first.', 'error', '#methods');
    await audit(request, 'identity.unlinked', { userId: request.user.id, provider });
    return back(reply, `${PROVIDERS[provider]} unlinked.`, 'ok', '#methods');
  });

  // ---------- 2FA ----------
  app.post('/account/2fa/start', async (request, reply) => {
    if (sensitive(request, reply, '#2fa')) return;
    if (request.user.totp_enabled_at) return back(reply, '2FA is already on.', 'ok', '#2fa');
    // Not saved until they prove the app works.
    reply.setCookie(TOTP_SETUP_COOKIE, seal('totp-setup', { uid: request.user.id, secret: totp.newSecret() }, 900), { ...cookieOptions, maxAge: 900 });
    return reply.redirect('/account/2fa');
  });

  const setupPage = async (request, reply, error = null) => {
    const pending = unseal('totp-setup', request.cookies[TOTP_SETUP_COOKIE]);
    if (!pending || pending.uid !== request.user.id) return back(reply, 'Setup timed out. Start again.', 'error', '#2fa');
    const uri = totp.uri(pending.secret, request.user.email || request.user.username);
    const qr = await QRCode.toDataURL(uri, { margin: 1, width: 220, errorCorrectionLevel: 'M' });
    const csrf = csrfToken(request, reply);
    return send(reply, error ? 400 : 200, {
      title: 'Set up 2FA', user: { ...request.user, csrf },
      body: html`<section class="card narrow"><p class="eyebrow">two-factor</p><h1 class="headline">Scan this with your authenticator</h1>
        <img class="qr" src="${qr}" alt="QR code for your authenticator app" width="220" height="220" />
        <p class="caption">Can’t scan? Enter this key: <code class="secret">${pending.secret.replace(/(.{4})/g, '$1 ').trim()}</code></p>
        ${notice(error)}
        <form method="post" action="/account/2fa/confirm" class="stack">${csrfField(csrf)}
          <label>6-digit code from the app <input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="10" required autofocus /></label>
          <button class="cta" type="submit">Turn on 2FA</button></form>
        <p class="caption"><a href="/account#2fa">Cancel</a></p></section>`,
    });
  };

  app.get('/account/2fa', async (request, reply) => setupPage(request, reply));

  const codesPage = (request, reply, codes) => send(reply, 200, {
    title: 'Recovery codes', user: { ...request.user, csrf: csrfToken(request, reply) },
    body: html`<section class="card narrow"><p class="eyebrow">two-factor</p><h1 class="headline">Save your recovery codes</h1>
      <p>Each one gets you in once if you lose your authenticator. This is the only time they’re shown.</p>
      <ol class="codes">${codes.map(c => html`<li><code>${c}</code></li>`)}</ol>
      <p><a class="button-link" href="/account#2fa"><button class="cta" type="button" tabindex="-1">I saved them</button></a></p></section>`,
  });

  app.post('/account/2fa/confirm', async (request, reply) => {
    if (sensitive(request, reply, '#2fa')) return;
    const pending = unseal('totp-setup', request.cookies[TOTP_SETUP_COOKIE]);
    if (!pending || pending.uid !== request.user.id) return back(reply, 'Setup timed out. Start again.', 'error', '#2fa');
    if (await limited(`totp-setup:${request.user.id}`, 10, 900)) return back(reply, 'Too many tries. Wait 15 minutes.', 'error', '#2fa');
    const step = totp.verify(pending.secret, field(request.body, 'code', 10));
    if (step === null) return setupPage(request, reply, 'That code didn’t match. Check the time on your phone and try the next one.');
    const codes = await transaction(async db => {
      await db.query('UPDATE users SET totp_secret = $2, totp_enabled_at = now(), totp_last_step = $3, updated_at = now() WHERE id = $1',
        [request.user.id, encrypt(pending.secret, `totp:${request.user.id}`), step]);
      return newRecoveryCodes(db, request.user.id);
    });
    reply.clearCookie(TOTP_SETUP_COOKIE, cookieOptions);
    await audit(request, 'mfa.enabled', { userId: request.user.id });
    return codesPage(request, reply, codes);
  });

  app.post('/account/2fa/recovery', async (request, reply) => {
    if (sensitive(request, reply, '#2fa')) return;
    if (!request.user.totp_enabled_at) return back(reply, '2FA is off.', 'error', '#2fa');
    const codes = await transaction(db => newRecoveryCodes(db, request.user.id));
    await audit(request, 'mfa.recovery_regenerated', { userId: request.user.id });
    return codesPage(request, reply, codes);
  });

  app.post('/account/2fa/disable', async (request, reply) => {
    if (sensitive(request, reply, '#2fa')) return;
    await transaction(async db => {
      await db.query('UPDATE users SET totp_secret = NULL, totp_enabled_at = NULL, totp_last_step = NULL, updated_at = now() WHERE id = $1', [request.user.id]);
      await db.query('DELETE FROM recovery_codes WHERE user_id = $1', [request.user.id]);
    });
    await audit(request, 'mfa.disabled', { userId: request.user.id });
    return back(reply, 'Two-factor authentication is off.', 'ok', '#2fa');
  });

  // ---------- sessions & apps ----------
  app.post('/account/sessions/:id/revoke', async (request, reply) => {
    const id = /^\d{1,18}$/.test(request.params.id) ? request.params.id : '0';
    await query('DELETE FROM sessions WHERE id = $1 AND user_id = $2 AND id <> $3', [id, request.user.id, request.user.session_id]);
    await audit(request, 'session.revoked', { userId: request.user.id, session: id });
    return back(reply, 'Signed that browser out.', 'ok', '#sessions');
  });

  app.post('/account/sessions/revoke-others', async (request, reply) => {
    await query('DELETE FROM sessions WHERE user_id = $1 AND id <> $2', [request.user.id, request.user.session_id]);
    await audit(request, 'session.revoked_others', { userId: request.user.id });
    return back(reply, 'Signed out everywhere else.', 'ok', '#sessions');
  });

  app.post('/account/apps/:client/revoke', async (request, reply) => {
    const clientId = String(request.params.client).slice(0, 100);
    await transaction(async db => {
      await db.query('DELETE FROM grants WHERE user_id = $1 AND client_id = $2', [request.user.id, clientId]);
      await db.query('UPDATE tokens SET revoked_at = now() WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL', [request.user.id, clientId]);
    });
    await audit(request, 'oauth.grant_revoked', { userId: request.user.id, clientId });
    return back(reply, 'Disconnected. That app has to ask again next time.', 'ok', '#apps');
  });

  // ---------- your data ----------
  app.get('/account/export.json', async (request, reply) => {
    const id = request.user.id;
    const [user, identities, sessions, grants, auditRows] = await Promise.all([
      one('SELECT id, email, username, display_name, avatar_url, created_at, updated_at, last_login_at, password_changed_at, totp_enabled_at, terms_version, privacy_version, policies_accepted_at, (password_hash IS NOT NULL) AS has_password FROM users WHERE id = $1', [id]),
      query('SELECT provider, subject, email, handle, created_at, last_used_at FROM identities WHERE user_id = $1', [id]).then(r => r.rows),
      query('SELECT amr, created_at, last_seen_at, expires_at, ip, user_agent FROM sessions WHERE user_id = $1', [id]).then(r => r.rows),
      query('SELECT client_id, scopes, created_at, last_used_at FROM grants WHERE user_id = $1', [id]).then(r => r.rows),
      query('SELECT at, action, ip, client_id, detail FROM audit_log WHERE user_id = $1 ORDER BY at DESC LIMIT 1000', [id]).then(r => r.rows),
    ]);
    reply.header('Content-Disposition', 'attachment; filename="ward-export.json"');
    return { exported_at: new Date().toISOString(), user, identities, sessions, connected_apps: grants, activity: auditRows };
  });

  app.post('/account/delete', async (request, reply) => {
    if (sensitive(request, reply, '#delete')) return;
    if (field(request.body, 'confirm', 40).trim() !== request.user.username) return back(reply, 'Type your username exactly to confirm.', 'error', '#delete');
    await transaction(async db => {
      await revokeEverything(db, request.user.id);
      await db.query('DELETE FROM users WHERE id = $1', [request.user.id]);
    });
    await audit(request, 'user.deleted', { userId: request.user.id, username: request.user.username });
    reply.clearCookie(SESSION_COOKIE, cookieOptions);
    return reply.redirect('/login?notice=deleted');
  });
}

function describeAgent(ua) {
  if (!ua) return 'Unknown browser';
  const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Mac OS X/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : '';
  return os ? `${browser} on ${os}` : browser;
}
