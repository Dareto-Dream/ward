import { z } from 'zod';
import { config, mailEnabled } from '../config.js';
import { query, one, transaction, limited } from '../db.js';
import { random, digest, equal } from '../crypto.js';
import { USERNAME, normalizeEmail, validEmail, revokeEverything } from '../users.js';
import { sendMail, templates } from '../mail.js';
import { SCOPES } from './oauth.js';
import { audit } from '../audit.js';

// /admin/v1 — what Telescreen uses to run accounts and apps. Bearer
// WARD_ADMIN_KEY only, never cookies, so a browser can't be tricked into it.
// Telescreen names the human behind each call in X-Ward-Actor for the audit log.
const uuid = z.string().uuid();
const httpsUrl = z.string().url().max(2000).refine(u => {
  const url = new URL(u);
  if (url.hash) return false;
  // http only for local development callbacks.
  return url.protocol === 'https:' || (url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname));
}, 'must be https (or http://localhost), without a #fragment');

const clientShape = z.object({
  name: z.string().trim().min(1).max(80),
  redirect_uris: z.array(httpsUrl).min(1).max(20),
  post_logout_redirect_uris: z.array(httpsUrl).max(20).default([]),
  scopes: z.array(z.enum(Object.keys(SCOPES))).min(1).default(['openid', 'profile', 'email', 'offline_access']),
  first_party: z.boolean().default(false),
  homepage_url: httpsUrl.nullable().optional(),
  confidential: z.boolean().default(true),
});

async function guard(request, reply) {
  const header = request.headers.authorization;
  const key = typeof header === 'string' && header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!config.adminKey || !equal(key, config.adminKey)) {
    if (await limited(`admin-fail:${request.ip}`, 20, 900)) return reply.code(429).send({ error: 'slow down' });
    return reply.code(401).send({ error: 'unauthorized' });
  }
  const actor = String(request.headers['x-ward-actor'] || 'admin').slice(0, 120);
  request.admin = `admin:${actor}`;
}

const notFound = () => Object.assign(new Error('not found'), { statusCode: 404 });
const userOr404 = async id => (await one('SELECT * FROM users WHERE id = $1', [uuid.parse(id)])) || Promise.reject(notFound());

const publicUser = u => ({
  id: u.id, email: u.email, username: u.username, display_name: u.display_name, avatar_url: u.avatar_url,
  has_password: Boolean(u.password_hash), mfa: Boolean(u.totp_enabled_at), suspended_at: u.suspended_at, suspended_reason: u.suspended_reason,
  created_at: u.created_at, updated_at: u.updated_at, last_login_at: u.last_login_at,
  terms_version: u.terms_version, privacy_version: u.privacy_version, policies_accepted_at: u.policies_accepted_at,
});
const publicClient = c => ({ ...c, secret_hash: undefined, confidential: Boolean(c.secret_hash) });
const newClientSecret = () => `wcs_${random(32)}`;

export async function adminRoutes(app) {
  app.addHook('onRequest', guard);

  app.get('/admin/v1/stats', async () => one(`SELECT
    (SELECT count(*) FROM users)::int AS users,
    (SELECT count(*) FROM users WHERE suspended_at IS NOT NULL)::int AS suspended,
    (SELECT count(*) FROM users WHERE totp_enabled_at IS NOT NULL)::int AS mfa,
    (SELECT count(*) FROM users WHERE created_at > now() - interval '7 days')::int AS new_7d,
    (SELECT count(DISTINCT user_id) FROM sessions WHERE last_seen_at > now() - interval '1 day')::int AS active_1d,
    (SELECT count(*) FROM clients WHERE disabled_at IS NULL)::int AS clients,
    (SELECT json_object_agg(provider, n) FROM (SELECT provider, count(*)::int n FROM identities GROUP BY provider) p) AS providers,
    (SELECT count(*) FROM audit_log WHERE action IN ('login.failed','mfa.failed') AND at > now() - interval '1 day')::int AS failed_logins_1d`));

  // ---------- users ----------
  app.get('/admin/v1/users', async request => {
    const q = z.object({
      q: z.string().trim().max(200).optional(),
      status: z.enum(['all', 'active', 'suspended']).default('all'),
      limit: z.coerce.number().int().min(1).max(200).default(50),
      offset: z.coerce.number().int().min(0).default(0),
    }).parse(request.query);
    const where = [], params = [];
    if (q.q) {
      params.push(`%${q.q.toLowerCase().replace(/[\\%_]/g, c => `\\${c}`)}%`);
      const p = `$${params.length}`;
      where.push(`(u.email LIKE ${p} OR u.username LIKE ${p} OR lower(u.display_name) LIKE ${p} OR u.id::text = $${params.push(q.q)} OR EXISTS (SELECT 1 FROM identities i WHERE i.user_id = u.id AND (lower(i.handle) LIKE ${p} OR i.email LIKE ${p} OR i.subject = $${params.length})))`);
    }
    if (q.status === 'active') where.push('u.suspended_at IS NULL');
    if (q.status === 'suspended') where.push('u.suspended_at IS NOT NULL');
    const sql = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const [rows, total] = await Promise.all([
      query(`SELECT u.*, (SELECT array_agg(provider ORDER BY provider) FROM identities WHERE user_id = u.id) AS providers
        FROM users u ${sql} ORDER BY u.created_at DESC LIMIT ${q.limit} OFFSET ${q.offset}`, params),
      one(`SELECT count(*)::int AS n FROM users u ${sql}`, params),
    ]);
    return { total: total.n, users: rows.rows.map(u => ({ ...publicUser(u), providers: u.providers || [] })) };
  });

  app.get('/admin/v1/users/:id', async request => {
    const user = await userOr404(request.params.id);
    const [identities, sessions, grants, activity] = await Promise.all([
      query('SELECT provider, subject, email, handle, created_at, last_used_at FROM identities WHERE user_id = $1 ORDER BY created_at', [user.id]),
      query('SELECT id, amr, created_at, last_seen_at, expires_at, ip, user_agent FROM sessions WHERE user_id = $1 AND expires_at > now() ORDER BY last_seen_at DESC', [user.id]),
      query(`SELECT g.client_id, c.name, g.scopes, g.created_at, g.last_used_at,
        (SELECT count(*) FROM tokens t WHERE t.user_id = g.user_id AND t.client_id = g.client_id AND t.revoked_at IS NULL AND t.expires_at > now())::int AS live_tokens
        FROM grants g JOIN clients c ON c.id = g.client_id WHERE g.user_id = $1 ORDER BY g.last_used_at DESC`, [user.id]),
      query('SELECT at, actor, action, ip, client_id, detail FROM audit_log WHERE user_id = $1 ORDER BY at DESC LIMIT 100', [user.id]),
    ]);
    return { user: publicUser(user), identities: identities.rows, sessions: sessions.rows, grants: grants.rows, activity: activity.rows };
  });

  app.patch('/admin/v1/users/:id', async request => {
    const user = await userOr404(request.params.id);
    const body = z.object({
      display_name: z.string().trim().min(1).max(60).optional(),
      username: z.string().trim().toLowerCase().regex(USERNAME).optional(),
      // Admin-set emails count as verified: the admin is vouching for it.
      email: z.string().trim().max(254).nullable().optional(),
    }).strict().parse(request.body);
    if (body.email) {
      body.email = normalizeEmail(body.email);
      if (!validEmail(body.email)) throw Object.assign(new Error('invalid email'), { statusCode: 400 });
    }
    const sets = [], params = [user.id];
    for (const [k, v] of Object.entries(body)) { params.push(v); sets.push(`${k} = $${params.length}`); }
    if (!sets.length) return { user: publicUser(user) };
    try {
      const updated = await one(`UPDATE users SET ${sets.join(', ')}, updated_at = now() WHERE id = $1 RETURNING *`, params);
      await audit(request, 'admin.user_updated', { userId: user.id, changes: Object.keys(body), before: Object.fromEntries(Object.keys(body).map(k => [k, user[k]])) });
      return { user: publicUser(updated) };
    } catch (err) {
      if (err.code === '23505') throw Object.assign(new Error('that username or email is already in use'), { statusCode: 409 });
      throw err;
    }
  });

  app.post('/admin/v1/users/:id/suspend', async request => {
    const user = await userOr404(request.params.id);
    const { reason } = z.object({ reason: z.string().trim().min(3).max(1000) }).parse(request.body);
    await transaction(async db => {
      await db.query('UPDATE users SET suspended_at = now(), suspended_reason = $2, updated_at = now() WHERE id = $1', [user.id, reason]);
      await revokeEverything(db, user.id);
    });
    await audit(request, 'admin.user_suspended', { userId: user.id, reason });
    return { ok: true };
  });

  app.post('/admin/v1/users/:id/unsuspend', async request => {
    const user = await userOr404(request.params.id);
    await query('UPDATE users SET suspended_at = NULL, suspended_reason = NULL, updated_at = now() WHERE id = $1', [user.id]);
    await audit(request, 'admin.user_unsuspended', { userId: user.id });
    return { ok: true };
  });

  app.post('/admin/v1/users/:id/logout', async request => {
    const user = await userOr404(request.params.id);
    await transaction(db => revokeEverything(db, user.id));
    await audit(request, 'admin.user_logged_out', { userId: user.id });
    return { ok: true };
  });

  app.delete('/admin/v1/users/:id/sessions/:sid', async request => {
    const user = await userOr404(request.params.id);
    const sid = z.coerce.number().int().positive().parse(request.params.sid);
    await query('DELETE FROM sessions WHERE id = $1 AND user_id = $2', [sid, user.id]);
    await audit(request, 'admin.session_revoked', { userId: user.id, session: sid });
    return { ok: true };
  });

  app.post('/admin/v1/users/:id/reset-mfa', async request => {
    const user = await userOr404(request.params.id);
    await transaction(async db => {
      await db.query('UPDATE users SET totp_secret = NULL, totp_enabled_at = NULL, totp_last_step = NULL, updated_at = now() WHERE id = $1', [user.id]);
      await db.query('DELETE FROM recovery_codes WHERE user_id = $1', [user.id]);
      await revokeEverything(db, user.id);
    });
    await audit(request, 'admin.mfa_reset', { userId: user.id });
    return { ok: true };
  });

  app.delete('/admin/v1/users/:id/identities/:provider', async request => {
    const user = await userOr404(request.params.id);
    const provider = z.enum(['google', 'github', 'discord']).parse(request.params.provider);
    const removed = await query('DELETE FROM identities WHERE user_id = $1 AND provider = $2', [user.id, provider]);
    if (!removed.rowCount) throw notFound();
    await audit(request, 'admin.identity_unlinked', { userId: user.id, provider });
    return { ok: true };
  });

  app.post('/admin/v1/users/:id/password-reset', async request => {
    const user = await userOr404(request.params.id);
    if (!user.email) throw Object.assign(new Error('user has no email'), { statusCode: 400 });
    if (!mailEnabled()) throw Object.assign(new Error('email is not configured'), { statusCode: 503 });
    const token = random();
    await query("INSERT INTO email_tokens (token_hash, purpose, user_id, email, expires_at) VALUES ($1, 'reset', $2, $3, now() + interval '1 hour')", [digest(token), user.id, user.email]);
    await sendMail(request.log, { to: user.email, ...templates.reset(`${config.publicUrl}/reset?token=${token}`) });
    await audit(request, 'admin.password_reset_sent', { userId: user.id });
    return { ok: true };
  });

  app.delete('/admin/v1/users/:id/grants/:client', async request => {
    const user = await userOr404(request.params.id);
    const clientId = z.string().max(100).parse(request.params.client);
    await transaction(async db => {
      await db.query('DELETE FROM grants WHERE user_id = $1 AND client_id = $2', [user.id, clientId]);
      await db.query('UPDATE tokens SET revoked_at = now() WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL', [user.id, clientId]);
    });
    await audit(request, 'admin.grant_revoked', { userId: user.id, clientId });
    return { ok: true };
  });

  app.delete('/admin/v1/users/:id', async request => {
    const user = await userOr404(request.params.id);
    const { confirm } = z.object({ confirm: z.string() }).parse(request.body || {});
    if (confirm !== user.username) throw Object.assign(new Error('confirm must equal the username'), { statusCode: 400 });
    await transaction(async db => {
      await revokeEverything(db, user.id);
      await db.query('DELETE FROM users WHERE id = $1', [user.id]);
    });
    await audit(request, 'admin.user_deleted', { userId: user.id, username: user.username, email: user.email });
    return { ok: true };
  });

  // ---------- clients (the sites that sign in with Ward) ----------
  app.get('/admin/v1/clients', async () => {
    const rows = await query(`SELECT c.*, (SELECT count(*) FROM grants g WHERE g.client_id = c.id)::int AS users,
      (SELECT max(last_used_at) FROM grants g WHERE g.client_id = c.id) AS last_used_at FROM clients c ORDER BY c.created_at`);
    return { clients: rows.rows.map(publicClient) };
  });

  app.post('/admin/v1/clients', async (request, reply) => {
    const body = clientShape.parse(request.body);
    const id = `${body.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 30) || 'app'}-${random(6).toLowerCase().replace(/[^a-z0-9]/g, 'x')}`;
    const secret = body.confidential ? newClientSecret() : null;
    const row = await one(`INSERT INTO clients (id, name, secret_hash, redirect_uris, post_logout_redirect_uris, scopes, first_party, homepage_url)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [id, body.name, secret ? digest(secret) : null, body.redirect_uris, body.post_logout_redirect_uris, body.scopes, body.first_party, body.homepage_url || null]);
    await audit(request, 'admin.client_created', { clientId: id, name: body.name, first_party: body.first_party });
    // The secret exists in plaintext exactly once: in this response.
    return reply.code(201).send({ client: publicClient(row), client_secret: secret });
  });

  app.patch('/admin/v1/clients/:id', async request => {
    const id = z.string().max(100).parse(request.params.id);
    const body = clientShape.omit({ confidential: true }).partial().extend({ disabled: z.boolean().optional() }).strict().parse(request.body);
    const sets = [], params = [id];
    for (const [k, v] of Object.entries(body)) {
      if (k === 'disabled') { sets.push(`disabled_at = ${v ? 'coalesce(disabled_at, now())' : 'NULL'}`); continue; }
      params.push(v ?? null); sets.push(`${k} = $${params.length}`);
    }
    if (!sets.length) throw Object.assign(new Error('nothing to change'), { statusCode: 400 });
    const row = await one(`UPDATE clients SET ${sets.join(', ')}, updated_at = now() WHERE id = $1 RETURNING *`, params);
    if (!row) throw notFound();
    // Disabling a client kills every token it holds.
    if (body.disabled) await query('UPDATE tokens SET revoked_at = now() WHERE client_id = $1 AND revoked_at IS NULL', [id]);
    await audit(request, 'admin.client_updated', { clientId: id, changes: Object.keys(body) });
    return { client: publicClient(row) };
  });

  app.post('/admin/v1/clients/:id/rotate-secret', async request => {
    const id = z.string().max(100).parse(request.params.id);
    const secret = newClientSecret();
    const row = await one('UPDATE clients SET secret_hash = $2, secret_rotated_at = now(), updated_at = now() WHERE id = $1 AND secret_hash IS NOT NULL RETURNING *', [id, digest(secret)]);
    if (!row) throw Object.assign(new Error('no such confidential client'), { statusCode: 404 });
    await audit(request, 'admin.client_secret_rotated', { clientId: id });
    return { client: publicClient(row), client_secret: secret };
  });

  app.delete('/admin/v1/clients/:id', async request => {
    const id = z.string().max(100).parse(request.params.id);
    const { confirm } = z.object({ confirm: z.string() }).parse(request.body || {});
    if (confirm !== id) throw Object.assign(new Error('confirm must equal the client id'), { statusCode: 400 });
    const removed = await query('DELETE FROM clients WHERE id = $1', [id]);
    if (!removed.rowCount) throw notFound();
    await audit(request, 'admin.client_deleted', { clientId: id });
    return { ok: true };
  });

  // ---------- audit ----------
  app.get('/admin/v1/audit', async request => {
    const q = z.object({
      user_id: uuid.optional(), client_id: z.string().max(100).optional(), action: z.string().max(60).optional(),
      before: z.coerce.number().int().positive().optional(), limit: z.coerce.number().int().min(1).max(500).default(100),
    }).parse(request.query);
    const where = [], params = [];
    if (q.user_id) where.push(`user_id = $${params.push(q.user_id)}`);
    if (q.client_id) where.push(`client_id = $${params.push(q.client_id)}`);
    if (q.action) where.push(`action LIKE $${params.push(`${q.action.replace(/[\\%_]/g, c => `\\${c}`)}%`)}`);
    if (q.before) where.push(`id < $${params.push(q.before)}`);
    const rows = await query(`SELECT * FROM audit_log ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY id DESC LIMIT ${q.limit}`, params);
    return { entries: rows.rows };
  });
}
