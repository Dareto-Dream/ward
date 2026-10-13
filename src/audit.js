import { query } from './db.js';
import { announce } from './hooks.js';

// Only the ones a person would want pinged about; everything still lands in audit_log.
const WORTH = {
  'user.registered': 'New Ward account', 'user.deleted': 'Account deleted', 'login.suspended': 'Suspended account tried to sign in',
  'mfa.disabled': 'Two-factor turned off', 'password.reset': 'Password reset', 'oauth.code_replay': 'Auth code replay blocked', 'oauth.refresh_replay': 'Refresh token replay blocked',
  'admin.level_changed': 'Staff level changed', 'admin.user_suspended': 'Account suspended', 'admin.user_unsuspended': 'Account unsuspended', 'admin.user_deleted': 'Account deleted by staff',
  'admin.mfa_reset': 'Two-factor reset by staff', 'admin.client_created': 'Ward app created', 'admin.client_deleted': 'Ward app deleted', 'admin.client_secret_rotated': 'Ward app secret rotated',
};

// Every security-relevant event goes to the audit_log table (Telescreen reads
// it) and to stdout as JSON (Railway logs), so there's a trail even if one of
// them is down.
export async function audit(request, action, { actor, userId = null, clientId = null, ...detail } = {}) {
  const who = actor ?? request.admin ?? (request.user ? `user:${request.user.id}` : null);
  request.log.info({ audit: true, action, actor: who, user: userId, client: clientId, ip: request.ip, ...detail }, `audit ${action}`);
  if (WORTH[action]) announce(action, `${WORTH[action]}${detail.username ? `: ${detail.username}` : ''}`, { Actor: who, ...detail });
  await query('INSERT INTO audit_log (actor, user_id, client_id, action, ip, detail) VALUES ($1, $2, $3, $4, $5, $6)',
    [who, userId, clientId, action, request.ip, detail]).catch(err => request.log.error({ err: err.message }, 'audit write failed'));
}
