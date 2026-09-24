import { query } from './db.js';

// Every security-relevant event goes to the audit_log table (Telescreen reads
// it) and to stdout as JSON (Railway logs), so there's a trail even if one of
// them is down.
export async function audit(request, action, { actor, userId = null, clientId = null, ...detail } = {}) {
  const who = actor ?? request.admin ?? (request.user ? `user:${request.user.id}` : null);
  request.log.info({ audit: true, action, actor: who, user: userId, client: clientId, ip: request.ip, ...detail }, `audit ${action}`);
  await query('INSERT INTO audit_log (actor, user_id, client_id, action, ip, detail) VALUES ($1, $2, $3, $4, $5, $6)',
    [who, userId, clientId, action, request.ip, detail]).catch(err => request.log.error({ err: err.message }, 'audit write failed'));
}
