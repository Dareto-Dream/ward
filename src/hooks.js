// Tells Hooks when something worth a Discord post happens (hooks.deltavdevs.com, automations decide what to do with it).
// Fire and forget: Hooks being down never slows or fails a request here, and nothing is queued. Off until HOOKS_KEY is set.
const SOURCE = 'ward';
const url = String(process.env.HOOKS_URL || 'https://hooks.deltavdevs.com').replace(/\/+$/, '');
const key = process.env.HOOKS_KEY || '';

export function announce(kind, title, fields = {}, body = '') {
  if (!key) return;
  const clean = Object.fromEntries(Object.entries(fields).filter(([, v]) => v !== undefined && v !== null && v !== '').map(([k, v]) => [k, typeof v === 'object' ? JSON.stringify(v).slice(0, 900) : typeof v === 'string' ? v.slice(0, 900) : v]));
  fetch(`${url}/v1/events`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ source: SOURCE, kind, title: String(title).slice(0, 200), body, fields: clean }),
    redirect: 'error', signal: AbortSignal.timeout(5000),
  }).catch(() => {});
}
