import pg from 'pg';
import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { config } from './config.js';

export const pool = new pg.Pool({
  connectionString: config.databaseUrl,
  max: 10,
  connectionTimeoutMillis: 5000,
  statement_timeout: 15_000,
  application_name: 'ward',
});
pool.on('error', () => {});

export const query = (text, params) => pool.query(text, params);
export const one = async (text, params) => (await pool.query(text, params)).rows[0] || null;

export async function transaction(work) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// Plain numbered .sql files, applied once each, under an advisory lock so two
// replicas booting together don't race.
export async function migrate() {
  const dir = fileURLToPath(new URL('../migrations', import.meta.url));
  const files = (await readdir(dir)).filter(f => /^\d+_.+\.sql$/.test(f)).sort();
  const client = await pool.connect();
  try {
    await client.query('SELECT pg_advisory_lock(726172647)');
    await client.query('CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())');
    const done = new Set((await client.query('SELECT name FROM schema_migrations')).rows.map(r => r.name));
    for (const file of files) {
      if (done.has(file)) continue;
      const sql = await readFile(`${dir}/${file}`, 'utf8');
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (name) VALUES ($1)', [file]);
        await client.query('COMMIT');
      } catch (err) {
        await client.query('ROLLBACK');
        throw new Error(`migration ${file} failed: ${err.message}`);
      }
    }
  } finally {
    await client.query('SELECT pg_advisory_unlock(726172647)').catch(() => {});
    client.release();
  }
}

// Fixed-window counter. Returns true once `key` has been hit more than `max`
// times inside the window.
export async function limited(key, max, windowSeconds) {
  const row = await one(`INSERT INTO rate_limits (key, count, reset_at) VALUES ($1, 1, now() + make_interval(secs => $2))
    ON CONFLICT (key) DO UPDATE SET
      count = CASE WHEN rate_limits.reset_at < now() THEN 1 ELSE rate_limits.count + 1 END,
      reset_at = CASE WHEN rate_limits.reset_at < now() THEN now() + make_interval(secs => $2) ELSE rate_limits.reset_at END
    RETURNING count`, [key, windowSeconds]);
  return row.count > max;
}

export const clearLimit = key => query('DELETE FROM rate_limits WHERE key = $1', [key]);

export async function sweep() {
  await query('DELETE FROM sessions WHERE expires_at < now()');
  await query("DELETE FROM tokens WHERE expires_at < now() - interval '1 day'");
  await query("DELETE FROM auth_codes WHERE expires_at < now() - interval '1 day'");
  await query('DELETE FROM email_tokens WHERE expires_at < now()');
  await query('DELETE FROM rate_limits WHERE reset_at < now()');
  await query("DELETE FROM audit_log WHERE at < now() - interval '400 days'");
}
