import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';
import helmet from '@fastify/helmet';
import staticFiles from '@fastify/static';
import { fileURLToPath } from 'node:url';
import { ZodError } from 'zod';
import { config, assertConfig } from './config.js';
import { pool, migrate, sweep } from './db.js';
import { jwks } from './keys.js';
import { loginRoutes } from './routes/login.js';
import { accountRoutes } from './routes/account.js';
import { oauthRoutes } from './routes/oauth.js';
import { adminRoutes } from './routes/admin.js';
import { legalRoutes } from './legal.js';
import { errorPage } from './views.js';

const THEME = 'https://css.deltavdevs.com';
const AVATARS = ['https://lh3.googleusercontent.com', 'https://avatars.githubusercontent.com', 'https://cdn.discordapp.com'];

export async function buildApp(options = {}) {
  assertConfig();
  jwks(); // load the signing key now so a bad one fails the boot, not the first login
  const app = Fastify({ logger: options.logger ?? { level: 'info', redact: ['req.headers.authorization', 'req.headers.cookie'] }, trustProxy: true, bodyLimit: 64 * 1024 });

  await app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        scriptSrc: ["'none'"],
        styleSrc: ["'self'", THEME, 'https://fonts.googleapis.com'],
        fontSrc: [THEME, 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:', ...AVATARS],
        connectSrc: ["'none'"],
        // Forms post here, and /oauth/authorize then redirects to a client —
        // Chrome applies form-action to that redirect, so leave it open to https.
        formAction: ["'self'", 'https:', ...(config.production ? [] : ['http://localhost:*', 'http://127.0.0.1:*'])],
        frameAncestors: ["'none'"],
        baseUri: ["'none'"],
        upgradeInsecureRequests: config.production ? [] : null,
      },
    },
    // same-origin, not no-referrer: with no-referrer Chrome sends `Origin: null` on
    // form POSTs and the CSRF origin check can't tell us apart from an attacker.
    // Cross-origin requests still get no Referer, so ?token= links never leak.
    referrerPolicy: { policy: 'same-origin' },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: 'same-site' },
    hsts: config.production ? { maxAge: 63072000, includeSubDomains: false } : false,
  });
  await app.register(cookie);
  await app.register(formbody, { bodyLimit: 16 * 1024 });
  app.addHook('onSend', async (request, reply) => {
    if (!reply.getHeader('Cache-Control')) reply.header('Cache-Control', 'no-store');
    reply.header('X-Robots-Tag', 'noindex');
  });

  app.setErrorHandler((error, request, reply) => {
    const api = request.url.startsWith('/admin/') || request.url.startsWith('/oauth/token') || request.url.startsWith('/oauth/userinfo');
    if (error instanceof ZodError) return reply.code(400).send({ error: error.issues.map(i => `${i.path.join('.') || 'body'}: ${i.message}`).join('; ') });
    const status = error.statusCode && error.statusCode >= 400 ? error.statusCode : 500;
    if (status >= 500) request.log.error(error);
    if (api) return reply.code(status).send({ error: status >= 500 ? 'server_error' : error.message });
    return errorPage(reply, status, status >= 500 ? 'Something broke' : 'That didn’t work', status >= 500 ? 'Ward hit an error. Try again in a moment.' : error.message);
  });
  app.setNotFoundHandler((request, reply) => (request.url.startsWith('/admin/') ? reply.code(404).send({ error: 'not found' }) : errorPage(reply, 404, 'Not found', 'There’s nothing here.')));

  app.get('/health', async () => { await pool.query('SELECT 1'); return { ok: true }; });
  app.get('/', async (_request, reply) => reply.redirect('/account'));

  await app.register(staticFiles, {
    root: fileURLToPath(new URL('../public', import.meta.url)),
    index: false,
    wildcard: false,
    cacheControl: false,
    // @fastify/static v10 passes Fastify's reply here, rather than Node's
    // ServerResponse. Calling setHeader made every static asset fail as a 500.
    setHeaders: reply => reply.header('Cache-Control', 'public, max-age=3600'),
  });
  await app.register(oauthRoutes);
  await app.register(loginRoutes);
  await app.register(accountRoutes);
  await app.register(adminRoutes);
  await app.register(legalRoutes);

  app.addHook('onClose', async () => { await pool.end(); });
  return app;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  assertConfig();
  await migrate();
  const app = await buildApp();
  const timer = setInterval(() => sweep().catch(err => app.log.error({ err: err.message }, 'sweep failed')), 15 * 60_000);
  timer.unref();
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => { clearInterval(timer); app.close().then(() => process.exit(0)); });
  await app.listen({ port: config.port, host: '0.0.0.0' });
}
