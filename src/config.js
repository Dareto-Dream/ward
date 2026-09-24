// Everything Ward needs comes from the environment. See .env.example.
const env = process.env;
const production = env.NODE_ENV === 'production';
const trim = v => (v || '').replace(/\/+$/, '');

const publicUrl = trim(env.PUBLIC_URL) || `http://localhost:${env.PORT || 3000}`;

const provider = (id, secret) => (env[id] && env[secret] ? { id: env[id], secret: env[secret] } : null);

export const config = {
  production,
  port: Number(env.PORT || 3000),
  publicUrl,
  issuer: publicUrl,
  origin: new URL(publicUrl).origin,
  databaseUrl: env.DATABASE_URL || '',
  // Signs cookies (CSRF, pending sign-ins). Rotating it only interrupts
  // sign-ins in progress; sessions live in Postgres.
  secret: env.WARD_SECRET || '',
  // Seals TOTP secrets at rest. Rotating this breaks every enrolled authenticator.
  encryptionKey: env.WARD_ENCRYPTION_KEY || '',
  // ES256 private key (PKCS8 PEM) that signs ID tokens. PREVIOUS stays in the
  // JWKS during a rotation so tokens already out there still verify.
  signingKey: (env.WARD_SIGNING_KEY || '').replace(/\\n/g, '\n'),
  previousSigningKey: (env.WARD_SIGNING_KEY_PREVIOUS || '').replace(/\\n/g, '\n'),
  // Telescreen's key for /admin/v1.
  adminKey: env.WARD_ADMIN_KEY || '',
  sessionDays: Math.min(Math.max(Number(env.SESSION_DAYS || 30), 1), 90),
  accessTokenMinutes: 60,
  refreshTokenDays: 30,
  providers: {
    google: provider('GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'),
    github: provider('GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET'),
    discord: provider('DISCORD_CLIENT_ID', 'DISCORD_CLIENT_SECRET'),
  },
  mail: {
    resendKey: env.RESEND_API_KEY || '',
    from: env.MAIL_FROM || 'Ward <ward@deltavdevs.com>',
  },
  // Check new passwords against Have I Been Pwned (k-anonymity, only 5 hash chars leave).
  breachCheck: env.PASSWORD_BREACH_CHECK !== 'off',
};

export const mailEnabled = () => Boolean(config.mail.resendKey) || !config.production;

// Fail closed: an identity provider with weak or missing keys must not boot.
export function assertConfig() {
  const problems = [];
  if (!config.databaseUrl) problems.push('DATABASE_URL is required');
  if (config.secret.length < 32) problems.push('WARD_SECRET must be at least 32 characters');
  if (Buffer.from(config.encryptionKey, 'base64').length !== 32) problems.push('WARD_ENCRYPTION_KEY must be 32 bytes, base64 (openssl rand -base64 32)');
  if (!config.signingKey.includes('PRIVATE KEY')) problems.push('WARD_SIGNING_KEY must be an ES256 PKCS8 PEM (npm run keygen)');
  if (config.adminKey && config.adminKey.length < 32) problems.push('WARD_ADMIN_KEY must be at least 32 characters');
  if (config.production && !config.publicUrl.startsWith('https://')) problems.push('PUBLIC_URL must be https in production');
  if (problems.length) throw new Error(`ward refuses to start:\n - ${problems.join('\n - ')}`);
}
