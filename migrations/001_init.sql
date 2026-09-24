-- Ward: one account for every DeltaVDevs site.
-- Every secret-ish value (session, code, token, email link) is stored as a
-- sha256 digest, so a database leak can't be replayed against the live site.

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- Only ever holds an address someone proved they own (provider-verified or
  -- clicked a link). Unverified addresses never land here.
  email text,
  username text NOT NULL,
  display_name text NOT NULL,
  avatar_url text,
  password_hash text,
  password_changed_at timestamptz,
  totp_secret text,               -- AES-GCM sealed with WARD_ENCRYPTION_KEY
  totp_enabled_at timestamptz,
  totp_last_step bigint,          -- last accepted 30s step, so a code can't be replayed
  suspended_at timestamptz,
  suspended_reason text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz,
  CONSTRAINT username_shape CHECK (username ~ '^[a-z0-9_]{3,32}$'),
  CONSTRAINT email_shape CHECK (email IS NULL OR (length(email) <= 254 AND email = lower(email)))
);
CREATE UNIQUE INDEX users_email_key ON users (email) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX users_username_key ON users (username);

-- Linked Google / GitHub / Discord accounts. One per provider per user.
CREATE TABLE identities (
  id bigserial PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider text NOT NULL CHECK (provider IN ('google', 'github', 'discord')),
  subject text NOT NULL,
  email text,
  handle text,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  UNIQUE (provider, subject),
  UNIQUE (user_id, provider)
);

CREATE TABLE recovery_codes (
  id bigserial PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash bytea NOT NULL,
  used_at timestamptz
);
CREATE INDEX recovery_codes_user ON recovery_codes (user_id);

CREATE TABLE sessions (
  id bigserial PRIMARY KEY,
  token_hash bytea NOT NULL UNIQUE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  amr text[] NOT NULL,            -- how they proved it: pwd, otp, google, github, discord, email
  auth_time timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  ip text,
  user_agent text
);
CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expiry ON sessions (expires_at);

-- Email links: registration, password reset, email change.
CREATE TABLE email_tokens (
  token_hash bytea PRIMARY KEY,
  purpose text NOT NULL CHECK (purpose IN ('register', 'reset', 'email')),
  user_id uuid REFERENCES users(id) ON DELETE CASCADE,
  email text NOT NULL,
  data jsonb NOT NULL DEFAULT '{}',
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX email_tokens_expiry ON email_tokens (expires_at);

CREATE TABLE clients (
  id text PRIMARY KEY,
  name text NOT NULL,
  secret_hash bytea,              -- NULL = public client (PKCE only)
  redirect_uris text[] NOT NULL,
  post_logout_redirect_uris text[] NOT NULL DEFAULT '{}',
  scopes text[] NOT NULL DEFAULT '{openid,profile,email,offline_access}',
  first_party boolean NOT NULL DEFAULT false,
  homepage_url text,
  disabled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  secret_rotated_at timestamptz
);

-- What a user has agreed to share with a client.
CREATE TABLE grants (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id text NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  scopes text[] NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, client_id)
);

CREATE TABLE auth_codes (
  code_hash bytea PRIMARY KEY,
  family uuid NOT NULL DEFAULT gen_random_uuid(),
  client_id text NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  redirect_uri text NOT NULL,
  scopes text[] NOT NULL,
  code_challenge text NOT NULL,
  nonce text,
  amr text[] NOT NULL,
  auth_time timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  used_at timestamptz
);

-- Access and refresh tokens. A family is everything descended from one
-- authorization code, so replaying a code or a rotated refresh token can
-- burn the whole chain.
CREATE TABLE tokens (
  token_hash bytea PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('access', 'refresh')),
  family uuid NOT NULL,
  client_id text NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scopes text[] NOT NULL,
  amr text[] NOT NULL,
  auth_time timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  revoked_at timestamptz
);
CREATE INDEX tokens_family ON tokens (family);
CREATE INDEX tokens_user ON tokens (user_id);
CREATE INDEX tokens_expiry ON tokens (expires_at);

CREATE TABLE rate_limits (
  key text PRIMARY KEY,
  count integer NOT NULL,
  reset_at timestamptz NOT NULL
);

-- Not a foreign key on purpose: the trail outlives deleted accounts.
CREATE TABLE audit_log (
  id bigserial PRIMARY KEY,
  at timestamptz NOT NULL DEFAULT now(),
  actor text,
  user_id uuid,
  client_id text,
  action text NOT NULL,
  ip text,
  detail jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_user ON audit_log (user_id, at DESC);
CREATE INDEX audit_at ON audit_log (at DESC);
