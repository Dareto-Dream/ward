# Ward

One account for every DeltaVDevs site. Ward runs at `https://ward.deltavdevs.com`, and the blog, DeltaTime, SynthCity and anything later sign people in through it with OAuth 2.0 / OpenID Connect.

- **Sign in with** Google, GitHub, Discord, or email + password (email is confirmed by link before the account exists).
- **Two-factor** with any TOTP app, plus 10 single-use recovery codes. When 2FA is on, it's required after every sign-in method.
- **Account page:** profile, email change, password, link and unlink providers, 2FA, active sessions, connected apps, JSON export, delete.
- **For sites:** authorization code flow with PKCE, ES256 ID tokens, userinfo, refresh token rotation, revocation, introspection and RP-initiated logout.
- **Admin** lives in Telescreen (Ward → Accounts / Apps / Audit log), over `/admin/v1`.
- **Legal:** `/privacy` and `/terms`. New accounts record which version they agreed to. Bump `POLICY_VERSION` in `src/legal.js` when either changes.

Server-rendered HTML with no client JS. Styles come from `css.deltavdevs.com`.

## Signing a site in with Ward

1. In Telescreen, go to **Ward → Apps → Register app**. Add the site's exact callback URL(s) and tick **first-party** for our own sites, which marks them "Official DeltaVDevs app" on the consent screen. Every sign-in still shows that screen, so opening a link never signs anyone in by itself. Copy the `client_secret`; it's shown once.
2. Point the site at the discovery document: `https://ward.deltavdevs.com/.well-known/openid-configuration`.
3. Send people to `/oauth/authorize` with:
   - `response_type=code`, `client_id`, `redirect_uri`, `state`;
   - `scope=openid profile email` (add `offline_access` for a refresh token);
   - `code_challenge` with `code_challenge_method=S256`. **PKCE is required, even for confidential clients.**
4. On the callback:
   1. Check `state` and `iss`.
   2. POST to `/oauth/token` with `grant_type=authorization_code`, `code`, `redirect_uri`, `code_verifier`, using HTTP Basic auth with `client_id:client_secret`.
   3. Verify the `id_token` (ES256, keys from `jwks_uri`, `iss`, `aud`, `nonce`), or call `/oauth/userinfo` with the access token.
5. Key your own user records on `sub`, not email. `sub` is Ward's stable account id and never changes. Emails can change.

Claims by scope:

| scope | claims |
| --- | --- |
| `openid` | `sub`, `auth_time`, `amr` |
| `profile` | `name`, `preferred_username`, `picture`, `updated_at` |
| `email` | `email`, `email_verified` (Ward only stores verified emails, so it's always `true`) |

Tokens and lifetimes:

- Access tokens (`wat_…`) last 1 hour.
- Refresh tokens (`wrt_…`) last 30 days and rotate on every use. Presenting a used one revokes the whole chain.
- Codes last 2 minutes and are single-use. Replaying one revokes everything it issued.

For sign-out, send people to `/oauth/logout?client_id=…&post_logout_redirect_uri=…`. That URI has to be registered on the app.

## Security model

- **Stored secrets:** everything replayable (sessions, codes, tokens, client secrets, email links, recovery codes) is stored only as a sha256. Passwords use scrypt (N=2^15, r=8, p=3). TOTP secrets use AES-256-GCM under `WARD_ENCRYPTION_KEY`. TOTP codes can't be replayed.
- **Accounts are never merged by email.** A new Google, GitHub or Discord sign-in with an email that's already on an account is refused. The owner signs in and links the provider from their account page. Only provider-verified or link-confirmed emails are stored.
- **Enumeration:** sign-up, password reset and login respond the same whether or not an account exists, including timing.
- **Sensitive changes** (password, email, 2FA, linking, unlinking, deletion) need a sign-in from the last 15 minutes. Resetting a password or suspending an account ends every session and revokes every token.
- **Redirects:** redirect URIs match exactly. Unknown clients and bad redirects get an error page, never a redirect. `return_to` only accepts local paths.
- **Browser protections:** every form carries a CSRF token bound to a per-browser cookie, plus Origin and Sec-Fetch-Site checks. Cookies are `__Host-` and httpOnly. The CSP has no scripts at all, and `frame-ancestors 'none'` blocks framing.
- **Rate limits** (in Postgres) cover login, 2FA, sign-up, password reset, the token endpoint and admin auth.
- **Audit:** every security event is written to `audit_log`, shown in Telescreen, and logged to stdout.

## Setup

```sh
npm install
npm run keygen >> .env      # then fill in the rest from .env.example
npm run dev
TEST_PG_URL=postgres://… npm test   # a throwaway database: the tests truncate it
```

**Sign-in provider callbacks:** `${PUBLIC_URL}/auth/{google,github,discord}/callback`.

**Railway:** the `ward` service with `ward-postgres` (private network only) in the delta-v-devs project. `DATABASE_URL=${{ward-postgres.DATABASE_URL}}`. Migrations run on boot.
