import { html, send } from './views.js';
import { loadSession, csrfToken } from './session.js';
import { config } from './config.js';

// Bump this when either document changes materially. New accounts record the
// version they agreed to (users.terms_version / privacy_version).
export const POLICY_VERSION = '2026-09-24';
const EFFECTIVE = 'September 24, 2026';

const contact = html`<a href="mailto:contact@deltavdevs.com">contact@deltavdevs.com</a>`;

export const agreement = html`<label class="agree"><input type="checkbox" name="accept_policies" value="${POLICY_VERSION}" required />
  <span>I agree to the <a href="/terms" target="_blank" rel="noopener">Terms of Service</a> and have read the <a href="/privacy" target="_blank" rel="noopener">Privacy Policy</a>.</span></label>`;

export const accepted = body => body?.accept_policies === POLICY_VERSION;

const privacy = () => html`
<p>Ward is the sign-in service for DeltaVDevs sites, including the blog, DeltaTime and SynthCity. It is run by DeltaVDevs, the independent developer publishing as DeltaVortex. This policy covers Ward itself at <code>${config.publicUrl.replace(/^https?:\/\//, '')}</code>. Each site you sign into with Ward also has its own policy for what it does with your data. For privacy questions or requests, contact ${contact}.</p>

<h2>What Ward stores</h2>
<p><strong>Your account:</strong> a random account ID, display name, username, profile picture link, and email address. Ward only stores an email once you've proven it's yours, either by clicking a link we sent or because Google, GitHub or Discord says it's verified. We also store when you created the account and last signed in, and which version of these policies you agreed to.</p>
<p><strong>Sign-in methods:</strong> if you use Google, GitHub or Discord, we store that provider's ID for your account, plus the username and verified email it reports. If you set a password, we store a salted scrypt hash, never the password. If you turn on two-factor authentication, we store your authenticator secret encrypted, and your recovery codes as hashes.</p>
<p><strong>Sessions and security records:</strong> for each browser you're signed into, we store the IP address, browser user-agent, sign-in time, method used and last activity. We also keep an activity log of security events such as sign-ins, failed attempts, password and 2FA changes, and apps connected or disconnected, with the IP address involved.</p>
<p><strong>Connected apps:</strong> which DeltaVDevs sites you've let use your Ward account, what they can see, and the access tokens issued to them. Tokens are stored as hashes.</p>

<h2>What sites you sign into receive</h2>
<p>When you sign into a site with Ward, it receives only what it asked for and you allowed. That can include your account ID, display name, username, profile picture, and verified email. Ward never shares your password, 2FA secret, recovery codes, IP history or other connected apps. Each site uses that information under its own privacy policy. You can see and disconnect connected sites from your account page at any time.</p>

<h2>Why we use it</h2>
<p>We use this information to sign you in, keep your account secure, let you use one account across DeltaVDevs sites, detect and stop abuse such as password guessing and account takeover, and answer your requests. Where data protection law requires a legal basis, we rely on providing the service you asked for, our legitimate interest in running and securing it, and legal obligations where they apply. We don't sell personal information, show ads, or use tracking or analytics cookies.</p>

<h2>Other services involved</h2>
<p>Ward runs on Railway, and its data is stored in a PostgreSQL database there. Account emails such as confirmation, password reset and change notices are sent through Resend. When you choose a new password, the first five characters of its SHA-1 hash are checked against the Have I Been Pwned breach list. Your password itself and its full hash never leave Ward. If you sign in with Google, GitHub or Discord, that provider processes your sign-in under its own privacy policy. Pages load stylesheets and fonts from DeltaVDevs and Google Fonts, and show profile pictures from the provider that hosts them. Your data may be processed outside your country, with protections required by applicable law.</p>

<h2>Cookies</h2>
<p>Ward only uses cookies it needs to work:</p>
<ul>
<li>a session cookie that keeps you signed in for up to ${config.sessionDays} days;</li>
<li>a browser cookie that protects forms against cross-site request forgery;</li>
<li>short-lived cookies, lasting at most 15 minutes, that hold a sign-in, 2FA setup or sign-up that's in progress.</li>
</ul>
<p>There are no advertising or analytics cookies.</p>

<h2>How long we keep it</h2>
<p>Account information is kept while your account exists. Sessions end when you sign out or after ${config.sessionDays} days. Access tokens expire after an hour, and refresh tokens after ${config.refreshTokenDays} days without use. Email links expire after an hour. The security activity log is kept for about 13 months, and it stays after an account is deleted so we can investigate abuse. Server logs and any backups follow our hosting provider's rotation.</p>

<h2>Your choices and rights</h2>
<p>From your account page you can:</p>
<ul>
<li>edit your profile;</li>
<li>change your email or password;</li>
<li>link or unlink sign-in methods;</li>
<li>turn two-factor authentication on or off;</li>
<li>sign out other browsers;</li>
<li>disconnect sites;</li>
<li>download everything Ward stores about you as JSON;</li>
<li>delete your account.</li>
</ul>
<p>Deleting your Ward account removes your profile, sign-in methods, sessions and connected-site permissions, and ends every site's access. It does not delete data a site stored itself, so ask that site separately. You can also contact ${contact} to request access, correction, export or deletion. Depending on where you live, you may have further rights, such as objecting to or restricting processing, and complaining to your local data protection authority. We may need to confirm a request is really from you. We will never ask for your password, 2FA code or recovery codes.</p>

<h2>Security</h2>
<p>We use hashed credentials, encrypted 2FA secrets, single-use and short-lived sign-in codes, rate limits, and optional two-factor authentication. No internet service can promise perfect security. If we learn of a breach that affects you, we will tell you as the law requires.</p>

<h2>Children</h2>
<p>Ward accounts are not for children under 13, or under the minimum age where you live. If you think a child has created an account, contact ${contact} and we'll look into it and remove it where appropriate.</p>

<h2>Changes</h2>
<p>Changes are dated on this page. If a change is material, we'll give notice and, where required, ask you to agree again. Questions go to ${contact}.</p>`;

const terms = () => html`
<p>These terms cover Ward, the account and sign-in service for DeltaVDevs sites, run by DeltaVDevs, the independent developer publishing as DeltaVortex. To create a Ward account, you must agree to these terms and acknowledge the <a href="/privacy">Privacy Policy</a>. Each site you sign into with Ward may have its own terms as well, and those apply when you use that site. Questions go to ${contact}.</p>

<h2>Your account</h2>
<p>You must be at least 13, or older if the law where you live requires it. If local law requires a parent or guardian's permission, get it first. One person, one account: don't impersonate anyone, and use only email addresses and sign-in providers that are yours.</p>
<p>Keep your password, authenticator and recovery codes safe. You're responsible for what happens through your account. If you think someone else has access, change your password, sign out other browsers from your account page, and contact us. If you lose every way to sign in, including your password, linked providers and 2FA recovery codes, we may not be able to restore your account.</p>

<h2>Signing into sites</h2>
<p>Ward lets you sign into DeltaVDevs sites and share the profile details you choose. Signing into a site with Ward doesn't give you any particular rights on that site. Each site decides what you can do there, and may restrict your access under its own rules. You can disconnect a site from your account page at any time.</p>

<h2>Acceptable use</h2>
<p>Don't:</p>
<ul>
<li>try to get into accounts that aren't yours;</li>
<li>guess passwords or codes, or test stolen credentials;</li>
<li>get around rate limits or security checks;</li>
<li>probe for vulnerabilities outside responsible disclosure;</li>
<li>create accounts in bulk or by automation;</li>
<li>use Ward to harass, defraud or impersonate anyone.</li>
</ul>
<p>If you find a security issue, report it privately to ${contact}. Please give us a chance to fix it before telling anyone else.</p>

<h2>Suspension and ending your account</h2>
<p>We may suspend or remove an account that breaks these terms, puts others or the service at risk, or when the law requires it. A suspended account can't sign into any DeltaVDevs site. To appeal, contact ${contact}. You can delete your account from your account page at any time.</p>

<h2>Availability</h2>
<p>Ward is provided as is and as available. It may change, pause or have outages, and we don't guarantee uninterrupted or error-free service. If Ward is down, you may not be able to sign into sites that depend on it. To the extent the law allows, we disclaim implied warranties and aren't liable for indirect or consequential losses from using Ward. Nothing here limits responsibility that the law doesn't allow us to exclude, including your consumer rights.</p>

<h2>Changes and disputes</h2>
<p>Changes are dated on this page. For material changes, we'll give notice and ask you to agree again where required. Your account records which version you accepted. If something goes wrong, contact ${contact} and we'll try to sort it out. These terms don't require arbitration or take away protections you have under applicable law.</p>`;

function legalPage(reply, user, kind) {
  return send(reply, 200, {
    title: kind === 'privacy' ? 'Privacy Policy' : 'Terms of Service',
    user,
    body: html`<article class="card legal">
      <p class="eyebrow">deltavdevs / ward</p>
      <h1 class="headline">${kind === 'privacy' ? 'Privacy Policy' : 'Terms of Service'}</h1>
      <p class="caption">Effective ${EFFECTIVE} · Version ${POLICY_VERSION}</p>
      <nav class="row caption"><a href="/privacy" ${kind === 'privacy' ? html`aria-current="page"` : ''}>Privacy Policy</a> · <a href="/terms" ${kind === 'terms' ? html`aria-current="page"` : ''}>Terms of Service</a></nav>
      ${kind === 'privacy' ? privacy() : terms()}
    </article>`,
  });
}

export async function legalRoutes(app) {
  for (const kind of ['privacy', 'terms']) {
    app.get(`/${kind}`, async (request, reply) => {
      const user = await loadSession(request);
      return legalPage(reply, user && { ...user, csrf: csrfToken(request, reply) }, kind);
    });
  }
}
