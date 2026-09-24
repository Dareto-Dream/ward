import { config } from './config.js';

// Server-rendered pages, no client JS. html`` escapes every interpolation
// unless it's already Html (nested templates) — so user data can't inject markup.
class Html {
  constructor(value) { this.value = value; }
  toString() { return this.value; }
}

const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ESC[c]);

function render(value) {
  if (value === null || value === undefined || value === false) return '';
  if (value instanceof Html) return value.value;
  if (Array.isArray(value)) return value.map(render).join('');
  return escape(value);
}

export const html = (strings, ...values) => new Html(strings.reduce((out, s, i) => out + s + (i < values.length ? render(values[i]) : ''), ''));
export const raw = value => new Html(String(value));

export const PROVIDERS = { google: 'Google', github: 'GitHub', discord: 'Discord' };

export function page({ title, body, user = null, wide = false }) {
  return `<!DOCTYPE html>${html`<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="theme-color" content="#000000" />
  <meta name="referrer" content="same-origin" />
  <title>${title ? `${title} · Ward` : 'Ward'}</title>
  <link rel="stylesheet" href="https://css.deltavdevs.com/theme.css" />
  <link rel="stylesheet" href="https://css.deltavdevs.com/fonts.css" />
  <link rel="stylesheet" href="/ward.css" />
  <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
</head>
<body>
  <header class="top">
    <a class="brand" href="${user ? '/account' : '/login'}"><span class="brand-mark">◈</span> Ward</a>
    ${user ? html`<form method="post" action="/logout" class="top-out"><input type="hidden" name="_csrf" value="${user.csrf}" /><span class="caption">${user.display_name}</span><button class="outline small" type="submit">Sign out</button></form>` : ''}
  </header>
  <main class="${wide ? 'wrap wide' : 'wrap'}">${body}</main>
  <footer class="foot caption">One account for every DeltaVDevs site · <a href="/privacy">Privacy</a> · <a href="/terms">Terms</a> · <a href="${config.publicUrl}/.well-known/openid-configuration">OIDC</a></footer>
</body>
</html>`}`;
}

export const notice = (message, kind = 'error') => (message ? html`<p class="notice ${kind}" role="${kind === 'error' ? 'alert' : 'status'}">${message}</p>` : '');
export const csrfField = token => html`<input type="hidden" name="_csrf" value="${token}" />`;

export function send(reply, status, options) {
  return reply.code(status).type('text/html; charset=utf-8').send(page(options));
}

export const errorPage = (reply, status, title, message) =>
  send(reply, status, { title, body: html`<section class="card narrow"><p class="eyebrow">ward</p><h1 class="headline">${title}</h1><p>${message}</p><p><a href="/account">Back to your account</a></p></section>` });
