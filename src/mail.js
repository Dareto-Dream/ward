import { config } from './config.js';

// Resend over plain fetch. Without a key, local dev prints the mail to stdout
// so links can be clicked from the terminal; production refuses instead
// (see mailEnabled in config.js).
export async function sendMail(log, { to, subject, text }) {
  if (!config.mail.resendKey) {
    if (config.production) throw new Error('email is not configured');
    log.info({ mail: { to, subject, text } }, 'mail (dev, not sent)');
    return;
  }
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${config.mail.resendKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: config.mail.from, to: [to], subject, text }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) {
    log.error({ status: response.status, body: (await response.text()).slice(0, 300) }, 'resend rejected mail');
    throw new Error('mail send failed');
  }
}

const footer = '\n\nIf this wasn\'t you, ignore this email. Nobody at DeltaVDevs will ever ask you for this link.\n— Ward, DeltaVDevs accounts';

export const templates = {
  register: link => ({
    subject: 'Finish creating your Ward account',
    text: `Click to confirm your email and finish signing up:\n\n${link}\n\nThe link works once and expires in 1 hour.${footer}`,
  }),
  alreadyRegistered: link => ({
    subject: 'You already have a Ward account',
    text: `Someone (hopefully you) tried to sign up with this email, but it already has a Ward account.\n\nSign in: ${config.publicUrl}/login\nForgot your password? ${link}${footer}`,
  }),
  reset: link => ({
    subject: 'Reset your Ward password',
    text: `Click to choose a new password:\n\n${link}\n\nThe link works once and expires in 1 hour. Resetting signs you out everywhere.${footer}`,
  }),
  changeEmail: link => ({
    subject: 'Confirm your new Ward email',
    text: `Click to make this your Ward email address:\n\n${link}\n\nThe link works once and expires in 1 hour.${footer}`,
  }),
  emailChanged: newEmail => ({
    subject: 'Your Ward email was changed',
    text: `The email on your Ward account was changed to ${newEmail}.${footer.replace('ignore this email', 'reset your password right away')}`,
  }),
};
