import { createPrivateKey, createPublicKey, createHash, sign } from 'node:crypto';
import { config } from './config.js';

// ID tokens are ES256 JWTs. The kid is the RFC 7638 thumbprint of the public
// key, so it changes automatically when the key does.
function load(pem) {
  const privateKey = createPrivateKey(pem);
  if (privateKey.asymmetricKeyType !== 'ec' || privateKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw new Error('Ward signing keys must be EC P-256');
  const { kty, crv, x, y } = createPublicKey(privateKey).export({ format: 'jwk' });
  const kid = createHash('sha256').update(JSON.stringify({ crv, kty, x, y })).digest('base64url');
  return { privateKey, jwk: { kty, crv, x, y, kid, use: 'sig', alg: 'ES256' } };
}

let current = null, previous = null;
function keys() {
  if (!current) {
    current = load(config.signingKey);
    previous = config.previousSigningKey ? load(config.previousSigningKey) : null;
  }
  return { current, previous };
}

export const jwks = () => {
  const { current, previous } = keys();
  return { keys: [current.jwk, ...(previous ? [previous.jwk] : [])] };
};

const b64 = value => Buffer.from(JSON.stringify(value)).toString('base64url');

export function signJwt(claims) {
  const { current } = keys();
  const input = `${b64({ alg: 'ES256', typ: 'JWT', kid: current.jwk.kid })}.${b64(claims)}`;
  const signature = sign('sha256', Buffer.from(input), { key: current.privateKey, dsaEncoding: 'ieee-p1363' });
  return `${input}.${signature.toString('base64url')}`;
}

// OIDC at_hash: left half of sha256(access_token), base64url.
export const atHash = token => createHash('sha256').update(token).digest().subarray(0, 16).toString('base64url');
