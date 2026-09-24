// Prints fresh secrets for a new Ward deployment. Nothing is written to disk.
//   npm run keygen
import { generateKeyPairSync, randomBytes } from 'node:crypto';

const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString().trim();

console.log(`WARD_SECRET=${randomBytes(48).toString('base64url')}`);
console.log(`WARD_ENCRYPTION_KEY=${randomBytes(32).toString('base64')}`);
console.log(`WARD_ADMIN_KEY=${randomBytes(32).toString('base64url')}`);
// One line with literal \n so it pastes into a Railway variable.
console.log(`WARD_SIGNING_KEY=${pem.replace(/\n/g, '\\n')}`);
