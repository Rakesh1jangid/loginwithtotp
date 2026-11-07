import { randomBytes } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';

const target = '.env.local';
if (existsSync(target)) {
  console.error(`${target} already exists; refusing to overwrite (it would invalidate all stored data).`);
  process.exit(1);
}
const k = () => randomBytes(32).toString('base64');
writeFileSync(
  target,
  `AES_KEY=${k()}\nJWT_SECRET=${k()}\nINDEX_KEY=${k()}\nJWT_ISSUER=secure-login\nJWT_AUDIENCE=secure-login-app\n`,
  { mode: 0o600 },
);
console.log(`Wrote ${target} with fresh random keys. Back it up: losing AES_KEY makes stored data unrecoverable.`);
