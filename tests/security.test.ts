import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';

const k = () => randomBytes(32).toString('base64');
process.env.AES_KEY = k();
process.env.JWT_SECRET = k();
process.env.INDEX_KEY = k();

const { decrypt, encrypt } = await import('../src/lib/crypto.ts');
const { signToken, verifyToken } = await import('../src/lib/jwt.ts');
const { hotp, verifyTotp, generateSecret, base32Decode } = await import('../src/lib/totp.ts');
const { consume, clearAll } = await import('../src/lib/rate-limit.ts');
const { hashPassword, verifyPassword } = await import('../src/lib/password.ts');

test('AES-256-GCM round-trips and rejects tampering / wrong context', () => {
  const blob = encrypt('alice@example.com', 'user.email');
  assert.equal(decrypt(blob, 'user.email'), 'alice@example.com');
  assert.notEqual(blob, encrypt('alice@example.com', 'user.email'), 'random IV per call');
  assert.throws(() => decrypt(blob, 'user.totp'), 'AAD mismatch');
  const raw = Buffer.from(blob, 'base64url');
  raw[raw.length - 1] = (raw[raw.length - 1] ?? 0) ^ 1;
  assert.throws(() => decrypt(raw.toString('base64url'), 'user.email'), 'flipped bit');
});

test('JWT: valid, tampered, wrong type, expired, alg=none', () => {
  const { token } = signToken('u1', 'session', 60);
  assert.equal(verifyToken(token, 'session')?.sub, 'u1');
  assert.equal(verifyToken(token, 'mfa'), null, 'type confusion');
  const [h, b, s] = token.split('.') as [string, string, string];
  const forged = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(b, 'base64url').toString()), sub: 'admin' })).toString('base64url');
  assert.equal(verifyToken(`${h}.${forged}.${s}`, 'session'), null, 'payload tamper');
  const none = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  assert.equal(verifyToken(`${none}.${b}.`, 'session'), null, 'alg none');
  assert.equal(verifyToken(token, 'session', Date.now() + 61_000), null, 'expired');
});

test('TOTP matches RFC 6238 vector and rejects bad codes', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  assert.equal(hotp(secret, Math.floor(59 / 30)), '287082');
  assert.equal(verifyTotp(secret, '287082', 59_000), 1);
  assert.equal(verifyTotp(secret, '000000', 59_000), null);
  assert.equal(verifyTotp(secret, 'abcdef', 59_000), null);
  assert.equal(base32Decode(generateSecret()).length, 20);
});

test('rate limiter blocks after the limit and escalates the lockout', () => {
  clearAll();
  const t = 1_000_000;
  for (let i = 0; i < 3; i++) assert.equal(consume('k', 3, 60_000, t).allowed, true);
  const first = consume('k', 3, 60_000, t);
  assert.equal(first.allowed, false);
  assert.equal(first.retryAfterSec, 60);
  assert.equal(consume('k', 3, 60_000, t + 30_000).allowed, false, 'still locked');
  for (let i = 0; i < 3; i++) consume('k', 3, 60_000, t + 61_000);
  assert.equal(consume('k', 3, 60_000, t + 61_000).retryAfterSec, 120, 'second strike doubles');
});

test('scrypt password hashing verifies only the right password', async () => {
  const h = await hashPassword('Correct-Horse-9');
  assert.equal(await verifyPassword('Correct-Horse-9', h), true);
  assert.equal(await verifyPassword('wrong', h), false);
});
