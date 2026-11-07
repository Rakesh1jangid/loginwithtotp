import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { config } from './config.ts';

const VERSION = 1;
const IV_LEN = 12; // 96-bit nonce, recommended for GCM
const TAG_LEN = 16;

/**
 * AES-256-GCM authenticated encryption.
 * Output: base64url( version(1) | iv(12) | tag(16) | ciphertext ).
 * `aad` binds the ciphertext to a context (e.g. field name) so blobs can't be swapped between fields.
 */
export function encrypt(plaintext: string, aad: string): string {
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv('aes-256-gcm', config().aesKey, iv, { authTagLength: TAG_LEN });
  cipher.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return Buffer.concat([Buffer.from([VERSION]), iv, cipher.getAuthTag(), ct]).toString('base64url');
}

/** Throws if the blob was tampered with, the key is wrong, or the AAD differs. */
export function decrypt(blob: string, aad: string): string {
  const buf = Buffer.from(blob, 'base64url');
  if (buf.length < 1 + IV_LEN + TAG_LEN || buf[0] !== VERSION) throw new Error('Malformed ciphertext');
  const iv = buf.subarray(1, 1 + IV_LEN);
  const tag = buf.subarray(1 + IV_LEN, 1 + IV_LEN + TAG_LEN);
  const ct = buf.subarray(1 + IV_LEN + TAG_LEN);
  const decipher = createDecipheriv('aes-256-gcm', config().aesKey, iv, { authTagLength: TAG_LEN });
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

/** Deterministic keyed hash so a user can be looked up by email without storing it in the clear. */
export function blindIndex(value: string): string {
  return createHmac('sha256', config().indexKey).update(value).digest('base64url');
}

/** Constant-time comparison. Length mismatch returns early; lengths here are not secret. */
export function safeEqual(a: string | Buffer, b: string | Buffer): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
