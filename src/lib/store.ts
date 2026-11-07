import { randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { blindIndex, decrypt, encrypt } from './crypto.ts';

/**
 * Flat-file user store for a local server. Sensitive fields are AES-256-GCM encrypted;
 * the email is findable only via an HMAC blind index. Swap for a real DB in production.
 */
export interface UserRecord {
  id: string;
  emailIdx: string; // HMAC(email) for lookup
  emailEnc: string; // AES-GCM(email)
  passwordHash: string; // scrypt
  totpSecretEnc: string; // AES-GCM(base32 secret)
  totpConfirmed: boolean;
  lastTotpStep: number; // replay protection
  createdAt: string;
}

// FILE is a constant under cwd/data, never derived from user input.
/* eslint-disable security/detect-non-literal-fs-filename */
const FILE = path.join(process.cwd(), 'data', 'users.json');

// Serialises read-modify-write cycles so concurrent requests can't lose updates.
const g = globalThis as typeof globalThis & { __storeLock?: Promise<unknown> };

function locked<T>(fn: () => Promise<T>): Promise<T> {
  const run = (g.__storeLock ?? Promise.resolve()).then(fn, fn);
  g.__storeLock = run.catch(() => undefined);
  return run;
}

async function readAll(): Promise<UserRecord[]> {
  try {
    return JSON.parse(await readFile(FILE, 'utf8')) as UserRecord[];
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw e;
  }
}

async function writeAll(users: UserRecord[]): Promise<void> {
  await mkdir(path.dirname(FILE), { recursive: true });
  const tmp = `${FILE}.${randomUUID()}.tmp`;
  await writeFile(tmp, JSON.stringify(users, null, 2), { mode: 0o600 });
  await rename(tmp, FILE); // atomic replace: a crash never leaves a half-written file
}

export const normalizeEmail = (email: string) => email.trim().toLowerCase();

export async function findByEmail(email: string): Promise<UserRecord | undefined> {
  const idx = blindIndex(normalizeEmail(email));
  return (await readAll()).find((u) => u.emailIdx === idx);
}

export async function findById(id: string): Promise<UserRecord | undefined> {
  return (await readAll()).find((u) => u.id === id);
}

/** Returns null if the email is already registered. */
export function createUser(email: string, passwordHash: string, totpSecret: string): Promise<UserRecord | null> {
  return locked(async () => {
    const users = await readAll();
    const e = normalizeEmail(email);
    const idx = blindIndex(e);
    if (users.some((u) => u.emailIdx === idx)) return null;
    const user: UserRecord = {
      id: randomUUID(),
      emailIdx: idx,
      emailEnc: encrypt(e, 'user.email'),
      passwordHash,
      totpSecretEnc: encrypt(totpSecret, 'user.totp'),
      totpConfirmed: false,
      lastTotpStep: 0,
      createdAt: new Date().toISOString(),
    };
    users.push(user);
    await writeAll(users);
    return user;
  });
}

export function updateUser(id: string, patch: Partial<Pick<UserRecord, 'totpConfirmed' | 'lastTotpStep'>>): Promise<void> {
  return locked(async () => {
    const users = await readAll();
    const u = users.find((x) => x.id === id);
    if (!u) return;
    Object.assign(u, patch);
    await writeAll(users);
  });
}

export const readEmail = (u: UserRecord) => decrypt(u.emailEnc, 'user.email');
export const readTotpSecret = (u: UserRecord) => decrypt(u.totpSecretEnc, 'user.totp');
