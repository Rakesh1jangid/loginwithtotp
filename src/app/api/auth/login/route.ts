import type { NextRequest } from 'next/server';
import { dummyHash, verifyPassword } from '@/lib/password';
import { assertSameOriginJson, clientIp, json, parseBody, tooMany } from '@/lib/http';
import { blindIndex } from '@/lib/crypto';
import { consume } from '@/lib/rate-limit';
import { cookieOptions, issue, MFA_COOKIE } from '@/lib/session';
import { findByEmail } from '@/lib/store';
import { loginSchema } from '@/lib/validation';

export const runtime = 'nodejs';

const WINDOW = 15 * 60_000;

/** Step 1 of 2: verify password, then hand out a short-lived, single-use MFA challenge cookie. */
export async function POST(req: NextRequest) {
  const bad = assertSameOriginJson(req);
  if (bad) return bad;

  const body = await parseBody(req, loginSchema);
  if ('error' in body) return body.error;
  const { email, password } = body.data;

  // Two independent limits: per source IP (spraying) and per target account (brute force / stuffing).
  const ipRl = consume(`login:ip:${clientIp(req)}`, 20, WINDOW);
  if (!ipRl.allowed) return tooMany(ipRl.retryAfterSec);
  const acctKey = `login:acct:${blindIndex(email)}`;
  const acctRl = consume(acctKey, 5, WINDOW);
  if (!acctRl.allowed) return tooMany(acctRl.retryAfterSec);

  const user = await findByEmail(email);
  // Always run one scrypt, so response time doesn't reveal whether the account exists.
  const ok = await verifyPassword(password, user?.passwordHash ?? (await dummyHash()));
  if (!user || !ok) return json({ error: 'Invalid email or password.' }, 401);

  const { token, maxAge } = issue(user.id, 'mfa');
  const res = json({ mfaRequired: true });
  res.cookies.set(MFA_COOKIE, token, cookieOptions(maxAge, '/api/auth/mfa'));
  return res;
}
