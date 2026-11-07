import type { NextRequest } from 'next/server';
import { assertSameOriginJson, clientIp, json, parseBody, tooMany } from '@/lib/http';
import { consume, reset } from '@/lib/rate-limit';
import { config } from '@/lib/config';
import { cookieOptions, issue, MFA_COOKIE, revoke, validate } from '@/lib/session';
import { findById, readTotpSecret, updateUser } from '@/lib/store';
import { verifyTotp } from '@/lib/totp';
import { mfaSchema } from '@/lib/validation';

export const runtime = 'nodejs';

const WINDOW = 15 * 60_000;

/** Step 2 of 2: verify the TOTP code against the challenge cookie, then issue the session JWT. */
export async function POST(req: NextRequest) {
  const bad = assertSameOriginJson(req);
  if (bad) return bad;

  const ipRl = consume(`mfa:ip:${clientIp(req)}`, 20, WINDOW);
  if (!ipRl.allowed) return tooMany(ipRl.retryAfterSec);

  const body = await parseBody(req, mfaSchema);
  if ('error' in body) return body.error;

  const challenge = validate(req.cookies.get(MFA_COOKIE)?.value, 'mfa');
  if (!challenge) return json({ error: 'Session expired. Sign in again.' }, 401);

  // Per-account cap on guesses: 5 codes per window across all challenges for this user.
  const userRl = consume(`mfa:user:${challenge.sub}`, 5, WINDOW);
  if (!userRl.allowed) {
    revoke(challenge.jti);
    return tooMany(userRl.retryAfterSec);
  }

  const user = await findById(challenge.sub);
  if (!user) return json({ error: 'Session expired. Sign in again.' }, 401);

  const step = verifyTotp(readTotpSecret(user), body.data.code);
  // step must be strictly newer than the last accepted one: a captured code can't be replayed.
  if (step === null || step <= user.lastTotpStep) return json({ error: 'Invalid code.' }, 401);

  revoke(challenge.jti); // challenge is single-use
  await updateUser(user.id, { lastTotpStep: step, totpConfirmed: true });
  reset(`mfa:user:${user.id}`);
  reset(`login:acct:${user.emailIdx}`);

  const { token, maxAge } = issue(user.id, 'session');
  const res = json({ ok: true });
  res.cookies.set(config().cookieName, token, cookieOptions(maxAge));
  res.cookies.set(MFA_COOKIE, '', { ...cookieOptions(0, '/api/auth/mfa') });
  return res;
}
