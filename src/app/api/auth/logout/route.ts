import type { NextRequest } from 'next/server';
import { config } from '@/lib/config';
import { assertSameOriginJson, json } from '@/lib/http';
import { cookieOptions, revoke, validate } from '@/lib/session';

export const runtime = 'nodejs';

export async function POST(req: NextRequest) {
  const bad = assertSameOriginJson(req);
  if (bad) return bad;
  const claims = validate(req.cookies.get(config().cookieName)?.value, 'session');
  if (claims) revoke(claims.jti); // server-side revocation: the JWT is dead even if someone kept a copy
  const res = json({ ok: true });
  res.cookies.set(config().cookieName, '', cookieOptions(0));
  return res;
}
