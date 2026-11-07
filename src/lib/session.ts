import { config } from './config.ts';
import { signToken, verifyToken, type Claims } from './jwt.ts';

/**
 * Server-side allow-list of live session/challenge JWT ids. A valid signature alone is not enough:
 * the jti must still be registered, which makes logout real (revocation) and makes MFA
 * challenge tokens single-use. In-memory, so a server restart signs everyone out.
 */
const g = globalThis as typeof globalThis & { __jtiStore?: Map<string, number> };
const live = (g.__jtiStore ??= new Map<string, number>()); // jti -> exp (sec)

function sweep(): void {
  const now = Math.floor(Date.now() / 1000);
  for (const [jti, exp] of live) if (exp <= now) live.delete(jti);
}

export function issue(sub: string, typ: 'session' | 'mfa'): { token: string; claims: Claims; maxAge: number } {
  sweep();
  const ttl = typ === 'session' ? config().sessionTtlSec : config().mfaChallengeTtlSec;
  const { token, claims } = signToken(sub, typ, ttl);
  live.set(claims.jti, claims.exp);
  return { token, claims, maxAge: ttl };
}

/** Verifies signature + claims AND that the jti has not been revoked/consumed. */
export function validate(token: string | undefined, typ: 'session' | 'mfa'): Claims | null {
  if (!token) return null;
  const claims = verifyToken(token, typ);
  if (!claims || !live.has(claims.jti)) return null;
  return claims;
}

export function revoke(jti: string): void {
  live.delete(jti);
}

export function cookieOptions(maxAge: number, path = '/') {
  return {
    httpOnly: true,
    secure: config().prod,
    sameSite: 'strict' as const,
    path: config().prod ? '/' : path, // __Host- cookies must use Path=/
    maxAge,
  };
}

export const MFA_COOKIE = 'mfa';
