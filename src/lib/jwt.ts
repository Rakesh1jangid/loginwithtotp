import { createHmac, randomUUID } from 'node:crypto';
import { config } from './config.ts';
import { safeEqual } from './crypto.ts';

/**
 * Minimal HS256 JWT on node:crypto.
 * Hardening: the header must equal our pinned header exactly (blocks "alg":"none" and algorithm
 * confusion), the signature is compared in constant time, and iss/aud/typ/exp/nbf are enforced.
 * `typ` separates the short-lived MFA challenge token from the real session token, so one
 * cannot be replayed as the other.
 */
export type TokenType = 'session' | 'mfa';

export interface Claims {
  sub: string;
  typ: TokenType;
  jti: string;
  iss: string;
  aud: string;
  iat: number;
  nbf: number;
  exp: number;
}

const HEADER = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
const CLOCK_SKEW_SEC = 5;

function sign(data: string): string {
  return createHmac('sha256', config().jwtSecret).update(data).digest('base64url');
}

export function signToken(sub: string, typ: TokenType, ttlSec: number, now = Date.now()): { token: string; claims: Claims } {
  const iat = Math.floor(now / 1000);
  const claims: Claims = {
    sub,
    typ,
    jti: randomUUID(),
    iss: config().issuer,
    aud: config().audience,
    iat,
    nbf: iat,
    exp: iat + ttlSec,
  };
  const body = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const data = `${HEADER}.${body}`;
  return { token: `${data}.${sign(data)}`, claims };
}

export function verifyToken(token: string, expectedType: TokenType, now = Date.now()): Claims | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [h, b, s] = parts as [string, string, string];
    if (h !== HEADER) return null;
    if (!safeEqual(sign(`${h}.${b}`), s)) return null;
    const c = JSON.parse(Buffer.from(b, 'base64url').toString('utf8')) as Partial<Claims>;
    const t = Math.floor(now / 1000);
    if (
      c.iss !== config().issuer ||
      c.aud !== config().audience ||
      c.typ !== expectedType ||
      typeof c.sub !== 'string' ||
      typeof c.jti !== 'string' ||
      typeof c.exp !== 'number' ||
      typeof c.nbf !== 'number' ||
      typeof c.iat !== 'number' ||
      t >= c.exp ||
      t + CLOCK_SKEW_SEC < c.nbf
    ) {
      return null;
    }
    return c as Claims;
  } catch {
    return null;
  }
}
