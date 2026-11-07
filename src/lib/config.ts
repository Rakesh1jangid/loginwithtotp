// Server-only configuration. Never import this from a client component.
function b64Key(name: string, minBytes: number): Buffer {
  const raw = process.env[name];
  if (!raw) throw new Error(`Missing env var ${name}. Run "npm run setup".`);
  const buf = Buffer.from(raw, 'base64');
  if (buf.length < minBytes) throw new Error(`${name} must decode to at least ${minBytes} bytes.`);
  return buf;
}

function load() {
  const prod = process.env.NODE_ENV === 'production';
  return {
    prod,
    aesKey: b64Key('AES_KEY', 32).subarray(0, 32),
    jwtSecret: b64Key('JWT_SECRET', 32),
    indexKey: b64Key('INDEX_KEY', 32),
    issuer: process.env.JWT_ISSUER ?? 'secure-login',
    audience: process.env.JWT_AUDIENCE ?? 'secure-login-app',
    sessionTtlSec: 15 * 60,
    mfaChallengeTtlSec: 5 * 60,
    // __Host- prefix forces Secure + Path=/ + no Domain; browsers only accept it over HTTPS,
    // so it is used in production only (plain http://localhost would be rejected).
    cookieName: prod ? '__Host-session' : 'session',
  };
}

let cached: ReturnType<typeof load> | undefined;

export function config() {
  cached ??= load();
  return cached;
}
