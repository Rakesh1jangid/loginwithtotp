import { cookies } from 'next/headers';
import { config } from './config';
import { validate } from './session';
import { findById, readEmail } from './store';

/** For server components: resolves the signed-in user from the session cookie, or null. */
export async function currentUser() {
  const jar = await cookies();
  const claims = validate(jar.get(config().cookieName)?.value, 'session');
  if (!claims) return null;
  const user = await findById(claims.sub);
  if (!user) return null;
  return {
    id: user.id,
    email: readEmail(user),
    issuedAt: new Date(claims.iat * 1000),
    expiresAt: new Date(claims.exp * 1000),
  };
}
