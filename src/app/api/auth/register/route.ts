import type { NextRequest } from 'next/server';
import QRCode from 'qrcode';
import { config } from '@/lib/config';
import { hashPassword } from '@/lib/password';
import { assertSameOriginJson, clientIp, json, parseBody, tooMany } from '@/lib/http';
import { consume } from '@/lib/rate-limit';
import { createUser } from '@/lib/store';
import { generateSecret, otpauthUri } from '@/lib/totp';
import { registerSchema } from '@/lib/validation';

export const runtime = 'nodejs';

export async function POST(req: NextRequest) {
  const bad = assertSameOriginJson(req);
  if (bad) return bad;

  const rl = consume(`reg:ip:${clientIp(req)}`, 5, 60 * 60_000);
  if (!rl.allowed) return tooMany(rl.retryAfterSec);

  const body = await parseBody(req, registerSchema);
  if ('error' in body) return body.error;
  const { email, password } = body.data;

  const secret = generateSecret();
  const user = await createUser(email, await hashPassword(password), secret);
  if (!user) return json({ error: 'Unable to register with these details.' }, 409);

  const uri = otpauthUri(secret, email, config().issuer);
  const qr = await QRCode.toDataURL(uri, { margin: 1, width: 220 });
  // Shown exactly once; the secret is only stored encrypted from here on.
  return json({ ok: true, secret, qr }, 201);
}
