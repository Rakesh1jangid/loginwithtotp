import { NextResponse, type NextRequest } from 'next/server';
import type { ZodType } from 'zod';

const MAX_BODY = 4096;

export function json(body: unknown, status = 200, headers?: Record<string, string>) {
  return NextResponse.json(body, { status, headers: { 'Cache-Control': 'no-store', ...headers } });
}

/** CSRF defence in depth (cookies are also SameSite=Strict): same-origin JSON POSTs only. */
export function assertSameOriginJson(req: NextRequest): NextResponse | null {
  const origin = req.headers.get('origin');
  const host = req.headers.get('host');
  try {
    if (!origin || !host || new URL(origin).host !== host) return json({ error: 'Forbidden' }, 403);
  } catch {
    return json({ error: 'Forbidden' }, 403);
  }
  if (!req.headers.get('content-type')?.toLowerCase().startsWith('application/json')) {
    return json({ error: 'Unsupported media type' }, 415);
  }
  return null;
}

/** Reads a size-capped JSON body and validates it with zod. */
export async function parseBody<T>(req: NextRequest, schema: ZodType<T>): Promise<{ data: T } | { error: NextResponse }> {
  const text = await req.text();
  if (text.length > MAX_BODY) return { error: json({ error: 'Payload too large' }, 413) };
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return { error: json({ error: 'Invalid request' }, 400) };
  }
  const parsed = schema.safeParse(raw);
  if (!parsed.success) return { error: json({ error: 'Invalid request', issues: parsed.error.issues.map((i) => i.message) }, 400) };
  return { data: parsed.data };
}

/**
 * Client address for rate limiting. The Node server appends the real socket address to
 * X-Forwarded-For, so the LAST entry is the one a client cannot forge.
 */
export function clientIp(req: NextRequest): string {
  const xff = req.headers.get('x-forwarded-for');
  const last = xff?.split(',').pop()?.trim();
  return last || 'unknown';
}

export function tooMany(retryAfterSec: number) {
  return json({ error: 'Too many attempts. Try again later.', retryAfterSec }, 429, { 'Retry-After': String(retryAfterSec) });
}
