/**
 * In-memory limiter for a single local Node process (swap the Map for Redis to scale out).
 * Sliding-window counter plus an escalating lockout once the window is exhausted.
 */
interface Entry {
  hits: number[]; // timestamps (ms) inside the window
  strikes: number; // number of lockouts so far (drives exponential backoff)
  lockedUntil: number;
}

// Pinned to globalThis: Next bundles each route separately (and re-evaluates modules on HMR),
// so a plain module-level Map would give every route its own empty limiter.
const g = globalThis as typeof globalThis & { __rateStore?: Map<string, Entry> };
const store = (g.__rateStore ??= new Map<string, Entry>());
const MAX_KEYS = 50_000; // bounds memory under a spray from many sources

export interface RateResult {
  allowed: boolean;
  retryAfterSec: number;
}

export function consume(key: string, limit: number, windowMs: number, now = Date.now()): RateResult {
  let e = store.get(key);
  if (!e) {
    if (store.size >= MAX_KEYS) prune(now);
    e = { hits: [], strikes: 0, lockedUntil: 0 };
    store.set(key, e);
  }
  if (e.lockedUntil > now) return { allowed: false, retryAfterSec: Math.ceil((e.lockedUntil - now) / 1000) };

  e.hits = e.hits.filter((t) => now - t < windowMs);
  if (e.hits.length >= limit) {
    e.strikes += 1;
    // 1x, 2x, 4x ... the window, capped at 24h
    const lock = Math.min(windowMs * 2 ** (e.strikes - 1), 24 * 3600_000);
    e.lockedUntil = now + lock;
    e.hits = [];
    return { allowed: false, retryAfterSec: Math.ceil(lock / 1000) };
  }
  e.hits.push(now);
  return { allowed: true, retryAfterSec: 0 };
}

/** Forgive failures after a fully successful login. */
export function reset(key: string): void {
  store.delete(key);
}

function prune(now: number): void {
  for (const [k, e] of store) {
    if (e.lockedUntil <= now && e.hits.every((t) => now - t > 3600_000)) store.delete(k);
  }
  if (store.size >= MAX_KEYS) store.clear();
}

export function clearAll(): void {
  store.clear();
}
