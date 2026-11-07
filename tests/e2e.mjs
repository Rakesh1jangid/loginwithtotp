// End-to-end smoke test against a running dev server: node tests/e2e.mjs [baseUrl]
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

const base = process.argv[2] ?? 'http://localhost:3000';
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const totp = (secret, now = Date.now()) => {
  let bits = 0, val = 0;
  const bytes = [];
  for (const c of secret) { val = (val << 5) | B32.indexOf(c); bits += 5; if (bits >= 8) { bytes.push((val >>> (bits - 8)) & 255); bits -= 8; val &= (1 << bits) - 1; } }
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(Math.floor(now / 30000)));
  const h = createHmac('sha1', Buffer.from(bytes)).update(msg).digest();
  const o = h[h.length - 1] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, '0');
};

const jar = new Map();
async function call(path, body, { headers = {}, method = 'POST' } = {}) {
  const res = await fetch(base + path, {
    method,
    redirect: 'manual',
    headers: { 'Content-Type': 'application/json', Origin: base, Cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '), ...headers },
    body: method === 'POST' ? JSON.stringify(body) : undefined,
  });
  for (const sc of res.headers.getSetCookie()) {
    const [kv, ...attrs] = sc.split('; ');
    const [k, v] = [kv.slice(0, kv.indexOf('=')), kv.slice(kv.indexOf('=') + 1)];
    if (v === '' || attrs.some((a) => a === 'Max-Age=0')) jar.delete(k); else jar.set(k, v);
    if (k === 'session') {
      assert.ok(attrs.includes('HttpOnly'), 'session cookie HttpOnly');
      assert.ok(attrs.some((a) => a.toLowerCase() === 'samesite=strict'), 'SameSite=Strict');
    }
  }
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  return { status: res.status, data };
}

const email = `t${Date.now()}@example.com`;
const password = 'Str0ng-Passphrase-42';
const ok = (name) => console.log('PASS', name);

let r = await call('/api/auth/register', { email, password: 'short' });
assert.equal(r.status, 400); ok('weak password rejected');

r = await call('/api/auth/register', { email, password });
assert.equal(r.status, 201); assert.match(r.data.qr, /^data:image\/png/);
const secret = r.data.secret; ok('registered, got TOTP secret + QR');

r = await call('/api/auth/register', { email, password });
assert.equal(r.status, 409); ok('duplicate rejected');

r = await call('/api/auth/login', { email, password }, { headers: { Origin: 'http://evil.example' } });
assert.equal(r.status, 403); ok('cross-origin POST blocked');

r = await call('/api/auth/login', { email, password: 'wrong-password-1A' });
assert.equal(r.status, 401); const wrongMsg = r.data.error;
r = await call('/api/auth/login', { email: 'nobody@example.com', password: 'wrong-password-1A' });
assert.equal(r.status, 401); assert.equal(r.data.error, wrongMsg); ok('same error for bad password and unknown user');

r = await call('/api/auth/mfa', { code: totp(secret) });
assert.equal(r.status, 401); ok('MFA without password step rejected');

r = await call('/api/auth/login', { email, password });
assert.equal(r.status, 200); assert.equal(r.data.mfaRequired, true); assert.ok(jar.has('mfa')); assert.ok(!jar.has('session'));
ok('password step issues only an MFA challenge, no session');

r = await call('/', null, { method: 'GET' }); // SSR page still login
r = await call('/dashboard', null, { method: 'GET' });
assert.equal(r.status, 307); ok('dashboard redirects without session');

r = await call('/api/auth/mfa', { code: '000000' });
assert.equal(r.status, 401); ok('wrong TOTP rejected');

const code = totp(secret);
r = await call('/api/auth/mfa', { code });
assert.equal(r.status, 200); assert.ok(jar.has('session')); ok('correct TOTP issues session JWT');
const jwt = jar.get('session');
assert.equal(jwt.split('.').length, 3);

r = await call('/dashboard', null, { method: 'GET' });
assert.equal(r.status, 200); assert.ok(r.data.includes(email)); ok('SSR dashboard shows decrypted email');

// replay: the same code with a fresh challenge must fail
const saved = jar.get('session'); jar.delete('session');
await call('/api/auth/login', { email, password });
r = await call('/api/auth/mfa', { code });
assert.equal(r.status, 401); ok('TOTP code replay rejected');
jar.delete('mfa'); jar.set('session', saved);

// tampered JWT
const [h, b, s] = jwt.split('.');
jar.set('session', `${h}.${Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(b, 'base64url')), sub: 'x' })).toString('base64url')}.${s}`);
r = await call('/dashboard', null, { method: 'GET' });
assert.equal(r.status, 307); ok('tampered JWT rejected'); jar.set('session', jwt);

r = await call('/api/auth/logout', {});
assert.equal(r.status, 200);
jar.set('session', jwt); // attacker replays the stolen token after logout
r = await call('/dashboard', null, { method: 'GET' });
assert.equal(r.status, 307); ok('JWT revoked server-side after logout'); jar.clear();

// brute force
const target = `victim${Date.now()}@example.com`;
let codes = [];
for (let i = 0; i < 7; i++) codes.push((await call('/api/auth/login', { email: target, password: 'guess-Number-1' + i })).status);
assert.deepEqual(codes.slice(0, 5), [401, 401, 401, 401, 401]);
assert.equal(codes[5], 429); ok(`rate limit kicks in after 5 attempts: ${codes.join(',')}`);
console.log('ALL PASSED');
