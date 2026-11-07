'use client';

import Link from 'next/link';
import { useState, type FormEvent } from 'react';
import { errorText, post } from './api';

export default function RegisterForm() {
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<{ qr: string; secret: string } | null>(null);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    setBusy(true);
    setError('');
    const r = await post<{ qr: string; secret: string }>('/api/auth/register', {
      email: form.get('email'),
      password: form.get('password'),
    });
    setBusy(false);
    if (!r.ok) return setError(errorText(r));
    setDone({ qr: r.data.qr, secret: r.data.secret });
  }

  if (done) {
    return (
      <div>
        <h1>Set up two-factor</h1>
        <p className="sub">
          Scan this with an authenticator app (Google Authenticator, Authy, 1Password). It is shown only once.
        </p>
        {/* eslint-disable-next-line @next/next/no-img-element -- data: URL QR, nothing to optimise */}
        <img className="qr" src={done.qr} alt="TOTP QR code" width={220} height={220} />
        <p className="sub">Or enter this key manually:</p>
        <div className="secret">{done.secret}</div>
        <Link href="/" className="btn ghost">Continue to sign in</Link>
      </div>
    );
  }

  return (
    <form onSubmit={onSubmit} noValidate>
      <h1>Create account</h1>
      <p className="sub">12+ characters with upper, lower and a digit.</p>
      <label htmlFor="email">Email</label>
      <input id="email" name="email" type="email" autoComplete="username" required maxLength={254} />
      <label htmlFor="password">Password</label>
      <input id="password" name="password" type="password" autoComplete="new-password" required minLength={12} maxLength={128} />
      <button type="submit" disabled={busy}>{busy ? 'Creating...' : 'Create account'}</button>
      <div className="msg err" role="alert">{error}</div>
      <p className="alt">
        Have an account? <Link href="/">Sign in</Link>
      </p>
    </form>
  );
}
