'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { errorText, post } from './api';

export default function LoginForm() {
  const router = useRouter();
  const [step, setStep] = useState<'password' | 'mfa'>('password');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    setBusy(true);
    setError('');
    const r =
      step === 'password'
        ? await post('/api/auth/login', { email: form.get('email'), password: form.get('password') })
        : await post('/api/auth/mfa', { code: String(form.get('code') ?? '').replace(/\s/g, '') });
    setBusy(false);
    if (!r.ok) {
      setError(errorText(r));
      if (step === 'mfa' && r.data.error?.startsWith('Session expired')) setStep('password');
      return;
    }
    if (step === 'password') setStep('mfa');
    else router.replace('/dashboard');
  }

  return (
    <form onSubmit={onSubmit} noValidate>
      <h1>{step === 'password' ? 'Sign in' : 'Two-factor code'}</h1>
      <p className="sub">
        {step === 'password' ? 'Use your email and password.' : 'Enter the 6-digit code from your authenticator app.'}
      </p>
      {step === 'password' ? (
        <div key="step-password">
          <label htmlFor="email">Email</label>
          <input id="email" name="email" type="email" autoComplete="username" required maxLength={254} />
          <label htmlFor="password">Password</label>
          <input id="password" name="password" type="password" autoComplete="current-password" required maxLength={128} />
        </div>
      ) : (
        <div key="step-mfa">
          <label htmlFor="code">Authentication code</label>
          <input id="code" name="code" type="text" inputMode="numeric" autoComplete="one-time-code" maxLength={7} required autoFocus />
        </div>
      )}
      <button type="submit" disabled={busy}>
        {busy ? 'Checking...' : step === 'password' ? 'Continue' : 'Verify'}
      </button>
      <div className="msg err" role="alert">{error}</div>
      {step === 'password' && (
        <p className="alt">
          No account? <Link href="/register">Create one</Link>
        </p>
      )}
    </form>
  );
}
