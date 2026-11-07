import { redirect } from 'next/navigation';
import LogoutButton from '@/components/LogoutButton';
import { currentUser } from '@/lib/auth';

export const dynamic = 'force-dynamic';

export default async function Dashboard() {
  const user = await currentUser();
  if (!user) redirect('/');
  return (
    <div>
      <h1>You are signed in</h1>
      <p className="sub">Authenticated by password + TOTP, session held in a signed JWT.</p>
      <dl>
        <dt>Email (decrypted from AES-256-GCM at rest)</dt>
        <dd>{user.email}</dd>
        <dt>Session issued</dt>
        <dd>{user.issuedAt.toISOString()}</dd>
        <dt>Session expires</dt>
        <dd>{user.expiresAt.toISOString()}</dd>
      </dl>
      <LogoutButton />
    </div>
  );
}
