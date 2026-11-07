'use client';

import { useRouter } from 'next/navigation';
import { post } from './api';

export default function LogoutButton() {
  const router = useRouter();
  return (
    <button
      type="button"
      className="ghost"
      onClick={async () => {
        await post('/api/auth/logout', {});
        router.replace('/');
        router.refresh();
      }}
    >
      Sign out
    </button>
  );
}
