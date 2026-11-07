import { redirect } from 'next/navigation';
import LoginForm from '@/components/LoginForm';
import { currentUser } from '@/lib/auth';

export const dynamic = 'force-dynamic'; // SSR on every request: the session check must never be cached

export default async function Home() {
  if (await currentUser()) redirect('/dashboard');
  return <LoginForm />;
}
