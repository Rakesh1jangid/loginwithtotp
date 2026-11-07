import { redirect } from 'next/navigation';
import RegisterForm from '@/components/RegisterForm';
import { currentUser } from '@/lib/auth';

export const dynamic = 'force-dynamic';

export default async function Register() {
  if (await currentUser()) redirect('/dashboard');
  return <RegisterForm />;
}
