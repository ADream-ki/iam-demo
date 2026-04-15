import { notFound, redirect } from 'next/navigation';

import { AuthShell } from '@/components/auth-shell';
import { backendFetch, parseJson } from '@/lib/api';
import { isNextRedirectError } from '@/lib/next-redirect';
import { parseSubjectKey, subjectFromRole } from '@/lib/subjects';

type SessionOverview = {
  subject_role: 'member' | 'community_staff' | 'platform_staff';
  mfa_level: 'none' | 'partial' | 'full';
};

export default async function AuthPage({ params }: { params: Promise<{ subject: string }> }) {
  const { subject } = await params;
  const parsed = parseSubjectKey(subject);
  if (!parsed) {
    notFound();
  }

  try {
    const sessionResponse = await backendFetch('/api/auth/session');
    if (sessionResponse.ok) {
      const session = await parseJson<SessionOverview>(sessionResponse);
      const actualSubject = subjectFromRole(session.subject_role);
      if (actualSubject !== parsed) {
        redirect(`/auth/${actualSubject}`);
      }
      if (session.mfa_level === 'full') {
        redirect(`/dashboard/${parsed}`);
      }

      return <AuthShell subject={parsed} initialStage="mfa" />;
    }
  } catch (err) {
    // Re-throw redirect/notFound so Next.js can handle them correctly.
    // Only swallow genuine network/parse errors to degrade to login shell.
    if (isNextRedirectError(err)) throw err;
    // Rendering the auth page must degrade to the login shell when session
    // introspection fails instead of surfacing a production RSC error page.
  }

  return <AuthShell subject={parsed} initialStage="auth" />;
}
