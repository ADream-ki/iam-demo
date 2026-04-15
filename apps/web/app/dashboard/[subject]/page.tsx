import { redirect, notFound } from 'next/navigation';

import { DashboardShell } from '@/components/dashboard-shell';
import { backendFetch, parseJson } from '@/lib/api';
import { isNextRedirectError } from '@/lib/next-redirect';
import { parseSubjectKey, subjectThemes, subjectFromRole } from '@/lib/subjects';

type SessionOverview = {
  subject_role: 'member' | 'community_staff' | 'platform_staff';
  display_name: string;
  email: string;
  mfa_level: 'none' | 'partial' | 'full';
};

type SessionItem = {
  id: string;
  device_name: string;
  user_agent?: string | null;
  ip?: string | null;
  mfa_level: 'none' | 'partial' | 'full';
  expires_at: string;
  last_seen_at: string;
  current: boolean;
};

export default async function DashboardPage({ params }: { params: Promise<{ subject: string }> }) {
  const { subject } = await params;
  const parsed = parseSubjectKey(subject);
  if (!parsed) {
    notFound();
  }

  const session = await fetchSessionOrRedirect(parsed);
  const actualSubject = subjectFromRole(session.subject_role);
  if (actualSubject !== parsed) {
    redirect(`/dashboard/${actualSubject}`);
  }

  if (session.mfa_level !== 'full') {
    redirect(`/auth/${parsed}`);
  }

  const sessions = await fetchSessionsOrRedirect(parsed);

  return (
    <main className="dashboard-page">
      <DashboardShell
        subject={parsed}
        email={session.email}
        displayName={`${session.display_name} · ${subjectThemes[parsed].title}`}
        sessions={sessions}
      />
    </main>
  );
}

async function fetchSessionOrRedirect(subject: string): Promise<SessionOverview> {
  try {
    const sessionResponse = await backendFetch('/api/auth/session');
    if (!sessionResponse.ok) {
      redirect(`/auth/${subject}`);
    }

    const session = await parseJson<SessionOverview>(sessionResponse);
    if (!session?.subject_role || !session?.mfa_level) {
      redirect(`/auth/${subject}`);
    }

    return session;
  } catch (err) {
    // Always re-throw Next.js redirect/notFound errors — swallowing them
    // causes the redirect to silently fail and the RSC render to crash
    // with a production-only "omitted" error.
    if (isNextRedirectError(err)) throw err;
    redirect(`/auth/${subject}`);
  }
}

async function fetchSessionsOrRedirect(subject: string): Promise<SessionItem[]> {
  try {
    const sessionsResponse = await backendFetch('/api/sessions');
    if (!sessionsResponse.ok) {
      // Non-fatal: return empty list rather than redirecting — the session
      // check above already confirmed the user is authenticated.
      return [];
    }

    const sessions = await parseJson<SessionItem[]>(sessionsResponse);
    return Array.isArray(sessions) ? sessions : [];
  } catch (err) {
    if (isNextRedirectError(err)) throw err;
    // Degrade gracefully: dashboard can render without session list.
    return [];
  }
}
