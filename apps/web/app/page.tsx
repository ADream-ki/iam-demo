import Link from 'next/link';

import { subjectThemes } from '@/lib/subjects';

export default function HomePage() {
  return (
    <main className="portal-shell">
      <section className="portal-hero">
        <p className="eyebrow">Enterprise IAM Solution</p>
        <h1>选择认证主体</h1>
        <p>支持 Member、Community Staff、Platform Staff 独立登录与多设备会话管理。</p>
      </section>
      <section className="portal-grid">
        {Object.values(subjectThemes).map((subject) => (
          <Link key={subject.key} href={`/auth/${subject.key}`} className="subject-card" style={{ ['--accent' as string]: subject.accent, ['--accent-soft' as string]: subject.accentSoft }}>
            <span className="subject-card__badge">{subject.level}</span>
            <h2>{subject.title}</h2>
            <p>{subject.description}</p>
          </Link>
        ))}
      </section>
    </main>
  );
}