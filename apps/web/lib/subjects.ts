export type SubjectKey = 'member' | 'community' | 'platform';
export type SubjectRole = 'member' | 'community_staff' | 'platform_staff';

export type SubjectTheme = {
  key: SubjectKey;
  role: SubjectRole;
  title: string;
  description: string;
  shortTag: string;
  accent: string;
  accentSoft: string;
  icon: string;
  level: string;
  requiresMfa: boolean;
};

export const subjectThemes: Record<SubjectKey, SubjectTheme> = {
  member: {
    key: 'member',
    role: 'member',
    title: '会员中心',
    description: '面向普通用户的权限域，支持 OTP、密码与 Passkey 登录。',
    shortTag: 'Member Domain',
    accent: '#2563eb',
    accentSoft: '#dbeafe',
    icon: 'user',
    level: 'Standard',
    requiresMfa: false,
  },
  community: {
    key: 'community',
    role: 'community_staff',
    title: '社区运营',
    description: '社区工作台，聚焦内容处理、会话审计与运营协同。',
    shortTag: 'Community Domain',
    accent: '#059669',
    accentSoft: '#d1fae5',
    icon: 'briefcase',
    level: 'Elevated',
    requiresMfa: false,
  },
  platform: {
    key: 'platform',
    role: 'platform_staff',
    title: '平台运营',
    description: '高敏权限域，要求完整 MFA，适合平台级安全操作。',
    shortTag: 'Platform Domain',
    accent: '#4f46e5',
    accentSoft: '#e0e7ff',
    icon: 'shield',
    level: 'Restricted',
    requiresMfa: true,
  },
};

export function parseSubjectKey(value: string): SubjectKey | null {
  if (value === 'member' || value === 'community' || value === 'platform') {
    return value;
  }

  return null;
}

export function subjectFromRole(role: SubjectRole): SubjectKey {
  switch (role) {
    case 'member':
      return 'member';
    case 'community_staff':
      return 'community';
    case 'platform_staff':
      return 'platform';
  }
}