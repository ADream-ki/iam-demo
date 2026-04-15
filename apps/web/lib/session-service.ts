import 'server-only';

import { backendFetch, parseJson } from '@/lib/api';

export type SessionView = {
  id: string;
  deviceName: string;
  clientLabel: string;
  location: string;
  ip: string;
  lastSeen: string;
  isCurrent: boolean;
};

export async function loadSessions() {
  // The backend exposes the collection at /api/sessions without a trailing slash.
  const response = await backendFetch('/api/sessions');
  if (!response.ok) {
    return { sessions: [], error: '会话列表加载失败' };
  }

  const payload = await parseJson<Array<{
    id: string;
    device_name: string;
    user_agent?: string | null;
    ip?: string | null;
    last_seen_at: string;
    current: boolean;
  }>>(response);

  return {
    sessions: payload.map((item) => ({
      id: item.id,
      deviceName: item.device_name,
      clientLabel: item.user_agent || 'Browser Session',
      location: 'n/a',
      ip: item.ip || '-',
      lastSeen: item.last_seen_at,
      isCurrent: item.current,
    })),
    error: null,
  };
}
