import { fetchJson, USE_MOCKS } from './client';
import type { Session, SessionListResponse } from '../types/api';
import { mockSessions, mockSession } from './mocks';

export async function getSessions(params?: {
  severity?: string;
  cipher_suite?: string;
  mode?: string;
  pfs_enabled?: boolean;
  traffic_class?: string;
  ike_version?: number;
  start_time?: string;
  end_time?: string;
  page?: number;
  page_size?: number;
}): Promise<SessionListResponse> {
  if (USE_MOCKS) return mockSessions;

  const searchParams = new URLSearchParams();
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined) {
        searchParams.append(key, String(value));
      }
    });
  }

  const queryStr = searchParams.toString();
  return fetchJson<SessionListResponse>(`/sessions${queryStr ? '?' + queryStr : ''}`);
}

export async function getSessionById(id: string): Promise<Session> {
  if (USE_MOCKS) {
    if (id === mockSession.es_id) return mockSession;
    const session = mockSessions.items.find(s => s.es_id === id);
    if (session) return session;
    throw new Error("Session not found (mock)");
  }
  return fetchJson<Session>(`/sessions/${id}`);
}
