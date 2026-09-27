import { fetchJson, USE_MOCKS } from './client';
import type { StatsResponse } from '../types/api';
import { mockStats } from './mocks';

export async function getStats(): Promise<StatsResponse> {
  if (USE_MOCKS) return mockStats;
  return fetchJson<StatsResponse>('/stats');
}
