import { fetchJson, USE_MOCKS } from './client';
import type { HealthResponse } from '../types/api';
import { mockHealth } from './mocks';

export async function getHealth(): Promise<HealthResponse> {
  if (USE_MOCKS) return mockHealth;
  return fetchJson<HealthResponse>('/health');
}
