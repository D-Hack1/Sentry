// Backend base URL — override with VITE_API_BASE_URL (e.g. in dashboard/.env.local).
export const API_BASE_URL: string = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? 'http://localhost:8000';

// Mock data is opt-in only: VITE_USE_MOCKS=true npm run dev
export const USE_MOCKS: boolean = import.meta.env.VITE_USE_MOCKS === 'true';

export async function fetchJson<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;
  const response = await fetch(url, options);

  if (!response.ok) {
    let message = `Request failed with status ${response.status}`;
    try {
      const errorData = await response.json();
      if (errorData?.error?.message) message = errorData.error.message;
    } catch {
      // body was not JSON — keep the generic message
    }
    throw new Error(message);
  }

  return response.json();
}
