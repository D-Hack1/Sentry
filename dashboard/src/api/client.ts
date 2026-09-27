export const API_BASE_URL = 'http://localhost:8000';
export const USE_MOCKS = import.meta.env.VITE_USE_MOCKS === 'true' || true; // Set default to true for development

export async function fetchJson<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;
  const response = await fetch(url, options);

  if (!response.ok) {
    let errorDetail = null;
    try {
      const errorData = await response.json();
      errorDetail = errorData.error;
    } catch {
      // Not JSON
    }
    
    if (errorDetail) {
      throw new Error(errorDetail.message || `Request failed with status ${response.status}`);
    } else {
      throw new Error(`Request failed with status ${response.status}`);
    }
  }

  return response.json();
}
