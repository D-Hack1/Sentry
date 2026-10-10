import { API_BASE_URL, USE_MOCKS } from './client';

export function getReportUrl(id: string): string {
  return `${API_BASE_URL}/report/${encodeURIComponent(id)}`;
}

/** Fetch the PDF for a session (es_id) as a Blob. */
export async function fetchReportBlob(id: string): Promise<Blob> {
  const response = await fetch(getReportUrl(id));
  if (!response.ok) {
    let message = `Report request failed with status ${response.status}`;
    try {
      const body = await response.json();
      if (body?.error?.message) message = body.error.message;
    } catch {
      // not JSON
    }
    throw new Error(message);
  }
  return response.blob();
}

/** Trigger a browser download of the session's PDF report. */
export async function downloadReport(id: string, sessionId?: string): Promise<void> {
  if (USE_MOCKS) {
    alert('Mock: PDF download triggered for session ' + id);
    return;
  }
  const blob = await fetchReportBlob(id);
  const blobUrl = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = blobUrl;
  a.download = `ipsec_report_${sessionId ?? id}.pdf`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
}
