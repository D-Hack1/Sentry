import { API_BASE_URL, USE_MOCKS } from './client';

export function getReportUrl(id: string): string {
  if (USE_MOCKS) {
    return '#mock-report-url';
  }
  return `${API_BASE_URL}/report/${id}`;
}

export async function downloadReport(id: string): Promise<void> {
  if (USE_MOCKS) {
    alert("Mock: PDF download triggered for session " + id);
    return;
  }
  const url = getReportUrl(id);
  try {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`Failed to download report: ${response.status}`);
    }
    const blob = await response.blob();
    const blobUrl = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = blobUrl;
    a.download = `ipsec_report_${id}.pdf`;
    a.click();
    URL.revokeObjectURL(blobUrl);
  } catch (err) {
    console.error('Download report failed:', err);
    throw err;
  }
}
