import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, Download, Share2, AlertTriangle } from 'lucide-react';
import { fetchReportBlob, downloadReport } from '../api/report';
import { USE_MOCKS } from '../api/client';

type ReportState =
  | { kind: 'loading' }
  | { kind: 'ready'; url: string }
  | { kind: 'mock' }
  | { kind: 'error'; message: string };

export default function Report() {
  const { id } = useParams();
  const [state, setState] = useState<ReportState>(USE_MOCKS ? { kind: 'mock' } : { kind: 'loading' });

  useEffect(() => {
    if (!id || USE_MOCKS) return;
    let objectUrl: string | null = null;
    let cancelled = false;
    fetchReportBlob(id)
      .then(blob => {
        if (cancelled) return;
        objectUrl = URL.createObjectURL(blob);
        setState({ kind: 'ready', url: objectUrl });
      })
      .catch((e: unknown) => {
        if (!cancelled) setState({ kind: 'error', message: e instanceof Error ? e.message : String(e) });
      });
    return () => {
      cancelled = true;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [id]);

  const handleShare = async () => {
    try {
      await navigator.clipboard.writeText(window.location.href);
      alert('Link copied to clipboard!');
    } catch {
      alert(window.location.href);
    }
  };

  const handleDownload = async () => {
    if (!id) return;
    try {
      await downloadReport(id);
    } catch {
      alert('Failed to download report.');
    }
  };

  return (
    <div className="max-w-5xl mx-auto h-[calc(100vh-6rem)] flex flex-col">
      <div className="flex justify-between items-center mb-6">
        <div>
          <Link to={`/sessions/${id}`} className="inline-flex items-center text-sm text-gray-400 hover:text-white transition-colors mb-2">
            <ArrowLeft size={16} className="mr-1" /> Back to Session
          </Link>
          <h1 className="text-2xl font-bold tracking-tight">Security Assessment Report</h1>
        </div>
        <div className="flex gap-3">
          <button onClick={handleShare} className="bg-gray-800 hover:bg-gray-700 text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 transition-colors">
            <Share2 size={16} /> Share Link
          </button>
          <button onClick={handleDownload} className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 transition-colors">
            <Download size={16} /> Download PDF
          </button>
        </div>
      </div>

      <div className="flex-1 panel relative">
        {state.kind === 'ready' && (
          <iframe src={state.url} className="w-full h-full border-none" title="PDF Report" />
        )}
        {state.kind === 'mock' && (
          <div className="absolute inset-0 flex items-center justify-center flex-col text-gray-500">
            <p>Mock PDF Report View</p>
            <p className="text-sm mt-2">Start the API and unset VITE_USE_MOCKS to render the real PDF here.</p>
          </div>
        )}
        {state.kind === 'loading' && (
          <div className="absolute inset-0 flex items-center justify-center text-gray-500 animate-pulse">
            Generating Report...
          </div>
        )}
        {state.kind === 'error' && (
          <div className="absolute inset-0 flex flex-col items-center justify-center text-red-500 gap-2">
            <AlertTriangle size={28} />
            <div>Unable to generate report — {state.message}</div>
          </div>
        )}
      </div>
    </div>
  );
}
