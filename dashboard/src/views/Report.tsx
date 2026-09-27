import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, Download, Share2 } from 'lucide-react';
import { getReportUrl, downloadReport } from '../api/report';

export default function Report() {
  const { id } = useParams();
  const [blobUrl, setBlobUrl] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    const url = getReportUrl(id);
    fetch(url)
      .then(r => r.blob())
      .then(blob => {
        if (blob.type === 'application/pdf' || url.includes('#mock-report-url')) {
          // If it's mock, we'll just show a dummy iframe or pdf viewer
          if (url.includes('#mock')) {
             setBlobUrl('mock');
          } else {
             setBlobUrl(URL.createObjectURL(blob));
          }
        }
      })
      .catch(e => console.error(e));

    return () => {
      if (blobUrl && blobUrl !== 'mock') URL.revokeObjectURL(blobUrl);
    };
  }, [id]);

  const handleShare = () => {
    navigator.clipboard.writeText(window.location.href);
    alert('Link copied to clipboard!');
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
          <button onClick={() => id && downloadReport(id)} className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 transition-colors">
            <Download size={16} /> Download PDF
          </button>
        </div>
      </div>

      <div className="flex-1 panel relative">
        {blobUrl ? (
          blobUrl === 'mock' ? (
             <div className="absolute inset-0 flex items-center justify-center flex-col text-gray-500">
                <p>Mock PDF Report View</p>
                <p className="text-sm mt-2">In production, the PDF would be rendered here in an iframe.</p>
             </div>
          ) : (
            <iframe src={blobUrl} className="w-full h-full border-none" title="PDF Report" />
          )
        ) : (
          <div className="absolute inset-0 flex items-center justify-center text-gray-500 animate-pulse">
            Generating Report...
          </div>
        )}
      </div>
    </div>
  );
}
