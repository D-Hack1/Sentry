import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, Lock, Unlock, AlertTriangle, Download, Network } from 'lucide-react';
import { getSessionById } from '../api/sessions';
import { downloadReport } from '../api/report';

export default function SessionDetail() {
  const { id } = useParams();
  
  const { data: session, isLoading } = useQuery({
    queryKey: ['session', id],
    queryFn: () => getSessionById(id!),
    enabled: !!id
  });

  if (isLoading) return <div className="p-8 h-96 skeleton w-full"></div>;
  if (!session) return <div className="p-8 text-red-500">Session not found.</div>;

  const handleDownload = async () => {
    try {
      await downloadReport(session.es_id);
    } catch (e) {
      alert("Failed to download report.");
    }
  };

  const isCritical = session.security_score < 40;

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <Link to="/" className="inline-flex items-center text-sm text-gray-400 hover:text-white transition-colors">
        <ArrowLeft size={16} className="mr-1" /> Back to feed
      </Link>
      
      <div className={`panel overflow-hidden bg-[var(--color-surface)] ${isCritical ? 'border-red-500/60' : ''}`}>
        {/* Header bar - solid background */}
        <div className="p-6 flex justify-between items-start border-b border-[var(--color-border-subtle)] bg-[var(--color-surface-hover)]">
          <div>
            <h1 className="text-xl font-bold flex items-center gap-2 mb-2">
              <Network size={20} className="text-blue-500" />
              Session {session.session_id}
            </h1>
            <div className="text-sm text-gray-400">
              {new Date(session.ts).toLocaleString()} • Duration: {session.duration}s
            </div>
          </div>
          <button onClick={handleDownload} className="btn-primary flex items-center gap-2">
            <Download size={16} /> Download Report
          </button>
        </div>

        <div className="p-6 grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="md:col-span-2 space-y-6">
            {/* Config Table - solid background */}
            <div className="bg-[var(--color-surface-subcard)] p-4 rounded-lg border border-[var(--color-border-subtle)]">
              <h2 className="text-sm font-semibold text-gray-400 mb-4 uppercase tracking-wider">Inferred Configuration</h2>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div>
                  <div className="text-xs text-gray-500 mb-1">Mode</div>
                  <div className="text-sm font-medium capitalize">{session.mode}</div>
                </div>
                <div>
                  <div className="text-xs text-gray-500 mb-1">Cipher Suite</div>
                  <div className="text-sm font-mono text-blue-400">{session.cipher_suite}</div>
                </div>
                <div>
                  <div className="text-xs text-gray-500 mb-1">DH Group</div>
                  <div className="text-sm font-mono">{session.dh_group}</div>
                </div>
                <div>
                  <div className="text-xs text-gray-500 mb-1">PFS</div>
                  <div className="text-sm flex items-center gap-1">
                    {session.pfs_enabled ? (
                      <><Lock size={14} className="text-green-500"/> <span className="text-green-500">Enabled</span></>
                    ) : (
                      <><Unlock size={14} className="text-red-500"/> <span className="text-red-500 font-semibold">Disabled</span></>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* IKE Stats - solid background */}
            <div className="bg-[var(--color-surface-subcard)] p-4 rounded-lg border border-[var(--color-border-subtle)]">
              <h2 className="text-sm font-semibold text-gray-400 mb-4 uppercase tracking-wider">IKE Negotiation</h2>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div><span className="text-gray-500 block text-xs">Version</span> IKEv{session.ike_version}</div>
                <div><span className="text-gray-500 block text-xs">Packets</span> {session.ike_packet_count}</div>
                <div><span className="text-gray-500 block text-xs">Handshake</span> {session.ike_handshake_duration}s</div>
                <div><span className="text-gray-500 block text-xs">Proposals</span> {session.sa_proposal_count}</div>
              </div>
            </div>

            {/* Traffic Class & Evidence - solid background */}
            <div className="bg-[var(--color-surface-subcard)] p-4 rounded-lg border border-[var(--color-border-subtle)]">
              <h2 className="text-sm font-semibold text-gray-400 mb-4 uppercase tracking-wider">Traffic Analysis</h2>
              
              <div className="mb-4">
                <div className="flex justify-between items-end mb-1">
                  <span className="text-sm font-medium capitalize">Predicted: {session.traffic_class}</span>
                  <span className="text-xs text-gray-400">Confidence: {(session.traffic_confidence * 100).toFixed(1)}%</span>
                </div>
                <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                  <div className="h-full bg-purple-500" style={{ width: `${session.traffic_confidence * 100}%` }} />
                </div>
              </div>

              <div>
                <span className="text-xs text-gray-500 block mb-2">SHAP Evidence</span>
                <div className="flex flex-wrap gap-2">
                  {session.evidence.map((ev, i) => (
                    <span key={i} className="text-xs bg-gray-800 text-gray-200 px-2.5 py-1 rounded-md border border-gray-700">
                      {ev}
                    </span>
                  ))}
                </div>
              </div>
            </div>
            
            {/* Risk Flags - solid red card */}
            {session.risk_flags.length > 0 && (
              <div className="bg-red-950/60 border border-red-500/40 p-4 rounded-lg">
                <h2 className="text-sm font-bold text-red-400 mb-3 flex items-center gap-2 uppercase tracking-wider">
                  <AlertTriangle size={16} /> Risk Flags
                </h2>
                <ul className="space-y-2">
                  {session.risk_flags.map((flag, i) => (
                    <li key={i} className="text-sm text-gray-200 flex items-start gap-2 font-medium">
                      <span className="text-red-400 mt-0.5">•</span> {flag}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          <div className="space-y-6">
            {/* Score Gauges - solid background */}
            <div className="bg-[var(--color-surface-subcard)] p-6 rounded-lg border border-[var(--color-border-subtle)] flex flex-col items-center justify-center">
              <h2 className="text-sm font-semibold text-gray-400 mb-6 uppercase tracking-wider text-center">Security Score</h2>
              <div className="relative w-32 h-32 flex items-center justify-center mb-2">
                <svg className="w-full h-full transform -rotate-90">
                  <circle cx="64" cy="64" r="56" stroke="currentColor" strokeWidth="12" fill="none" className="text-gray-800" />
                  <circle cx="64" cy="64" r="56" stroke="currentColor" strokeWidth="12" fill="none" 
                    strokeDasharray="351.8" 
                    strokeDashoffset={351.8 - (351.8 * session.security_score) / 100}
                    className={
                      session.security_score < 40 ? 'text-red-500' :
                      session.security_score < 75 ? 'text-yellow-500' : 'text-green-500'
                    }
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-3xl font-bold">{Math.round(session.security_score)}</span>
                </div>
              </div>
              <div className={`text-sm font-bold uppercase tracking-wider ${
                session.severity === 'critical' ? 'text-red-500' :
                session.severity === 'high' ? 'text-orange-500' :
                session.severity === 'medium' ? 'text-yellow-500' :
                'text-green-500'
              }`}>{session.severity}</div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="bg-[var(--color-surface-subcard)] p-4 rounded-lg border border-[var(--color-border-subtle)] text-center">
                <div className="text-xs text-gray-500 mb-1">Anomaly Score</div>
                <div className="text-xl font-mono text-gray-200 font-bold">{session.anomaly_score.toFixed(3)}</div>
              </div>
              <div className="bg-[var(--color-surface-subcard)] p-4 rounded-lg border border-[var(--color-border-subtle)] text-center">
                <div className="text-xs text-gray-500 mb-1">AI Confidence</div>
                <div className="text-xl font-mono text-gray-200 font-bold">{(session.ai_confidence * 100).toFixed(1)}%</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
