import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { Lock, Unlock, AlertTriangle, Info, ArrowRight } from 'lucide-react';
import { getSessions } from '../api/sessions';
import type { Session } from '../types/api';

// removed severityColors

function SessionCard({ session }: { session: Session }) {
  const navigate = useNavigate();

  return (
    <div 
      onClick={() => navigate(`/sessions/${session.es_id}`)}
      className="panel panel-hover p-4 cursor-pointer group"
    >
      <div className="flex justify-between items-start mb-4">
        <div>
          <div className="text-xs text-gray-500 mb-1">{new Date(session.ts).toLocaleString()}</div>
          <div className="flex items-center gap-2 font-mono text-sm">
            <span className="text-gray-300">{session.initiator_ip}</span>
            <ArrowRight size={14} className="text-gray-600" />
            <span className="text-gray-300">{session.responder_ip}</span>
          </div>
        </div>
        <div className={`badge-neon badge-${session.severity}`}>
          {session.severity}
        </div>
      </div>

      <div className="grid grid-cols-4 gap-4 mt-4 text-sm bg-black/20 p-3 rounded-lg border border-[var(--color-border-subtle)]">
        <div>
          <div className="text-gray-500 text-xs mb-1">Mode</div>
          <div className="capitalize">{session.mode}</div>
        </div>
        <div>
          <div className="text-gray-500 text-xs mb-1">Cipher Suite</div>
          <div className="font-mono text-xs text-blue-400">{session.cipher_suite}</div>
        </div>
        <div>
          <div className="text-gray-500 text-xs mb-1">DH Group</div>
          <div className="font-mono text-xs">{session.dh_group}</div>
        </div>
        <div>
          <div className="text-gray-500 text-xs mb-1">PFS</div>
          <div className="flex items-center gap-1">
            {session.pfs_enabled ? (
              <><Lock size={14} className="text-green-500"/> <span className="text-green-500">Enabled</span></>
            ) : (
              <><Unlock size={14} className="text-red-500"/> <span className="text-red-500">Disabled</span></>
            )}
          </div>
        </div>
      </div>
      
      <div className="mt-4 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="relative w-12 h-12 flex items-center justify-center">
            <svg className="w-full h-full transform -rotate-90">
              <circle cx="24" cy="24" r="20" stroke="currentColor" strokeWidth="4" fill="none" className="text-gray-800" />
              <circle cx="24" cy="24" r="20" stroke="currentColor" strokeWidth="4" fill="none" 
                strokeDasharray="125.6" 
                strokeDashoffset={125.6 - (125.6 * session.security_score) / 100}
                className={
                  session.security_score < 40 ? 'text-red-500' :
                  session.security_score < 75 ? 'text-yellow-500' : 'text-green-500'
                }
              />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center text-xs font-bold">
              {Math.round(session.security_score)}
            </div>
          </div>
          <div className="text-xs text-gray-400">Security Score</div>
        </div>
        <div className="flex gap-2">
           {session.risk_flags.length > 0 && (
             <span className="badge-neon badge-critical flex items-center gap-1">
               <AlertTriangle size={12} /> {session.risk_flags.length} risks
             </span>
           )}
           <span className="badge-neon badge-purple flex items-center gap-1">
             {session.traffic_class}
           </span>
        </div>
      </div>
    </div>
  );
}

export default function LiveSessions() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['sessions'],
    queryFn: () => getSessions({ page: 1, page_size: 20 }),
    refetchInterval: 5000
  });

  if (isLoading) {
    return <div className="space-y-4">
      {[...Array(3)].map((_, i) => (
        <div key={i} className="h-48 skeleton" />
      ))}
    </div>;
  }

  if (isError) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-red-500 border border-red-500/20 bg-red-500/10 rounded-xl">
        <AlertTriangle size={32} className="mb-2" />
        <div>Unable to reach API — check backend connection</div>
      </div>
    );
  }

  if (!data || data.items.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-gray-500 border border-dashed border-gray-800 rounded-xl">
        <Info size={32} className="mb-2" />
        <div>No VPN sessions analysed yet — awaiting captures</div>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-2xl font-bold tracking-tight mb-1">Live Sessions</h1>
          <p className="text-gray-400 text-sm">Real-time analysis of IPsec VPN traffic</p>
        </div>
        <div className="text-xs text-gray-500">Auto-refreshing every 5s</div>
      </div>
      
      <div className="grid gap-4">
        {data.items.map(session => (
          <SessionCard key={session.es_id} session={session} />
        ))}
      </div>
    </div>
  );
}
