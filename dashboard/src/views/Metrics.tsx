import { useEffect, useState } from 'react';
import { LineChart, Line, ResponsiveContainer, YAxis } from 'recharts';
import { subscribeToMetrics } from '../api/metrics';
import type { MetricsEvent } from '../types/api';

export default function Metrics() {
  const [metrics, setMetrics] = useState<MetricsEvent[]>([]);
  const [error, setError] = useState<boolean>(false);

  useEffect(() => {
    const unsub = subscribeToMetrics(
      (data) => {
        setError(false);
        setMetrics(prev => {
          const next = [...prev, data];
          if (next.length > 30) next.shift(); // Keep last 30
          return next;
        });
      },
      () => setError(true)
    );
    return unsub;
  }, []);

  const latest = metrics[metrics.length - 1];

  const renderCard = (title: string, value: string | number, dataKey: keyof MetricsEvent, isLatency = false) => {
    let statusColor = '';
    if (isLatency && typeof value === 'number') {
      if (value < 100) statusColor = 'bg-green-500';
      else if (value < 500) statusColor = 'bg-yellow-500';
      else statusColor = 'bg-red-500';
    }

    return (
      <div className="panel p-6 flex flex-col justify-between h-40">
        <div>
          <div className="flex justify-between items-center mb-2">
            <h3 className="text-sm font-medium text-gray-400 uppercase tracking-wider">{title}</h3>
            {isLatency && <div className={`w-3 h-3 rounded-full ${statusColor}`} />}
          </div>
          <div className="text-3xl font-bold font-mono">{value || 0}</div>
        </div>
        <div className="h-12 w-full mt-auto">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={metrics}>
              <YAxis domain={['auto', 'auto']} hide />
              <Line type="monotone" dataKey={dataKey} stroke="#3b82f6" strokeWidth={2} dot={false} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    );
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight mb-1">Pipeline Throughput</h1>
        <p className="text-gray-400 text-sm flex items-center gap-2">
          Real-time event processing metrics
          {error && <span className="text-red-400 bg-red-400/10 px-2 py-0.5 rounded text-xs">Reconnecting...</span>}
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {renderCard("Sessions / sec", latest?.sessions_per_sec.toFixed(1), "sessions_per_sec")}
        {renderCard("MB / sec", latest ? (latest.bytes_per_sec / 1024 / 1024).toFixed(2) : 0, "bytes_per_sec")}
        {renderCard("Kafka Queue", latest?.kafka_queue_depth, "kafka_queue_depth")}
        {renderCard("Latency (ms)", latest?.pipeline_latency_ms.toFixed(0), "pipeline_latency_ms", true)}
      </div>
    </div>
  );
}
