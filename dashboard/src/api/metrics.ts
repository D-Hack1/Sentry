import { API_BASE_URL, USE_MOCKS } from './client';
import type { MetricsEvent } from '../types/api';

export function subscribeToMetrics(onMessage: (data: MetricsEvent) => void, onError?: (err: Event) => void): () => void {
  if (USE_MOCKS) {
    let ts = Date.now();
    const interval = setInterval(() => {
      ts += 2000;
      onMessage({
        ts: new Date(ts).toISOString(),
        sessions_per_sec: Math.random() * 10,
        bytes_per_sec: Math.random() * 100000,
        kafka_queue_depth: Math.floor(Math.random() * 10),
        pipeline_latency_ms: 20 + Math.random() * 200
      });
    }, 2000);
    return () => clearInterval(interval);
  }

  const es = new EventSource(`${API_BASE_URL}/metrics`);
  
  es.onmessage = (e) => {
    try {
      const metrics = JSON.parse(e.data);
      onMessage(metrics);
    } catch (err) {
      console.error('Failed to parse metrics SSE data', err);
    }
  };

  if (onError) {
    es.onerror = onError;
  }

  return () => {
    es.close();
  };
}
