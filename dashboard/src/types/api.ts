export interface Session {
  session_id: string;
  es_id: string;
  ts: string;
  initiator_ip: string;
  responder_ip: string;
  initiator_port?: number;
  responder_port?: number;
  duration?: number;
  
  ike_version: number;
  ike_exchange_type?: number;
  ike_initiator_spi?: string;
  sa_proposal_count?: number;
  ke_dh_group?: number;
  ike_nat_traversal?: boolean;
  ike_packet_count?: number;
  ike_handshake_duration?: number;
  
  mode: 'tunnel' | 'transport';
  cipher_suite: string;
  auth_algo?: string;
  dh_group: string;
  pfs_enabled: boolean;
  key_lifetime_sec?: number;
  esp_spi?: string;
  
  esp_packet_count?: number;
  esp_bytes_total?: number;
  esp_pkt_size_mean?: number;
  esp_pkt_size_std?: number;
  esp_pkt_size_min?: number;
  esp_pkt_size_max?: number;
  esp_iat_mean?: number;
  esp_iat_std?: number;
  esp_iat_min?: number;
  esp_iat_max?: number;
  esp_burst_count?: number;
  esp_burst_size_mean?: number;
  esp_bytes_per_sec?: number;
  esp_pkts_per_sec?: number;
  asymmetry_ratio?: number;
  esp_pkt_size_entropy?: number;
  esp_iat_entropy?: number;
  esp_active_fraction?: number;
  
  traffic_class: 'web' | 'voip' | 'video_stream' | 'file_transfer' | 'icmp';
  traffic_confidence: number;
  anomaly_score: number;
  ai_confidence: number;
  security_score: number;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  risk_flags: string[];
  evidence: string[];
  report_id?: string | null;
}

export interface SessionListResponse {
  items: Session[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface ScoreBucket {
  bucket: string;
  count: number;
}

export interface WeakConfig {
  config: string;
  count: number;
  avg_score: number;
}

export interface StatsResponse {
  total_sessions: number;
  cipher_suite_distribution: Record<string, number>;
  dh_group_distribution: Record<string, number>;
  pfs_distribution: Record<string, number>;
  ike_version_distribution: Record<string, number>;
  severity_distribution: Record<string, number>;
  score_histogram: ScoreBucket[];
  top_weak_configs: WeakConfig[];
  traffic_class_distribution: Record<string, number>;
}

export interface MetricsEvent {
  ts: string;
  sessions_per_sec: number;
  bytes_per_sec: number;
  kafka_queue_depth: number;
  pipeline_latency_ms: number;
}

export interface HealthResponse {
  status: 'ok' | 'degraded';
  uptime_sec: number;
  kafka: {
    connected: boolean;
    topics: string[];
  };
  elasticsearch: {
    connected: boolean;
    cluster_status: string;
    index: string;
    doc_count: number;
  };
  models: {
    protocol_model: boolean;
    traffic_model: boolean;
    anomaly_model: boolean;
  };
}

export interface ErrorEnvelope {
  error: {
    code: string;
    message: string;
    detail: any | null;
  };
}
