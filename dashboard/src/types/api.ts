export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type TrafficClass = 'web' | 'voip' | 'video_stream' | 'file_transfer' | 'icmp';

export interface Correlation {
  initiator_ip?: string;
  weak_session_count?: number;
  pattern_detected?: boolean;
  pattern_description?: string;
  correlation_confidence?: number;
  recommended_action?: string;
}

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

  // null only when neither the IKE parser nor the protocol model could determine it
  mode: 'tunnel' | 'transport' | null;
  cipher_suite: string | null;
  auth_algo?: string | null;
  dh_group: string | null;
  pfs_enabled: boolean | null;
  key_lifetime_sec?: number | null;
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

  traffic_class: TrafficClass;
  traffic_confidence: number;
  anomaly_score: number;
  ai_confidence: number;
  security_score: number;
  severity: Severity;
  risk_flags: string[];
  // Full record only (GET /sessions/{id}); list items omit it.
  evidence?: string[];
  report_id?: string | null;

  // Extensions beyond API_CONTRACT v1.2 (all optional)
  anomaly_label?: 'normal' | 'slightly_unusual' | 'anomalous';
  recommendations?: string[];
  config_evidence?: string[];
  config_source?: Partial<Record<'mode' | 'cipher_suite' | 'dh_group' | 'pfs_enabled', 'parser' | 'model'>>;
  predicted_config?: string;
  config_confidence?: number;
  adjusted_security_score?: number;
  adjusted_severity?: Severity;
  correlation?: Correlation;
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
    missing_topics?: string[];
    detail?: string;
  };
  elasticsearch: {
    connected: boolean;
    cluster_status: string;
    index: string;
    doc_count: number;
    detail?: string;
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
    detail: unknown;
  };
}
