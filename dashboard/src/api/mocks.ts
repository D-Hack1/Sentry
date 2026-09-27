import type { Session, SessionListResponse, StatsResponse, HealthResponse } from '../types/api';

export const mockSession: Session = {
  session_id: "tunnel_aes256gcm_group19_pfs_web_001",
  es_id: "AbCdEfGhIjKl",
  ts: new Date().toISOString(),
  initiator_ip: "10.10.0.2",
  responder_ip: "10.10.0.3",
  mode: "tunnel",
  cipher_suite: "aes256_gcm",
  dh_group: "group19",
  pfs_enabled: true,
  ike_version: 2,
  traffic_class: "web",
  traffic_confidence: 0.97,
  anomaly_score: 0.18,
  ai_confidence: 0.82,
  security_score: 100.0,
  severity: "info",
  risk_flags: [],
  evidence: ["High inter-arrival time entropy", "High burst count"],
  report_id: null
};

export const mockSessions: SessionListResponse = {
  items: [
    mockSession,
    {
      ...mockSession,
      session_id: "tunnel_aes128cbc_group2_nopfs_web_007",
      es_id: "XyZ123",
      cipher_suite: "aes128_cbc",
      dh_group: "group2",
      pfs_enabled: false,
      security_score: 15.0,
      severity: "critical",
      risk_flags: ["Weak cipher suite", "PFS disabled"]
    }
  ],
  total: 2,
  page: 1,
  page_size: 20,
  pages: 1
};

export const mockStats: StatsResponse = {
  total_sessions: 842,
  cipher_suite_distribution: { "aes256_gcm": 301, "aes128_gcm": 212, "aes256_cbc": 187, "aes128_cbc": 142 },
  dh_group_distribution: { "group19": 289, "group20": 198, "group14": 201, "group5": 102, "group2": 52 },
  pfs_distribution: { "enabled": 612, "disabled": 230 },
  ike_version_distribution: { "ikev2": 701, "ikev1": 141 },
  severity_distribution: { "critical": 45, "high": 102, "medium": 198, "low": 301, "info": 196 },
  score_histogram: [
    { bucket: "0-9", count: 12 }, { bucket: "10-19", count: 33 }, { bucket: "20-29", count: 0 },
    { bucket: "30-39", count: 0 }, { bucket: "40-49", count: 72 }, { bucket: "50-59", count: 30 },
    { bucket: "60-69", count: 98 }, { bucket: "70-79", count: 100 }, { bucket: "80-89", count: 201 },
    { bucket: "90-100", count: 296 }
  ],
  top_weak_configs: [
    { config: "aes128_cbc + group2 + no_pfs", count: 42, avg_score: 15.2 }
  ],
  traffic_class_distribution: { "web": 212, "file_transfer": 198, "video_stream": 178, "voip": 142, "icmp": 112 }
};

export const mockHealth: HealthResponse = {
  status: "ok",
  uptime_sec: 3600,
  kafka: { connected: true, topics: ["raw-features"] },
  elasticsearch: { connected: true, cluster_status: "yellow", index: "ipsec_sessions", doc_count: 842 },
  models: { protocol_model: true, traffic_model: true, anomaly_model: true }
};
