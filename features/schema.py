
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional, List
import json


# ---------------------------------------------------------------------------
# IPsec Feature Row
# ---------------------------------------------------------------------------

@dataclass
class IPsecFeatureRow:
    """
    One row of features extracted from a single IPsec session (one PCAP).

    Sections
    --------
    1. Session identity      — who, when, how long
    2. IKE fields            — parsed from plaintext IKE packets (Aadi fills these)
    3. Inferred config       — derived from IKE negotiation (Aadi fills these)
    4. ESP metadata features — computed from encrypted-payload metadata (Gowri fills these)
    5. Model outputs         — filled by inference.py at runtime (None at feature-extraction time)
    6. Ground-truth labels   — filled from label JSON files (None at inference time)
    """

    # ------------------------------------------------------------------
    # 1. Session identity
    # ------------------------------------------------------------------
    session_id: str
    """Unique capture session ID — matches the PCAP filename stem.
    Format: <mode>_<cipher>_<dh>_<pfs>_<traffic>_<seq>, e.g.
    tunnel_aes256gcm_group19_pfs_web_001"""

    ts: float
    """Session start time as Unix timestamp (float, seconds since epoch)."""

    initiator_ip: str
    """Source IP of the IKE initiator, e.g. '10.10.0.2'."""

    responder_ip: str
    """Destination IP of the IKE responder, e.g. '10.10.0.3'."""

    initiator_port: int
    """UDP port on initiator side. 500 = normal IKE, 4500 = NAT-T."""

    responder_port: int
    """UDP port on responder side. 500 = normal IKE, 4500 = NAT-T."""

    duration: float
    """Total session capture duration in seconds."""

    # ------------------------------------------------------------------
    # 2. IKE fields  (plaintext — Aadi's ike_parser.py fills these)
    # ------------------------------------------------------------------
    ike_version: int
    """IKE protocol version: 1 or 2."""

    ike_exchange_type: int
    """Numeric exchange type of the first IKE message.
    IKEv2: IKE_SA_INIT=34, IKE_AUTH=35, CREATE_CHILD_SA=36, INFORMATIONAL=37.
    IKEv1: Main Mode=2, Aggressive Mode=4."""

    ike_initiator_spi: str
    """Initiator SPI as a hex string, e.g. '0x1a2b3c4d5e6f7a8b'."""

    sa_proposal_count: int
    """Number of SA proposals sent in the IKE_SA_INIT message.
    Higher count = more flexible initiator."""

    ke_dh_group: int
    """Numeric DH group from the Key Exchange payload.
    2=modp1024, 5=modp1536, 14=modp2048, 19=ecp256, 20=ecp384."""

    ike_nat_traversal: bool
    """True if NAT-T was detected (IKE moved from UDP/500 → UDP/4500)."""

    ike_packet_count: int
    """Total number of IKE packets captured in the handshake."""

    ike_handshake_duration: float
    """Seconds from the first to the last IKE packet in the handshake."""

    # ------------------------------------------------------------------
    # 3. Inferred config  (from IKE negotiation — Aadi fills these)
    # ------------------------------------------------------------------
    mode: str
    """Tunnel or transport mode.
    Values: 'tunnel' | 'transport'
    Derived from Traffic Selector payloads: TS 0.0.0.0/0 → tunnel."""

    cipher_suite: str
    """Negotiated encryption algorithm + key length.
    Values: 'aes128_cbc' | 'aes256_cbc' | 'aes128_gcm' | 'aes256_gcm'"""

    auth_algo: str
    """Authentication/integrity algorithm.
    Values: 'hmac_sha1' | 'hmac_sha256' | 'hmac_sha384' | 'aes_gcm' (AEAD, no separate auth)"""

    dh_group: str
    """Human-readable DH group label.
    Values: 'group2' | 'group5' | 'group14' | 'group19' | 'group20'
    Mapped from ke_dh_group by Gowri's ike_field_table.py."""

    pfs_enabled: bool
    """True if Perfect Forward Secrecy is active.
    Detected by presence of a KE payload in CREATE_CHILD_SA."""

    key_lifetime_sec: int
    """SA key lifetime in seconds. Default strongSwan: 3600 (1h) for IKEv2."""

    esp_spi: str
    """ESP Security Parameter Index (hex) for the child SA.
    Extracted from the IKE_AUTH or CREATE_CHILD_SA response."""

    # ------------------------------------------------------------------
    # 4. ESP metadata features  (Gowri's pipeline.py fills these)
    # ------------------------------------------------------------------
    esp_packet_count: int
    """Total number of ESP packets observed in this session."""

    esp_bytes_total: int
    """Total bytes across all ESP packets (IP payload, not including IP/UDP headers)."""

    esp_pkt_size_mean: float
    """Mean ESP packet payload size in bytes."""

    esp_pkt_size_std: float
    """Standard deviation of ESP packet payload sizes."""

    esp_pkt_size_min: float
    """Minimum ESP packet payload size in bytes."""

    esp_pkt_size_max: float
    """Maximum ESP packet payload size in bytes."""

    esp_iat_mean: float
    """Mean inter-arrival time between consecutive ESP packets, in seconds."""

    esp_iat_std: float
    """Standard deviation of ESP packet inter-arrival times."""

    esp_iat_min: float
    """Minimum inter-arrival time between ESP packets, in seconds."""

    esp_iat_max: float
    """Maximum inter-arrival time between ESP packets, in seconds."""

    esp_burst_count: int
    """Number of burst events.
    A burst = consecutive packets with IAT < 10 ms, terminated by a gap > 100 ms."""

    esp_burst_size_mean: float
    """Mean number of ESP packets per burst event."""

    esp_bytes_per_sec: float
    """Throughput: total ESP bytes / session duration."""

    esp_pkts_per_sec: float
    """Packet rate: total ESP packets / session duration."""

    bidir_ratio: float
    """Asymmetry ratio: outbound_bytes / (inbound_bytes + 1).
    High ratio → mostly upload. Low ratio → mostly download."""

    # ------------------------------------------------------------------
    # 5. Model outputs  (inference.py fills these at runtime)
    # ------------------------------------------------------------------
    traffic_class: Optional[str] = None
    """Predicted traffic type inside the ESP tunnel.
    Values: 'web' | 'voip' | 'video_stream' | 'file_transfer' | 'icmp'"""

    traffic_confidence: Optional[float] = None
    """Probability of the predicted traffic class (0.0–1.0)."""

    anomaly_score: Optional[float] = None
    """Isolation Forest anomaly score (higher = more anomalous).
    Computed as -score_samples() so higher is always worse."""

    security_score: Optional[float] = None
    """Rule-based security score (0–100). Higher = more secure.
    Computed by scorer.py. See security_rules.py for penalty table."""

    severity: Optional[str] = None
    """Human severity label derived from security_score.
    Values: 'critical' | 'high' | 'medium' | 'low' | 'info'"""

    risk_flags: Optional[List[str]] = field(default=None)
    """List of triggered security rule descriptions, e.g.
    ['DEPRECATED: DH Group 2 (1024-bit) — broken by Logjam', ...]"""

    ai_confidence: Optional[float] = None
    """Geometric mean of config_model and traffic_model top-class probabilities.
    ai_confidence = sqrt(config_confidence * traffic_confidence)"""

    evidence: Optional[List[str]] = field(default=None)
    """SHAP-derived human-readable explanations for the classification.
    e.g. ['High burst count — consistent with file transfer or streaming', ...]"""

    report_id: Optional[str] = None
    """UUID assigned when a PDF report is generated for this session."""

    # ------------------------------------------------------------------
    # 6. Ground-truth labels  (None at inference time — Sanjay fills these)
    # ------------------------------------------------------------------
    label_config: Optional[str] = None
    """Ground-truth config combo string, e.g. 'tunnel_aes256gcm_group19_pfs'.
    Loaded from data/labels/<session_id>.json."""

    label_traffic: Optional[str] = None
    """Ground-truth traffic class, e.g. 'web'.
    Loaded from data/labels/<session_id>.json."""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialise to a plain dict (suitable for JSON or Kafka publish)."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialise to a JSON string."""
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, d: dict) -> "IPsecFeatureRow":
        """Deserialise from a plain dict (e.g. from Kafka consumer)."""
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    def ike_feature_vector(self) -> list:
        """
        Return only the IKE-derived numeric features used by the protocol
        identification model (Model 1). Consumed by inference.py and train.py.
        Column order must stay stable — add new features at the END only.
        """
        return [
            self.ike_version,
            self.ike_exchange_type,
            self.sa_proposal_count,
            self.ke_dh_group,
            int(self.ike_nat_traversal),
            self.ike_packet_count,
            self.ike_handshake_duration,
            self.initiator_port,
            self.responder_port,
        ]

    def esp_feature_vector(self) -> list:
        """
        Return only the ESP metadata features used by the traffic classification
        model (Model 2) and the Isolation Forest. Column order must stay stable.
        """
        return [
            self.esp_packet_count,
            self.esp_bytes_total,
            self.esp_pkt_size_mean,
            self.esp_pkt_size_std,
            self.esp_pkt_size_min,
            self.esp_pkt_size_max,
            self.esp_iat_mean,
            self.esp_iat_std,
            self.esp_iat_min,
            self.esp_iat_max,
            self.esp_burst_count,
            self.esp_burst_size_mean,
            self.esp_bytes_per_sec,
            self.esp_pkts_per_sec,
            self.bidir_ratio,
        ]

    IKE_FEATURE_NAMES = [
        "ike_version", "ike_exchange_type", "sa_proposal_count",
        "ke_dh_group", "ike_nat_traversal", "ike_packet_count",
        "ike_handshake_duration", "initiator_port", "responder_port",
    ]

    ESP_FEATURE_NAMES = [
        "esp_packet_count", "esp_bytes_total",
        "esp_pkt_size_mean", "esp_pkt_size_std",
        "esp_pkt_size_min", "esp_pkt_size_max",
        "esp_iat_mean", "esp_iat_std", "esp_iat_min", "esp_iat_max",
        "esp_burst_count", "esp_burst_size_mean",
        "esp_bytes_per_sec", "esp_pkts_per_sec", "bidir_ratio",
    ]


# ---------------------------------------------------------------------------
# Report Schema
# ---------------------------------------------------------------------------

@dataclass
class SessionReport:
    """
    Full PDF report data structure.
    Constructed by report_generator.py from an IPsecFeatureRow + ES metadata.
    Passed as context into the Jinja2 HTML template.
    """
    report_id: str
    session_id: str
    generated_at: str           # ISO 8601 datetime string

    # Session metadata
    initiator_ip: str
    responder_ip: str
    session_start: str          # ISO 8601
    session_duration_sec: float

    # IKE summary
    ike_version: int
    mode: str
    cipher_suite: str
    auth_algo: str
    dh_group: str
    pfs_enabled: bool
    key_lifetime_sec: int
    nat_traversal: bool

    # Security assessment
    security_score: float
    severity: str
    risk_flags: List[str]
    recommendations: List[str]  # ordered by impact (highest penalty first)

    # Traffic analysis
    traffic_class: str
    traffic_confidence: float
    anomaly_score: float
    ai_confidence: float
    evidence: List[str]

    # Executive summary (generated by scorer / template)
    executive_summary: str

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Kafka Message Schemas
# ---------------------------------------------------------------------------

@dataclass
class KafkaFeatureMessage:
    """Message published to the 'raw-features' Kafka topic."""
    schema_version: str = "1.0"
    source: str = "watcher"           # "watcher" | "replay"
    feature_row: Optional[dict] = None  # IPsecFeatureRow.to_dict()


@dataclass
class KafkaInferenceResult:
    """Message published to the 'inference-results' Kafka topic."""
    schema_version: str = "1.0"
    session_id: str = ""
    security_score: float = 0.0
    severity: str = ""
    traffic_class: str = ""
    traffic_confidence: float = 0.0
    anomaly_score: float = 0.0
    ai_confidence: float = 0.0
    risk_flags: List[str] = field(default_factory=list)


@dataclass
class KafkaAlert:
    """Message published to the 'alerts' Kafka topic (score < 50 only)."""
    schema_version: str = "1.0"
    session_id: str = ""
    initiator_ip: str = ""
    security_score: float = 0.0
    severity: str = ""
    top_risk_flag: str = ""
    ts: float = 0.0


@dataclass
class KafkaPipelineMetrics:
    """Message published to the 'pipeline-metrics' Kafka topic every 2s."""
    schema_version: str = "1.0"
    ts: str = ""                # ISO 8601
    sessions_per_sec: float = 0.0
    bytes_per_sec: float = 0.0
    kafka_queue_depth: int = 0
    pipeline_latency_ms: float = 0.0


# ---------------------------------------------------------------------------
# Enumerations (use these string constants everywhere — no magic strings)
# ---------------------------------------------------------------------------

class CipherSuite:
    AES128_CBC = "aes128_cbc"
    AES256_CBC = "aes256_cbc"
    AES128_GCM = "aes128_gcm"
    AES256_GCM = "aes256_gcm"
    ALL = [AES128_CBC, AES256_CBC, AES128_GCM, AES256_GCM]


class DHGroup:
    GROUP2  = "group2"
    GROUP5  = "group5"
    GROUP14 = "group14"
    GROUP19 = "group19"
    GROUP20 = "group20"
    ALL = [GROUP2, GROUP5, GROUP14, GROUP19, GROUP20]


class TunnelMode:
    TUNNEL    = "tunnel"
    TRANSPORT = "transport"
    ALL = [TUNNEL, TRANSPORT]


class TrafficClass:
    WEB           = "web"
    VOIP          = "voip"
    VIDEO_STREAM  = "video_stream"
    FILE_TRANSFER = "file_transfer"
    ICMP          = "icmp"
    ALL = [WEB, VOIP, VIDEO_STREAM, FILE_TRANSFER, ICMP]


class Severity:
    CRITICAL = "critical"   # score < 40
    HIGH     = "high"       # score < 60
    MEDIUM   = "medium"     # score < 75
    LOW      = "low"        # score < 90
    INFO     = "info"       # score >= 90