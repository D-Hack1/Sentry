# API Contract — IPsec VPN Analyzer
> **Author:** Ebin | **Version:** 1.2 | **Last updated:** Day 1 (revised)


---

## Base URL

```
http://localhost:8000
```

All responses are JSON. All timestamps are ISO 8601 strings unless noted.

---

## Error Envelope

All errors use this shape:

```json
{
  "error": {
    "code": "SESSION_NOT_FOUND",
    "message": "No session found with id 'abc123'",
    "detail": null
  }
}
```

| HTTP status | When used |
|---|---|
| 200 | Success |
| 400 | Bad request / invalid params |
| 404 | Resource not found |
| 422 | Validation error (malformed body) |
| 500 | Internal server / model error |
| 503 | Upstream dependency down (Kafka / ES) |

---

## Pagination Format

Endpoints that return lists use:

```json
{
  "items": [ ... ],
  "total": 842,
  "page": 1,
  "page_size": 20,
  "pages": 43
}
```

Default `page=1`, `page_size=20`. Max `page_size=100`.

---

## Severity Thresholds

Used by `security_score` → `severity` mapping everywhere in the API.

| Score range | Severity |
|---|---|
| < 40 | `critical` |
| 40 – 59 | `high` |
| 60 – 74 | `medium` |
| 75 – 89 | `low` |
| ≥ 90 | `info` |

---

## Anomaly Score Interpretation

`anomaly_score` is a continuous float ≥ 0. Higher = more anomalous.

| Range | Label | Meaning |
|---|---|---|
| < 0.40 | `normal` | Within learned distribution of benign sessions |
| 0.40 – 0.54 | `slightly_unusual` | Warrants a second look |
| ≥ 0.55 | `anomalous` | Significantly outside normal — inspect manually |

> Thresholds are heuristic on synthetic training data. Recalibrate after training on real PCAPs.

---

## Model Artefacts

| File | Contents |
|---|---|
| `ml/protocol_model.joblib` | XGBClassifier — IKE features → combined config label |
| `ml/traffic_model.joblib` | XGBClassifier — ESP features (18) → traffic class |
| `ml/anomaly_model.joblib` | IsolationForest — ESP features (18) → anomaly score |
| `ml/encoder.joblib` | Dict: `protocol_encoder` (LabelEncoder) + `traffic_encoder` (LabelEncoder) |
| `ml/optuna_study_traffic.pkl` | Pickled Optuna Study for traffic model hyperparameter search |

---

## Endpoints

---

### POST /analyze

Accepts a raw feature row, runs all three models + scorer + SHAP, saves to ES.

**Request body** — `IPsecFeatureRow` sections 1–4, all fields required:

```json
{
  "session_id": "tunnel_aes256gcm_group19_pfs_web_001",
  "ts": 1751234567.0,
  "initiator_ip": "10.10.0.2",
  "responder_ip": "10.10.0.3",
  "initiator_port": 500,
  "responder_port": 500,
  "duration": 62.4,

  "ike_version": 2,
  "ike_exchange_type": 34,
  "ike_initiator_spi": "0x1a2b3c4d5e6f7a8b",
  "sa_proposal_count": 3,
  "ke_dh_group": 19,
  "ike_nat_traversal": false,
  "ike_packet_count": 6,
  "ike_handshake_duration": 0.14,

  "mode": "tunnel",
  "cipher_suite": "aes256_gcm",
  "auth_algo": "aes_gcm",
  "dh_group": "group19",
  "pfs_enabled": true,
  "key_lifetime_sec": 3600,
  "esp_spi": "0xdeadbeef",

  "esp_packet_count": 1843,
  "esp_bytes_total": 2107392,
  "esp_pkt_size_mean": 1143.2,
  "esp_pkt_size_std": 312.1,
  "esp_pkt_size_min": 68.0,
  "esp_pkt_size_max": 1500.0,
  "esp_iat_mean": 0.033,
  "esp_iat_std": 0.021,
  "esp_iat_min": 0.001,
  "esp_iat_max": 0.812,
  "esp_burst_count": 14,
  "esp_burst_size_mean": 7.3,
  "esp_bytes_per_sec": 33828.1,
  "esp_pkts_per_sec": 29.6,
  "asymmetry_ratio": 0.82,
  "esp_pkt_size_entropy": 3.71,
  "esp_iat_entropy": 2.84,
  "esp_active_fraction": 0.91
}
```

**ESP field quick-reference:**

| Field | Type | Description |
|---|---|---|
| `asymmetry_ratio` | float | outbound_bytes / (inbound_bytes + 1). High = upload-heavy, Low = download-heavy |
| `esp_pkt_size_entropy` | float (bits) | Shannon entropy of packet size histogram (64-byte bins). Low = regular sizes (VoIP/ICMP), High = varied (web/video) |
| `esp_iat_entropy` | float (bits) | Shannon entropy of inter-arrival time histogram (5 ms bins). Low = regular timing (VoIP), High = bursty (web/file) |
| `esp_active_fraction` | float [0,1] | Fraction of session with active traffic (gaps < 500 ms). Near 1 = sustained flow (video/VoIP), Near 0 = sparse (ICMP/idle) |

**Response 200:**

```json
{
  "session_id": "tunnel_aes256gcm_group19_pfs_web_001",
  "es_id": "AbCdEfGhIjKl",

  "ike_version": 2,
  "mode": "tunnel",
  "cipher_suite": "aes256_gcm",
  "dh_group": "group19",
  "pfs_enabled": true,

  "traffic_class": "web",
  "traffic_confidence": 0.9712,

  "anomaly_score": 0.183,
  "ai_confidence": 0.821,

  "security_score": 100.0,
  "severity": "info",

  "risk_flags": [],

  "evidence": [
    "High inter-arrival time entropy — consistent with web browsing",
    "High burst count — consistent with web browsing",
    "Low mean inter-arrival time — consistent with web browsing",
    "High packet rate (pkts/sec) — consistent with web browsing",
    "High packet size entropy — consistent with web browsing"
  ]
}
```

**Response field reference:**

| Field | Type | Range | Description |
|---|---|---|---|
| `session_id` | str | — | Passed through from input |
| `es_id` | str | — | Elasticsearch document ID — use this for `/sessions/{id}` and `/report/{id}` |
| `ike_version` | int | 1 or 2 | From IKE parser or protocol model |
| `mode` | str | `tunnel` \| `transport` | From IKE parser or protocol model |
| `cipher_suite` | str | see enums | From IKE parser or protocol model |
| `dh_group` | str | see enums | From IKE parser or protocol model |
| `pfs_enabled` | bool | — | From IKE parser or protocol model |
| `traffic_class` | str | `web` \| `voip` \| `video_stream` \| `file_transfer` \| `icmp` | Traffic model prediction |
| `traffic_confidence` | float | [0.0, 1.0] | Softmax probability of predicted traffic class |
| `anomaly_score` | float | ≥ 0 | IsolationForest score, negated — higher = more anomalous |
| `ai_confidence` | float | [0.0, 1.0] | `sqrt(config_conf × traffic_conf)` geometric mean |
| `security_score` | float | [0, 100] | Deterministic rule-based score — higher = more secure |
| `severity` | str | `critical` \| `high` \| `medium` \| `low` \| `info` | Derived from security_score, see thresholds above |
| `risk_flags` | list[str] | — | Human-readable fired security rule descriptions. Empty array `[]` when none |
| `evidence` | list[str] | — | SHAP top-5 natural-language explanations. Always ≥ 1 string |

---

### GET /sessions

List sessions with optional filtering and pagination.

**Query params:**

| Param | Type | Example | Notes |
|---|---|---|---|
| `severity` | string | `critical` | Filter by severity label |
| `cipher_suite` | string | `aes128_cbc` | Filter by cipher suite |
| `mode` | string | `tunnel` | `tunnel` or `transport` |
| `pfs_enabled` | bool | `false` | |
| `traffic_class` | string | `voip` | |
| `ike_version` | int | `1` | Filter IKEv1-only sessions |
| `start_time` | ISO 8601 | `2025-01-01T00:00:00Z` | Session timestamp ≥ |
| `end_time` | ISO 8601 | `2025-01-02T00:00:00Z` | Session timestamp ≤ |
| `page` | int | `1` | Default 1 |
| `page_size` | int | `20` | Default 20, max 100 |

**Response 200:**

```json
{
  "items": [
    {
      "session_id": "tunnel_aes128cbc_group2_nopfs_web_007",
      "es_id": "XyZ123",
      "ts": "2025-01-01T10:32:11Z",
      "initiator_ip": "10.10.0.2",
      "responder_ip": "10.10.0.3",
      "ike_version": 1,
      "mode": "tunnel",
      "cipher_suite": "aes128_cbc",
      "dh_group": "group2",
      "pfs_enabled": false,
      "traffic_class": "web",
      "traffic_confidence": 0.87,
      "security_score": 15.0,
      "severity": "critical",
      "anomaly_score": 0.21,
      "ai_confidence": 0.83
    }
  ],
  "total": 284,
  "page": 1,
  "page_size": 20,
  "pages": 15
}
```

> List items are intentionally compact — they omit raw ESP fields.
> Fetch `GET /sessions/{id}` for the full record including all ESP metadata.

---

### GET /sessions/{id}

Full detail for a single session. `{id}` is the `es_id` from any list or analyze response.

**Response 200:**

```json
{
  "session_id": "tunnel_aes256gcm_group19_pfs_web_001",
  "es_id": "AbCdEfGhIjKl",
  "ts": "2025-01-01T10:00:00Z",
  "duration": 62.4,

  "initiator_ip": "10.10.0.2",
  "responder_ip": "10.10.0.3",
  "initiator_port": 500,
  "responder_port": 500,

  "ike_version": 2,
  "ike_exchange_type": 34,
  "ike_initiator_spi": "0x1a2b3c4d5e6f7a8b",
  "sa_proposal_count": 3,
  "ke_dh_group": 19,
  "ike_nat_traversal": false,
  "ike_packet_count": 6,
  "ike_handshake_duration": 0.14,

  "mode": "tunnel",
  "cipher_suite": "aes256_gcm",
  "auth_algo": "aes_gcm",
  "dh_group": "group19",
  "pfs_enabled": true,
  "key_lifetime_sec": 3600,
  "esp_spi": "0xdeadbeef",

  "esp_packet_count": 1843,
  "esp_bytes_total": 2107392,
  "esp_pkt_size_mean": 1143.2,
  "esp_pkt_size_std": 312.1,
  "esp_pkt_size_min": 68.0,
  "esp_pkt_size_max": 1500.0,
  "esp_iat_mean": 0.033,
  "esp_iat_std": 0.021,
  "esp_iat_min": 0.001,
  "esp_iat_max": 0.812,
  "esp_burst_count": 14,
  "esp_burst_size_mean": 7.3,
  "esp_bytes_per_sec": 33828.1,
  "esp_pkts_per_sec": 29.6,
  "asymmetry_ratio": 0.82,
  "esp_pkt_size_entropy": 3.71,
  "esp_iat_entropy": 2.84,
  "esp_active_fraction": 0.91,

  "traffic_class": "web",
  "traffic_confidence": 0.9712,
  "anomaly_score": 0.183,
  "ai_confidence": 0.821,
  "security_score": 100.0,
  "severity": "info",
  "risk_flags": [],
  "evidence": [
    "High inter-arrival time entropy — consistent with web browsing",
    "High burst count — consistent with web browsing"
  ],
  "report_id": null
}
```

**Response 404:**

```json
{ "error": { "code": "SESSION_NOT_FOUND", "message": "No session with id 'AbCdEfGhIjKl'", "detail": null } }
```

---

### GET /report/{id}

Generate and return a PDF security assessment report for a session.
`{id}` is the `es_id` from any session response.

**Response 200:**
- `Content-Type: application/pdf`
- `Content-Disposition: attachment; filename="ipsec_report_<session_id>.pdf"`
- Body: binary PDF

**Response 404:** Session not found — same error envelope as above.

> Jaith: trigger a browser download on this response. Do not try to render it inline.
> Use `window.URL.createObjectURL(blob)` + a temporary `<a>` element.

---

### GET /stats

Aggregate statistics across all sessions in Elasticsearch.

**Response 200:**

```json
{
  "total_sessions": 842,
  "cipher_suite_distribution": {
    "aes256_gcm": 301,
    "aes128_gcm": 212,
    "aes256_cbc": 187,
    "aes128_cbc": 142
  },
  "dh_group_distribution": {
    "group19": 289,
    "group20": 198,
    "group14": 201,
    "group5":  102,
    "group2":   52
  },
  "pfs_distribution": {
    "enabled": 612,
    "disabled": 230
  },
  "ike_version_distribution": {
    "ikev2": 701,
    "ikev1": 141
  },
  "severity_distribution": {
    "critical": 45,
    "high": 102,
    "medium": 198,
    "low": 301,
    "info": 196
  },
  "score_histogram": [
    { "bucket": "0-9",   "count": 12 },
    { "bucket": "10-19", "count": 33 },
    { "bucket": "20-29", "count": 0  },
    { "bucket": "30-39", "count": 0  },
    { "bucket": "40-49", "count": 72 },
    { "bucket": "50-59", "count": 30 },
    { "bucket": "60-69", "count": 98 },
    { "bucket": "70-79", "count": 100 },
    { "bucket": "80-89", "count": 201 },
    { "bucket": "90-100","count": 296 }
  ],
  "top_weak_configs": [
    { "config": "aes128_cbc + group2 + no_pfs", "count": 42, "avg_score": 15.2 },
    { "config": "aes256_cbc + group5 + no_pfs", "count": 31, "avg_score": 30.0 }
  ],
  "traffic_class_distribution": {
    "web": 212,
    "file_transfer": 198,
    "video_stream": 178,
    "voip": 142,
    "icmp": 112
  }
}
```

---

### GET /metrics  (SSE)

Server-Sent Events stream of pipeline throughput metrics.
Connect with the browser's `EventSource` API — no auth required.

**How to connect (JS):**
```js
const es = new EventSource("http://localhost:8000/metrics");
es.onmessage = (e) => {
  const metrics = JSON.parse(e.data);
};
es.onerror = () => {
  // reconnect with exponential backoff — the stream never intentionally closes
};
```

**SSE message format** — emitted every 2 seconds:

```
data: {"ts":"2025-01-01T10:05:02Z","sessions_per_sec":2.1,"bytes_per_sec":71200,"kafka_queue_depth":3,"pipeline_latency_ms":48.2}

```

*(The blank line after `data:` is required by the SSE spec.)*

**Fields:**

| Field | Type | Description |
|---|---|---|
| `ts` | string (ISO 8601) | Timestamp of this measurement |
| `sessions_per_sec` | float | Sessions processed in the last 2-second window |
| `bytes_per_sec` | float | ESP bytes processed in the last 2-second window |
| `kafka_queue_depth` | int | Consumer group lag on `raw-features` topic |
| `pipeline_latency_ms` | float | Median end-to-end latency: feature publish → inference result stored |

**Status dot mapping (for Jaith's sparkline panel):**

| `pipeline_latency_ms` | Colour |
|---|---|
| < 100 | green |
| 100 – 499 | yellow |
| ≥ 500 | red |

---

### GET /health

System health check. Used by Jaith's global status bar.
**Always returns HTTP 200** — even when dependencies are degraded. Check `status` in the body.

**Response 200:**

```json
{
  "status": "ok",
  "uptime_sec": 3612,
  "kafka": {
    "connected": true,
    "topics": ["raw-features", "inference-results", "alerts", "pipeline-metrics"]
  },
  "elasticsearch": {
    "connected": true,
    "cluster_status": "yellow",
    "index": "ipsec_sessions",
    "doc_count": 842
  },
  "models": {
    "protocol_model": true,
    "traffic_model": true,
    "anomaly_model": true
  }
}
```

When any dependency is down: its `connected` field is `false`, and top-level `status` becomes `"degraded"`.

---

## CORS

Allowed origin: `http://localhost:5173` (Vite dev server).

---

## Notes for Jaith

**Field naming**
- `bidir_ratio` is gone — it's now `asymmetry_ratio`. Update your TypeScript interface.
- There are 3 new ESP fields in the `POST /analyze` request and `GET /sessions/{id}` response:
  `esp_pkt_size_entropy`, `esp_iat_entropy`, `esp_active_fraction`.
- Use `es_id` (not `session_id`) as the path param in `/sessions/{id}` and `/report/{id}`.

**Nullability**
- `risk_flags` is always `[]` (never `null`) when there are no active flags.
- `evidence` always has ≥ 1 string (the API never returns an empty evidence list).
- `report_id` is `null` until a PDF has been generated for that session.

**Confidence values**
- All float confidence fields (`traffic_confidence`, `ai_confidence`) are in `[0.0, 1.0]`.
- `security_score` is in `[0, 100]`. Higher = more secure.
- `anomaly_score` is ≥ 0. Higher = more anomalous. See anomaly thresholds table above.

**SSE**
- `/metrics` never closes intentionally — implement reconnect with exponential backoff.
- Each `data:` message is a single JSON line — `JSON.parse(e.data)` is safe.

**PDF download**
- `/report/{id}` streams a binary PDF. Do not try to render it inline.
- Suggested implementation:
  ```js
  const blob = await fetch(`/report/${esId}`).then(r => r.blob());
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = `report_${sessionId}.pdf`; a.click();
  URL.revokeObjectURL(url);
  ```