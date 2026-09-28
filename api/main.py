"""
api/main.py — FastAPI application for IPsec VPN Protocol Analyzer
WITH CORRELATOR INTEGRATION
"""

import os
import json
import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional, AsyncGenerator

import joblib
import numpy as np
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, Response
from elasticsearch import AsyncElasticsearch, NotFoundError
from kafka import KafkaConsumer
from pydantic import BaseModel

# ── Internal imports ──────────────────────────────────────────────────────────
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from features.schema import IPsecFeatureRow
from ml.inference import infer
from ml.scorer import score_session
from ml.explainability import explain_config, explain_traffic
from api.report_generator import generate_pdf_report
from api.correlator import SessionCorrelator, create_correlator  # ← NEW

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Env / config ──────────────────────────────────────────────────────────────
ES_HOST          = os.getenv("ES_HOST", "localhost")
ES_PORT          = int(os.getenv("ES_PORT", "9200"))
KAFKA_BOOTSTRAP  = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
ES_INDEX         = "ipsec_sessions"
METRICS_TOPIC    = "pipeline-metrics"
MODEL_DIR        = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ml")

# ── App state (populated at startup) ─────────────────────────────────────────
class AppState:
    es: Optional[AsyncElasticsearch] = None
    protocol_model = None
    traffic_model  = None
    iso_forest     = None
    encoder        = None
    correlator: Optional[SessionCorrelator] = None  # ← NEW
    models_loaded: bool = False
    startup_time: datetime = None

state = AppState()


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ───────────────────────────────────────────────────────────────
    state.startup_time = datetime.now(timezone.utc)

    # Load models — fail fast if any are missing
    required_files = {
        "protocol_model": "protocol_model.joblib",
        "traffic_model":  "traffic_model.joblib",
        "iso_forest":     "iso_forest.joblib",
        "encoder":        "encoder.joblib",
    }
    for attr, fname in required_files.items():
        fpath = os.path.join(MODEL_DIR, fname)
        if not os.path.exists(fpath):
            raise RuntimeError(
                f"Required model file missing: {fpath}. "
                "Run ml/train.py before starting the API."
            )
        setattr(state, attr, joblib.load(fpath))
        logger.info(f"Loaded {fname}")

    state.models_loaded = True
    logger.info("All models loaded successfully.")

    # Connect to Elasticsearch
    state.es = AsyncElasticsearch(
        [{"host": ES_HOST, "port": ES_PORT, "scheme": "http"}]
    )
    logger.info(f"Elasticsearch client connected to {ES_HOST}:{ES_PORT}")

    # Initialize Correlator with ES client  ← NEW
    state.correlator = create_correlator(state.es, ES_INDEX)
    logger.info("Session Correlator initialized.")

    yield

    # ── Shutdown ──────────────────────────────────────────────────────────────
    await state.es.close()
    logger.info("Elasticsearch client closed.")


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="IPsec VPN Protocol Analyzer",
    version="1.0.0",
    description="AI-powered IPsec session analysis and security assessment API",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ══════════════════════════════════════════════════════════════════════════════
# POST /analyze  ← UPDATED WITH CORRELATOR
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/analyze")
async def analyze(row: IPsecFeatureRow):
    """
    Run all models on a feature row and persist to Elasticsearch.
    Returns full enriched session document WITH correlation metadata.
    """
    feature_dict = row.model_dump()

    # 1 + 2 + 3 — inference (protocol ID, traffic class, anomaly)
    inference_result = infer(
        feature_dict,
        protocol_model=state.protocol_model,
        traffic_model=state.traffic_model,
        iso_forest=state.iso_forest,
        encoder=state.encoder,
    )

    # 4 — security scoring (deterministic rule-based)
    score_result = score_session(feature_dict)

    # 5 — SHAP explainability
    evidence_config  = explain_config(feature_dict,  state.protocol_model, state.encoder)
    evidence_traffic = explain_traffic(feature_dict, state.traffic_model,  state.encoder)

    # Build the session document (before correlation)
    session_doc = {
        "session_id":           row.session_id,
        "timestamp":            datetime.fromtimestamp(row.ts, tz=timezone.utc).isoformat(),
        "initiator_ip":         row.initiator_ip,
        "responder_ip":         row.responder_ip,
        # IKE config (parsed + model-predicted)
        "ike_version":          row.ike_version,
        "mode":                 inference_result["predicted_config"].get("mode", row.mode),
        "cipher_suite":         inference_result["predicted_config"].get("cipher_suite", row.cipher_suite),
        "dh_group":             inference_result["predicted_config"].get("dh_group", row.dh_group),
        "pfs_enabled":          inference_result["predicted_config"].get("pfs_enabled", row.pfs_enabled),
        "key_lifetime_sec":     row.key_lifetime_sec,
        # Traffic classification
        "traffic_class":        inference_result["traffic_class"],
        "traffic_confidence":   inference_result["traffic_confidence"],
        # Security assessment
        "security_score":       score_result["security_score"],
        "severity":             score_result["severity"],
        "risk_flags":           score_result["risk_flags"],
        "recommendations":      score_result["recommendations"],
        # AI signals
        "anomaly_score":        inference_result["anomaly_score"],
        "ai_confidence":        inference_result["ai_confidence"],
        "config_confidence":    inference_result["config_confidence"],
        # SHAP evidence
        "evidence": {
            "config":  evidence_config,
            "traffic": evidence_traffic,
        },
        # Report placeholder
        "report_id": None,
    }

    # ── NEW: Run correlation analysis ────────────────────────────────────────
    session_doc = await state.correlator.correlate(session_doc)
    # Now session_doc has:
    #   - correlation: {...with pattern_detected, weak_session_count, etc.}
    #   - adjusted_security_score: int
    #   - adjusted_severity: str

    logger.info(
        f"Session {row.session_id} analyzed — "
        f"score={session_doc['security_score']} → adjusted={session_doc['adjusted_security_score']}, "
        f"pattern_detected={session_doc['correlation'].get('pattern_detected')}"
    )

    # 6 — Persist to Elasticsearch (including correlation metadata)
    await state.es.index(
        index=ES_INDEX,
        id=row.session_id,
        document=session_doc,
    )

    return session_doc


# ══════════════════════════════════════════════════════════════════════════════
# GET /sessions  ← UPDATED TO INCLUDE CORRELATION FILTERS
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/sessions")
async def list_sessions(
    severity:           Optional[str]  = Query(None, description="critical|high|medium|low|info"),
    cipher_suite:       Optional[str]  = Query(None),
    mode:               Optional[str]  = Query(None, description="tunnel|transport"),
    pfs_enabled:        Optional[bool] = Query(None),
    start_time:         Optional[str]  = Query(None, description="ISO 8601 datetime"),
    end_time:           Optional[str]  = Query(None, description="ISO 8601 datetime"),
    pattern_detected:   Optional[bool] = Query(None, description="Filter by correlation pattern"),
    initiator_ip:       Optional[str]  = Query(None, description="Filter by initiator IP"),
    page:               int            = Query(1, ge=1),
    page_size:          int            = Query(20, ge=1, le=100),
):
    """
    Paginated session listing with optional filters, including new correlation filters.
    """
    must_clauses = []

    if severity:
        must_clauses.append({"term": {"adjusted_severity": severity}})  # Use adjusted_severity
    if cipher_suite:
        must_clauses.append({"term": {"cipher_suite": cipher_suite}})
    if mode:
        must_clauses.append({"term": {"mode": mode}})
    if pfs_enabled is not None:
        must_clauses.append({"term": {"pfs_enabled": pfs_enabled}})
    if start_time or end_time:
        range_filter: dict = {}
        if start_time:
            range_filter["gte"] = start_time
        if end_time:
            range_filter["lte"] = end_time
        must_clauses.append({"range": {"timestamp": range_filter}})
    if pattern_detected is not None:
        must_clauses.append({"term": {"correlation.pattern_detected": pattern_detected}})
    if initiator_ip:
        must_clauses.append({"term": {"initiator_ip": initiator_ip}})

    es_query = {
        "query": {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}},
        "sort":  [{"timestamp": {"order": "desc"}}],
        "from":  (page - 1) * page_size,
        "size":  page_size,
    }

    resp = await state.es.search(index=ES_INDEX, body=es_query)
    total = resp["hits"]["total"]["value"]
    hits  = [h["_source"] for h in resp["hits"]["hits"]]

    return {
        "total":     total,
        "page":      page,
        "page_size": page_size,
        "pages":     (total + page_size - 1) // page_size,
        "sessions":  hits,
    }


# ══════════════════════════════════════════════════════════════════════════════
# GET /sessions/{id}
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/sessions/{session_id}")
async def get_session(session_id: str):
    """Fetch a single session by its session_id (now includes correlation metadata)."""
    try:
        resp = await state.es.get(index=ES_INDEX, id=session_id)
        return resp["_source"]
    except NotFoundError:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")


# ══════════════════════════════════════════════════════════════════════════════
# GET /report/{id}
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/report/{session_id}")
async def get_report(session_id: str):
    """Generate and return a PDF security assessment report for a session."""
    try:
        resp = await state.es.get(index=ES_INDEX, id=session_id)
        session = resp["_source"]
    except NotFoundError:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")

    pdf_bytes = generate_pdf_report(session)

    # Store report_id back in ES so the session knows it has a report
    report_id = f"report_{session_id}"
    await state.es.update(
        index=ES_INDEX,
        id=session_id,
        body={"doc": {"report_id": report_id}},
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{report_id}.pdf"'
        },
    )


# ══════════════════════════════════════════════════════════════════════════════
# GET /stats  ← UPDATED WITH CORRELATION STATS
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/stats")
async def get_stats():
    """
    Aggregated statistics across all indexed sessions.
    Now includes correlation pattern stats.
    """
    agg_query = {
        "size": 0,
        "aggs": {
            "cipher_suite_dist": {
                "terms": {"field": "cipher_suite", "size": 20}
            },
            "dh_group_dist": {
                "terms": {"field": "dh_group", "size": 20}
            },
            "pfs_dist": {
                "terms": {"field": "pfs_enabled", "size": 2}
            },
            "severity_dist": {
                "terms": {"field": "adjusted_severity", "size": 10}  # Use adjusted_severity
            },
            "score_histogram": {
                "histogram": {"field": "adjusted_security_score", "interval": 10}  # Use adjusted score
            },
            "pattern_detected_dist": {
                "terms": {"field": "correlation.pattern_detected", "size": 2}
            },
            "top_weak_configs": {
                "filter": {"range": {"adjusted_security_score": {"lt": 60}}},
                "aggs": {
                    "by_cipher": {"terms": {"field": "cipher_suite", "size": 5}},
                    "by_dh":     {"terms": {"field": "dh_group",     "size": 5}},
                },
            },
            "avg_score": {
                "avg": {"field": "adjusted_security_score"}  # Use adjusted score
            },
            "traffic_class_dist": {
                "terms": {"field": "traffic_class", "size": 10}
            },
            "top_attack_ips": {
                "filter": {"term": {"correlation.pattern_detected": True}},
                "aggs": {
                    "by_ip": {
                        "terms": {"field": "initiator_ip", "size": 10}
                    }
                }
            },
        },
    }

    resp = await state.es.search(index=ES_INDEX, body=agg_query)
    aggs = resp["aggregations"]

    def buckets(agg_name: str):
        return [
            {"key": b["key"], "count": b["doc_count"]}
            for b in aggs[agg_name]["buckets"]
        ]

    return {
        "total_sessions":          resp["hits"]["total"]["value"],
        "average_score":           round(aggs["avg_score"]["value"] or 0, 2),
        "cipher_suite_dist":       buckets("cipher_suite_dist"),
        "dh_group_dist":           buckets("dh_group_dist"),
        "pfs_dist": [
            {"key": "enabled" if b["key"] == 1 else "disabled", "count": b["doc_count"]}
            for b in aggs["pfs_dist"]["buckets"]
        ],
        "severity_dist":           buckets("severity_dist"),
        "score_histogram": [
            {"bucket": f"{int(b['key'])}-{int(b['key'])+10}", "count": b["doc_count"]}
            for b in aggs["score_histogram"]["buckets"]
        ],
        "pattern_detected_dist": [
            {"key": "detected" if b["key"] == 1 else "not_detected", "count": b["doc_count"]}
            for b in aggs["pattern_detected_dist"]["buckets"]
        ],
        "top_weak_cipher_suites":  [
            {"key": b["key"], "count": b["doc_count"]}
            for b in aggs["top_weak_configs"]["by_cipher"]["buckets"]
        ],
        "top_weak_dh_groups": [
            {"key": b["key"], "count": b["doc_count"]}
            for b in aggs["top_weak_configs"]["by_dh"]["buckets"]
        ],
        "traffic_class_dist":      buckets("traffic_class_dist"),
        "top_attack_ips": [
            {"ip": b["key"], "count": b["doc_count"]}
            for b in aggs["top_attack_ips"]["by_ip"]["buckets"]
        ],
    }


# ══════════════════════════════════════════════════════════════════════════════
# GET /correlations/{initiator_ip}  ← NEW ENDPOINT FOR DETAILED CORRELATION VIEW
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/correlations/{initiator_ip}")
async def get_correlations_for_ip(
    initiator_ip: str,
    window_minutes: int = Query(60, ge=1, le=1440, description="Lookback window in minutes"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
):
    """
    Retrieve all sessions from a specific initiator IP with correlation details.
    Useful for investigating potentially malicious IPs.
    """
    from datetime import timedelta
    
    cutoff_time = (
        datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    ).isoformat()

    es_query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"initiator_ip": initiator_ip}},
                    {"range": {"timestamp": {"gte": cutoff_time}}},
                ]
            }
        },
        "sort": [{"timestamp": {"order": "desc"}}],
        "from": (page - 1) * page_size,
        "size": page_size,
    }

    resp = await state.es.search(index=ES_INDEX, body=es_query)
    total = resp["hits"]["total"]["value"]
    sessions = [h["_source"] for h in resp["hits"]["hits"]]

    # Aggregate stats for this IP
    weak_count = sum(
        1 for s in sessions
        if s.get("correlation", {}).get("pattern_detected", False)
    )
    avg_score = (
        sum(s.get("adjusted_security_score", 100) for s in sessions) / len(sessions)
        if sessions else 100
    )

    return {
        "initiator_ip":      initiator_ip,
        "window_minutes":    window_minutes,
        "total_sessions":    total,
        "page":              page,
        "page_size":         page_size,
        "pages":             (total + page_size - 1) // page_size,
        "weak_sessions":     weak_count,
        "average_score":     round(avg_score, 2),
        "sessions":          sessions,
    }


# ══════════════════════════════════════════════════════════════════════════════
# GET /metrics  (SSE)
# ══════════════════════════════════════════════════════════════════════════════
async def _metrics_event_stream() -> AsyncGenerator[str, None]:
    """
    Consume the pipeline-metrics Kafka topic and stream as SSE.
    Each message is forwarded as: data: {...}\n\n
    Sends a heartbeat comment every 15 s if no messages arrive.
    """
    loop = asyncio.get_event_loop()

    def _create_consumer():
        return KafkaConsumer(
            METRICS_TOPIC,
            bootstrap_servers=KAFKA_BOOTSTRAP,
            auto_offset_reset="latest",
            enable_auto_commit=True,
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            consumer_timeout_ms=15_000,   # yield control every 15 s
        )

    consumer = await loop.run_in_executor(None, _create_consumer)

    try:
        while True:
            # poll() in a thread pool so we don't block the event loop
            def _poll():
                records = consumer.poll(timeout_ms=15_000, max_records=10)
                return [
                    msg.value
                    for tp_records in records.values()
                    for msg in tp_records
                ]

            messages = await loop.run_in_executor(None, _poll)

            if messages:
                for msg in messages:
                    yield f"data: {json.dumps(msg)}\n\n"
            else:
                # Heartbeat — keeps the connection alive and lets the browser
                # detect a dropped connection quickly
                yield ": heartbeat\n\n"

            await asyncio.sleep(0)  # yield to event loop
    finally:
        consumer.close()


@app.get("/metrics")
async def metrics_sse():
    """SSE stream of pipeline throughput metrics from Kafka."""
    return StreamingResponse(
        _metrics_event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",     # disable nginx buffering
            "Access-Control-Allow-Origin": "http://localhost:5173",
        },
    )


# ══════════════════════════════════════════════════════════════════════════════
# GET /health  ← UPDATED WITH CORRELATOR STATUS
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/health")
async def health():
    """Returns status of Elasticsearch, Kafka, models, correlator, and uptime."""
    # Elasticsearch
    es_ok = False
    es_detail = "unknown"
    try:
        info = await state.es.cluster.health()
        es_ok     = info["status"] in ("green", "yellow")
        es_detail = info["status"]
    except Exception as exc:
        es_detail = str(exc)

    # Kafka — lightweight check via a short-lived consumer
    kafka_ok = False
    kafka_detail = "unknown"
    try:
        from kafka.admin import KafkaAdminClient
        admin = KafkaAdminClient(
            bootstrap_servers=KAFKA_BOOTSTRAP,
            request_timeout_ms=3000,
        )
        topics = admin.list_topics()
        admin.close()
        required = {"raw-features", "inference-results", "alerts", "pipeline-metrics"}
        missing  = required - set(topics)
        kafka_ok     = len(missing) == 0
        kafka_detail = "ok" if kafka_ok else f"missing topics: {missing}"
    except Exception as exc:
        kafka_detail = str(exc)

    # Correlator
    correlator_ok = state.correlator is not None
    correlator_detail = "initialized" if correlator_ok else "not initialized"

    uptime_sec = (
        (datetime.now(timezone.utc) - state.startup_time).total_seconds()
        if state.startup_time else 0
    )

    return {
        "status":        "healthy" if (es_ok and kafka_ok and state.models_loaded and correlator_ok) else "degraded",
        "models_loaded": state.models_loaded,
        "elasticsearch": {"ok": es_ok, "detail": es_detail},
        "kafka":         {"ok": kafka_ok, "detail": kafka_detail},
        "correlator":    {"ok": correlator_ok, "detail": correlator_detail},
        "uptime_sec":    round(uptime_sec, 1),
        "timestamp":     datetime.now(timezone.utc).isoformat(),
    }