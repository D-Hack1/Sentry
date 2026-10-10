"""
api/main.py — FastAPI application for the IPsec VPN Protocol Analyzer.

Implements API_CONTRACT.md (v1.2):
    POST /analyze           run all models + scorer + SHAP + correlation, store in ES
    GET  /sessions          paginated, filterable session list
    GET  /sessions/{id}     full session record (id = es_id, or the session_id)
    GET  /report/{id}       PDF security assessment report
    GET  /stats             aggregate statistics
    GET  /metrics           SSE stream of the pipeline-metrics Kafka topic
    GET  /health            dependency status (always HTTP 200)
Extensions (not in the contract, additive only):
    GET  /correlations/{initiator_ip}   repeated weak-config sessions from one IP

Run from the repository root:
    uvicorn api.main:app --port 8000
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sys
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Literal, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env")

from elasticsearch import (  # noqa: E402
    ApiError,
    AsyncElasticsearch,
    BadRequestError,
    Elasticsearch,
    NotFoundError,
)
from elasticsearch import ConnectionError as ESConnectionError  # noqa: E402
from fastapi import FastAPI, Query, Request  # noqa: E402
from fastapi.concurrency import run_in_threadpool  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from fastapi.responses import JSONResponse, Response, StreamingResponse  # noqa: E402
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress  # noqa: E402
from starlette.exceptions import HTTPException as StarletteHTTPException  # noqa: E402

from api.correlator import SessionCorrelator, create_correlator  # noqa: E402
from api.report_generator import generate_pdf_report  # noqa: E402
from es.init_index import ensure_index, es_url_from_env  # noqa: E402
from ml.inference import MODEL_FILES, Models, analyze_dict, load_models  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s | %(message)s")
logger = logging.getLogger("api")
logging.getLogger("elastic_transport").setLevel(logging.WARNING)  # one INFO line per ES request otherwise

# ── Config (.env / environment) ──────────────────────────────────────────────
ES_URL = es_url_from_env()
ES_INDEX = os.getenv("ES_INDEX", "ipsec_sessions")
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:29092")
REQUIRED_TOPICS = [
    os.getenv("KAFKA_TOPIC_RAW_FEATURES", "raw-features"),
    os.getenv("KAFKA_TOPIC_INFERENCE_RESULTS", "inference-results"),
    os.getenv("KAFKA_TOPIC_ALERTS", "alerts"),
    os.getenv("KAFKA_TOPIC_PIPELINE_METRICS", "pipeline-metrics"),
]
METRICS_TOPIC = REQUIRED_TOPICS[3]
MODEL_DIR = Path(os.getenv("MODEL_DIR", str(ROOT / "ml")))
CORS_ORIGINS = [
    o.strip()
    for o in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
    if o.strip()
]
SSE_HEARTBEAT_SEC = 15.0
ES_ID_NAMESPACE = uuid.UUID("6f1c2d3e-8a4b-4c5d-9e0f-a1b2c3d4e5f6")

LIST_FIELDS = [
    "session_id", "es_id", "ts", "initiator_ip", "responder_ip", "ike_version", "mode",
    "cipher_suite", "dh_group", "pfs_enabled", "traffic_class", "traffic_confidence",
    "security_score", "severity", "anomaly_score", "ai_confidence", "risk_flags",
    "adjusted_security_score", "adjusted_severity", "correlation.pattern_detected", "report_id",
]


# ── App state ────────────────────────────────────────────────────────────────
class AppState:
    models: Optional[Models] = None
    es: Optional[AsyncElasticsearch] = None
    correlator: Optional[SessionCorrelator] = None
    index_ready: bool = False
    startup_time: Optional[datetime] = None


state = AppState()


def _ensure_index_sync() -> str:
    client = Elasticsearch(ES_URL, request_timeout=10)
    try:
        return ensure_index(client, ES_INDEX)
    finally:
        client.close()


async def _ensure_index() -> bool:
    if state.index_ready:
        return True
    try:
        status = await run_in_threadpool(_ensure_index_sync)
        state.index_ready = True
        logger.info("Elasticsearch: %s", status)
    except Exception as exc:
        logger.warning("Elasticsearch index not ready (%s): %s", ES_URL, exc)
    return state.index_ready


@asynccontextmanager
async def lifespan(app: FastAPI):
    state.startup_time = datetime.now(timezone.utc)
    # Fail fast: the API is useless without its models.
    state.models = load_models(MODEL_DIR)
    logger.info("Models loaded from %s: %s", MODEL_DIR, ", ".join(MODEL_FILES.values()))

    state.es = AsyncElasticsearch(ES_URL, request_timeout=15)
    state.correlator = create_correlator(state.es, ES_INDEX)
    await _ensure_index()  # ES may still be starting — retried lazily on first write
    yield
    await state.es.close()


app = FastAPI(
    title="IPsec VPN Protocol Analyzer",
    version="1.2.0",
    description="AI-powered IPsec session analysis and security assessment API",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)


# ── Error envelope ───────────────────────────────────────────────────────────
class APIError(Exception):
    def __init__(self, status: int, code: str, message: str, detail: Any = None):
        self.status, self.code, self.message, self.detail = status, code, message, detail


def _envelope(status: int, code: str, message: str, detail: Any = None) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": message, "detail": detail}})


@app.exception_handler(APIError)
async def _api_error(_: Request, exc: APIError):
    return _envelope(exc.status, exc.code, exc.message, exc.detail)


@app.exception_handler(RequestValidationError)
async def _validation_error(_: Request, exc: RequestValidationError):
    detail = json.loads(json.dumps(exc.errors(), default=str))
    return _envelope(422, "VALIDATION_ERROR", "Request body or parameters failed validation", detail)


@app.exception_handler(StarletteHTTPException)
async def _http_error(_: Request, exc: StarletteHTTPException):
    code = {404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED"}.get(exc.status_code, "HTTP_ERROR")
    return _envelope(exc.status_code, code, str(exc.detail))


@app.exception_handler(ESConnectionError)
async def _es_down(_: Request, exc: ESConnectionError):
    return _envelope(503, "ELASTICSEARCH_UNAVAILABLE", f"Cannot reach Elasticsearch at {ES_URL}")


@app.exception_handler(BadRequestError)
async def _es_bad_request(_: Request, exc: BadRequestError):
    return _envelope(400, "BAD_REQUEST", "Elasticsearch rejected the query", str(exc.message))


@app.exception_handler(Exception)
async def _unhandled(_: Request, exc: Exception):
    logger.exception("Unhandled error")
    return _envelope(500, "INTERNAL_ERROR", f"{type(exc).__name__}: {exc}")


# ── Request model ────────────────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    """IPsecFeatureRow sections 1–4 (features/schema.py). Unknown keys are ignored."""

    model_config = ConfigDict(extra="ignore", allow_inf_nan=False)

    session_id: str = Field(min_length=1, max_length=512)
    ts: float = Field(ge=0, le=253402300799)  # unix seconds, up to 9999-12-31
    initiator_ip: IPvAnyAddress
    responder_ip: IPvAnyAddress
    initiator_port: int = Field(ge=0, le=65535)
    responder_port: int = Field(ge=0, le=65535)
    duration: float = Field(ge=0)

    ike_version: int
    ike_exchange_type: int
    ike_initiator_spi: str
    sa_proposal_count: int = Field(ge=0)
    ke_dh_group: int = Field(ge=0)
    ike_nat_traversal: bool
    ike_packet_count: int = Field(ge=0)
    ike_handshake_duration: float = Field(ge=0)

    # The parser leaves these None when they are not observable in plaintext;
    # the protocol model then fills them in (see ml/inference.resolve_config).
    mode: Optional[Literal["tunnel", "transport"]] = None
    cipher_suite: Optional[str] = None
    auth_algo: Optional[str] = None
    dh_group: Optional[str] = None
    pfs_enabled: Optional[bool] = None
    key_lifetime_sec: Optional[int] = Field(default=None, ge=0)
    esp_spi: str

    esp_packet_count: int = Field(ge=0)
    esp_bytes_total: int = Field(ge=0)
    esp_pkt_size_mean: float
    esp_pkt_size_std: float
    esp_pkt_size_min: float
    esp_pkt_size_max: float
    esp_iat_mean: float
    esp_iat_std: float
    esp_iat_min: float
    esp_iat_max: float
    esp_burst_count: int = Field(ge=0)
    esp_burst_size_mean: float
    esp_bytes_per_sec: float
    esp_pkts_per_sec: float
    asymmetry_ratio: float
    esp_pkt_size_entropy: float
    esp_iat_entropy: float
    esp_active_fraction: float

    label_config: Optional[str] = None
    label_traffic: Optional[str] = None


def es_id_for(session_id: str) -> str:
    """Deterministic, URL-safe document id: re-analysing a session overwrites it."""
    return uuid.uuid5(ES_ID_NAMESPACE, session_id).hex


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


# ── POST /analyze ────────────────────────────────────────────────────────────
@app.post("/analyze")
async def analyze(body: AnalyzeRequest):
    features = body.model_dump(mode="json")
    analysis = await run_in_threadpool(analyze_dict, features, state.models)

    doc = {
        **features,
        **analysis,
        "es_id": es_id_for(body.session_id),
        "ts": _iso(body.ts),
        "ts_epoch": body.ts,
        "analyzed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "report_id": None,
    }
    doc = await state.correlator.correlate(doc)

    if not await _ensure_index():
        raise APIError(503, "ELASTICSEARCH_UNAVAILABLE", f"Cannot reach Elasticsearch at {ES_URL}")
    await state.es.index(index=ES_INDEX, id=doc["es_id"], document=doc, refresh=True)
    logger.info(
        "analyzed %s | traffic=%s (%.2f) | score=%.0f %s | adjusted=%.0f | pattern=%s",
        body.session_id, doc["traffic_class"], doc["traffic_confidence"], doc["security_score"],
        doc["severity"], doc["adjusted_security_score"], doc["correlation"]["pattern_detected"],
    )
    return doc


# ── GET /sessions ────────────────────────────────────────────────────────────
def _page(total: int, page: int, page_size: int, items: list) -> dict:
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
    }


@app.get("/sessions")
async def list_sessions(
    severity: Optional[Literal["critical", "high", "medium", "low", "info"]] = None,
    cipher_suite: Optional[str] = None,
    mode: Optional[Literal["tunnel", "transport"]] = None,
    pfs_enabled: Optional[bool] = None,
    traffic_class: Optional[str] = None,
    ike_version: Optional[int] = None,
    start_time: Optional[str] = Query(None, description="ISO 8601, session ts >= this"),
    end_time: Optional[str] = Query(None, description="ISO 8601, session ts <= this"),
    initiator_ip: Optional[str] = None,
    pattern_detected: Optional[bool] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
):
    if page * page_size > 10_000:
        raise APIError(400, "PAGE_OUT_OF_RANGE", "page * page_size must be <= 10000")
    filters: list[dict] = []
    for field, value in (
        ("severity", severity), ("cipher_suite", cipher_suite), ("mode", mode),
        ("pfs_enabled", pfs_enabled), ("traffic_class", traffic_class),
        ("ike_version", ike_version), ("initiator_ip", initiator_ip),
        ("correlation.pattern_detected", pattern_detected),
    ):
        if value is not None:
            filters.append({"term": {field: value}})
    if start_time or end_time:
        time_range = {k: v for k, v in (("gte", start_time), ("lte", end_time)) if v}
        filters.append({"range": {"ts": time_range}})

    resp = await state.es.search(
        index=ES_INDEX,
        query={"bool": {"filter": filters}} if filters else {"match_all": {}},
        sort=[{"ts": {"order": "desc", "unmapped_type": "date"}}, {"session_id": {"order": "asc", "unmapped_type": "keyword"}}],
        from_=(page - 1) * page_size,
        size=page_size,
        source_includes=LIST_FIELDS,
        track_total_hits=True,
        ignore_unavailable=True,
    )
    items = [h["_source"] for h in resp["hits"]["hits"]]
    return _page(resp["hits"]["total"]["value"], page, page_size, items)


async def _get_session_doc(session_ref: str) -> dict:
    """Look up by es_id; fall back to session_id so either identifier works."""
    try:
        return (await state.es.get(index=ES_INDEX, id=session_ref))["_source"]
    except NotFoundError:
        pass
    resp = await state.es.search(
        index=ES_INDEX, query={"term": {"session_id": session_ref}}, size=1, ignore_unavailable=True
    )
    hits = resp["hits"]["hits"]
    if not hits:
        raise APIError(404, "SESSION_NOT_FOUND", f"No session with id '{session_ref}'")
    return hits[0]["_source"]


@app.get("/sessions/{session_ref}")
async def get_session(session_ref: str):
    return await _get_session_doc(session_ref)


# ── GET /report/{id} ─────────────────────────────────────────────────────────
@app.get("/report/{session_ref}")
async def get_report(session_ref: str):
    session = await _get_session_doc(session_ref)
    session["report_id"] = str(uuid.uuid4())
    try:
        pdf_bytes = await run_in_threadpool(generate_pdf_report, session)
    except OSError as exc:  # WeasyPrint could not load Pango / system libraries
        raise APIError(500, "REPORT_RENDERER_UNAVAILABLE", f"PDF renderer unavailable: {exc}")
    try:
        await state.es.update(index=ES_INDEX, id=session["es_id"], doc={"report_id": session["report_id"]})
    except ApiError as exc:
        logger.warning("Could not store report_id for %s: %s", session.get("session_id"), exc)
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", str(session.get("session_id", "session")))
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="ipsec_report_{safe_name}.pdf"'},
    )


# ── GET /stats ───────────────────────────────────────────────────────────────
SCORE_BUCKETS = [(lo, lo + 10) for lo in range(0, 100, 10)]


@app.get("/stats")
async def get_stats():
    ranges = [{"key": f"{lo}-{hi - 1}" if hi < 100 else "90-100", "from": lo, "to": hi if hi < 100 else 100.0001}
              for lo, hi in SCORE_BUCKETS]
    resp = await state.es.search(
        index=ES_INDEX,
        size=0,
        track_total_hits=True,
        ignore_unavailable=True,
        aggs={
            "cipher": {"terms": {"field": "cipher_suite", "size": 20}},
            "dh": {"terms": {"field": "dh_group", "size": 20}},
            "pfs": {"terms": {"field": "pfs_enabled", "size": 2}},
            "ike": {"terms": {"field": "ike_version", "size": 5}},
            "severity": {"terms": {"field": "severity", "size": 10}},
            "traffic": {"terms": {"field": "traffic_class", "size": 10}},
            "scores": {"range": {"field": "security_score", "ranges": ranges, "keyed": False}},
            "avg_score": {"avg": {"field": "security_score"}},
            "weak": {
                "filter": {"range": {"security_score": {"lt": 60}}},
                "aggs": {"configs": {
                    "multi_terms": {
                        "terms": [{"field": "cipher_suite"}, {"field": "dh_group"}, {"field": "pfs_enabled"}],
                        "size": 10,
                    },
                    "aggs": {"avg_score": {"avg": {"field": "security_score"}}},
                }},
            },
            "patterns": {"terms": {"field": "correlation.pattern_detected", "size": 2}},
            "attack_ips": {
                "filter": {"term": {"correlation.pattern_detected": True}},
                "aggs": {"by_ip": {"terms": {"field": "initiator_ip", "size": 10}}},
            },
        },
    )
    aggs = resp.get("aggregations")
    if not aggs:  # index does not exist yet
        return {
            "total_sessions": 0, "cipher_suite_distribution": {}, "dh_group_distribution": {},
            "pfs_distribution": {"enabled": 0, "disabled": 0}, "ike_version_distribution": {},
            "severity_distribution": {}, "traffic_class_distribution": {},
            "score_histogram": [{"bucket": r["key"], "count": 0} for r in ranges],
            "top_weak_configs": [], "average_score": 0.0, "pattern_detected_distribution": {},
            "top_attack_ips": [],
        }

    def dist(name: str) -> dict:
        return {str(b["key"]): b["doc_count"] for b in aggs[name]["buckets"]}

    pfs = {"enabled": 0, "disabled": 0}
    for b in aggs["pfs"]["buckets"]:
        pfs["enabled" if b.get("key_as_string") == "true" or b["key"] == 1 else "disabled"] = b["doc_count"]

    def pfs_text(value: str) -> str:
        return {"true": "pfs", "1": "pfs", "false": "no_pfs", "0": "no_pfs"}.get(str(value).lower(), "pfs_unknown")

    return {
        "total_sessions": resp["hits"]["total"]["value"],
        "cipher_suite_distribution": dist("cipher"),
        "dh_group_distribution": dist("dh"),
        "pfs_distribution": pfs,
        "ike_version_distribution": {f"ikev{b['key']}": b["doc_count"] for b in aggs["ike"]["buckets"]},
        "severity_distribution": dist("severity"),
        "score_histogram": [{"bucket": b["key"], "count": b["doc_count"]} for b in aggs["scores"]["buckets"]],
        "top_weak_configs": [
            {
                "config": f"{b['key'][0]} + {b['key'][1]} + {pfs_text(b['key'][2])}",
                "count": b["doc_count"],
                "avg_score": round(b["avg_score"]["value"] or 0.0, 1),
            }
            for b in aggs["weak"]["configs"]["buckets"]
        ],
        "traffic_class_distribution": dist("traffic"),
        # extensions
        "average_score": round(aggs["avg_score"]["value"] or 0.0, 2),
        "pattern_detected_distribution": {
            ("detected" if b.get("key_as_string") == "true" or b["key"] == 1 else "not_detected"): b["doc_count"]
            for b in aggs["patterns"]["buckets"]
        },
        "top_attack_ips": [{"ip": b["key"], "count": b["doc_count"]} for b in aggs["attack_ips"]["by_ip"]["buckets"]],
    }


# ── GET /correlations/{initiator_ip}  (extension) ────────────────────────────
@app.get("/correlations/{initiator_ip}")
async def get_correlations_for_ip(
    initiator_ip: IPvAnyAddress,
    window_minutes: int = Query(60, ge=1, le=1440),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
):
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
    query = {"bool": {"filter": [{"term": {"initiator_ip": str(initiator_ip)}}, {"range": {"ts": {"gte": cutoff}}}]}}
    resp = await state.es.search(
        index=ES_INDEX, query=query, sort=[{"ts": {"order": "desc", "unmapped_type": "date"}}],
        from_=(page - 1) * page_size, size=page_size, source_includes=LIST_FIELDS,
        track_total_hits=True, ignore_unavailable=True,
        aggs={
            "weak": {"filter": {"range": {"security_score": {"lt": 60}}}},
            "patterns": {"filter": {"term": {"correlation.pattern_detected": True}}},
            "avg_score": {"avg": {"field": "security_score"}},
        },
    )
    aggs = resp.get("aggregations") or {}
    result = _page(resp["hits"]["total"]["value"], page, page_size, [h["_source"] for h in resp["hits"]["hits"]])
    result.update(
        initiator_ip=str(initiator_ip),
        window_minutes=window_minutes,
        weak_sessions=aggs.get("weak", {}).get("doc_count", 0),
        pattern_sessions=aggs.get("patterns", {}).get("doc_count", 0),
        average_score=round((aggs.get("avg_score", {}).get("value") or 0.0), 2),
    )
    return result


# ── GET /metrics (SSE) ───────────────────────────────────────────────────────
def _new_metrics_consumer():
    from kafka import KafkaConsumer, TopicPartition

    from features.kafka_serde import SafeJsonDeserializer

    consumer = KafkaConsumer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        group_id=None,
        enable_auto_commit=False,
        value_deserializer=SafeJsonDeserializer(),
        request_timeout_ms=10_000,
    )
    partitions = consumer.partitions_for_topic(METRICS_TOPIC) or set()
    if not partitions:
        consumer.close()
        raise RuntimeError(f"topic {METRICS_TOPIC} not found")
    tps = [TopicPartition(METRICS_TOPIC, p) for p in partitions]
    consumer.assign(tps)
    consumer.seek_to_end(*tps)
    return consumer


def _poll_metrics(consumer) -> list[dict]:
    records = consumer.poll(timeout_ms=1000, max_records=50)
    return [msg.value for batch in records.values() for msg in batch]


async def _metrics_event_stream(request: Request) -> AsyncGenerator[str, None]:
    loop = asyncio.get_running_loop()
    consumer = None
    last_sent = time.monotonic()
    yield ": connected\n\n"
    try:
        while not await request.is_disconnected():
            if consumer is None:
                try:
                    consumer = await loop.run_in_executor(None, _new_metrics_consumer)
                except Exception as exc:
                    yield f": kafka unavailable ({type(exc).__name__}) - retrying\n\n"
                    await asyncio.sleep(5)
                    continue
            try:
                messages = await loop.run_in_executor(None, _poll_metrics, consumer)
            except Exception as exc:
                logger.warning("metrics SSE poll failed: %s", exc)
                consumer.close()
                consumer = None
                continue
            for msg in messages:
                yield f"data: {json.dumps(msg, default=str)}\n\n"
                last_sent = time.monotonic()
            if time.monotonic() - last_sent >= SSE_HEARTBEAT_SEC:
                yield ": heartbeat\n\n"
                last_sent = time.monotonic()
    finally:
        if consumer is not None:
            try:
                consumer.close()
            except Exception:
                pass


@app.get("/metrics")
async def metrics_sse(request: Request):
    return StreamingResponse(
        _metrics_event_stream(request),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── GET /health ──────────────────────────────────────────────────────────────
def _kafka_topics() -> list[str]:
    from confluent_kafka.admin import AdminClient

    admin = AdminClient({"bootstrap.servers": KAFKA_BOOTSTRAP, "socket.timeout.ms": 3000, "log_level": 0})
    return sorted(t for t in admin.list_topics(timeout=3).topics if not t.startswith("__"))


@app.get("/health")
async def health():
    kafka = {"connected": False, "topics": []}
    try:
        topics = await run_in_threadpool(_kafka_topics)
        missing = [t for t in REQUIRED_TOPICS if t not in topics]
        kafka = {"connected": True, "topics": topics}
        if missing:
            kafka["missing_topics"] = missing
    except Exception as exc:
        kafka["detail"] = f"{type(exc).__name__}: {exc}"

    es = {"connected": False, "cluster_status": "unreachable", "index": ES_INDEX, "doc_count": 0}
    try:
        cluster = await state.es.cluster.health(timeout="3s")
        es.update(connected=True, cluster_status=cluster["status"])
        await _ensure_index()
        es["doc_count"] = (await state.es.count(index=ES_INDEX, ignore_unavailable=True))["count"]
    except Exception as exc:
        es["detail"] = f"{type(exc).__name__}: {exc}"

    loaded = state.models is not None
    models = {"protocol_model": loaded, "traffic_model": loaded, "anomaly_model": loaded}
    healthy = (
        kafka["connected"] and not kafka.get("missing_topics")
        and es["connected"] and es["cluster_status"] in ("green", "yellow")
        and loaded and state.correlator is not None
    )
    uptime = (datetime.now(timezone.utc) - state.startup_time).total_seconds() if state.startup_time else 0
    return {
        "status": "ok" if healthy else "degraded",
        "uptime_sec": round(uptime, 1),
        "kafka": kafka,
        "elasticsearch": es,
        "models": models,
        "correlator": {"connected": state.correlator is not None},
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
