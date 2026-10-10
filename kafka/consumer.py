"""

Consumes the 'raw-features' Kafka topic. For each message:
  1. Deserialise JSON → IPsecFeatureRow
  2. Record arrival timestamp
  3. POST to http://localhost:8000/analyze
  4. Record response timestamp → compute pipeline_latency_ms
  5. Publish result to 'inference-results'
  6. If security_score < 50 → publish to 'alerts'
  7. On any error → dead-letter log, never crash

Usage (run by path — `kafka` is also the kafka-python import name):
    python kafka/consumer.py [--bootstrap localhost:29092] [--api-url http://localhost:8000]

Transient API failures (connection refused, timeouts, 5xx) are retried with
backoff so messages are not lost while the API restarts; 4xx responses and
exhausted retries go to the dead-letter log.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Deque, Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env")

import httpx  # noqa: E402
from kafka import KafkaConsumer  # noqa: E402  (kafka-python)
from kafka.errors import KafkaError  # noqa: E402

from features.kafka_serde import JsonValueSerializer, SafeJsonDeserializer  # noqa: E402
from features.schema import (  # noqa: E402
    IPsecFeatureRow,
    KafkaAlert,
    KafkaInferenceResult,
)

# 
# Config (env overrides CLI defaults)
# 

BOOTSTRAP_SERVERS: str   = os.getenv("KAFKA_BOOTSTRAP",   "localhost:29092")
API_BASE_URL: str        = os.getenv("API_BASE_URL",       "http://localhost:8000")
TOPIC_RAW_FEATURES: str  = os.getenv("KAFKA_TOPIC_RAW_FEATURES", "raw-features")
TOPIC_INFERENCE: str     = os.getenv("KAFKA_TOPIC_INFERENCE_RESULTS", "inference-results")
TOPIC_ALERTS: str        = os.getenv("KAFKA_TOPIC_ALERTS", "alerts")
CONSUMER_GROUP: str      = "ipsec-consumer-group"
ALERT_SCORE_THRESHOLD: float = 50.0   # security_score < this → publish to alerts
CONNECT_RETRY_SEC: int   = 5
MAX_CONNECT_RETRIES: int = 12
API_TIMEOUT_SEC: float   = 30.0
API_MAX_ATTEMPTS: int    = 6          # transient API failures: retry with backoff
API_RETRY_BASE_SEC: float = 1.0       # 1, 2, 4, 8, 16 s between attempts

# Rolling window for computing median pipeline latency (last N samples)
LATENCY_WINDOW_SIZE: int = 50

log = logging.getLogger("consumer")


# 
# Kafka client factories
# 

def _make_consumer(bootstrap: str, retries: int = MAX_CONNECT_RETRIES) -> KafkaConsumer:
    for attempt in range(1, retries + 1):
        try:
            consumer = KafkaConsumer(
                TOPIC_RAW_FEATURES,
                bootstrap_servers=bootstrap,
                group_id=CONSUMER_GROUP,
                auto_offset_reset="earliest",     # catch up on missed messages after restart
                enable_auto_commit=False,          # manual commit after successful processing
                value_deserializer=SafeJsonDeserializer(),  # bad JSON -> dead letter, not a crash
                # Tuning
                max_poll_records=10,               # process 10 at a time — keeps latency low
                session_timeout_ms=30_000,
                heartbeat_interval_ms=10_000,
                fetch_max_wait_ms=500,
                request_timeout_ms=15_000,
            )
            log.info("Kafka consumer connected | bootstrap=%s | group=%s", bootstrap, CONSUMER_GROUP)
            return consumer
        except KafkaError as exc:
            log.warning(
                "Kafka not reachable (attempt %d/%d): %s — retrying in %ds",
                attempt, retries, exc, CONNECT_RETRY_SEC,
            )
            if attempt < retries:
                time.sleep(CONNECT_RETRY_SEC)

    log.critical("Could not connect to Kafka after %d attempts — exiting", retries)
    sys.exit(1)


def _make_producer(bootstrap: str):
    """Inline producer for publishing to inference-results and alerts topics."""
    from kafka import KafkaProducer  # kafka-python library
    return KafkaProducer(
        bootstrap_servers=bootstrap,
        value_serializer=JsonValueSerializer(),
        acks="all",
        retries=3,
        retry_backoff_ms=200,
        linger_ms=5,
        compression_type="gzip",
    )


# 
# Dead-letter logger
# 

def _dead_letter(raw_msg: dict, reason: str, detail: str = "") -> None:
    """
    Write un-processable messages to a local dead-letter JSONL file.
    Never raises — called from error paths.
    """
    try:
        dl_path = os.getenv("CONSUMER_DEAD_LETTER_LOG", str(ROOT / ".run" / "consumer_dead_letter.jsonl"))
        os.makedirs(os.path.dirname(dl_path), exist_ok=True)
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "detail": detail,
            "raw_message": raw_msg,
        }
        with open(dl_path, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
        log.warning("DEAD-LETTER | reason=%s | detail=%s", reason, detail[:120])
    except Exception as write_exc:
        log.error("Dead-letter write itself failed: %s", write_exc)


# 
# Deserialisation
# 

def _deserialise(envelope: dict) -> Optional[IPsecFeatureRow]:
    """
    Validate the Kafka message envelope and deserialise into IPsecFeatureRow.
    Returns None (and dead-letters) on any schema mismatch.
    """
    if not isinstance(envelope, dict):
        raise TypeError(f"Expected dict, got {type(envelope).__name__}")
    if "__undecodable__" in envelope:
        raise ValueError(f"Message is not valid JSON: {envelope['__undecodable__']}")

    feature_dict = envelope.get("feature_row")
    if not feature_dict or not isinstance(feature_dict, dict):
        raise ValueError("Missing or empty 'feature_row' key in envelope")

    try:
        row = IPsecFeatureRow.from_dict(feature_dict)
    except TypeError as exc:
        raise ValueError(f"IPsecFeatureRow.from_dict failed: {exc}") from exc

    return row


# 
# API call
# 

def _call_analyze(client: httpx.Client, row: IPsecFeatureRow) -> dict:
    """
    POST the feature row to /analyze and return the response dict.
    Retries connection errors, timeouts and 5xx responses with exponential
    backoff; raises httpx.HTTPStatusError / httpx.RequestError when giving up.
    """
    payload = row.to_dict()
    for attempt in range(1, API_MAX_ATTEMPTS + 1):
        try:
            resp = client.post("/analyze", json=payload, timeout=API_TIMEOUT_SEC)
            if resp.status_code < 500:
                resp.raise_for_status()
                return resp.json()
            error: Exception = httpx.HTTPStatusError(
                f"HTTP {resp.status_code}", request=resp.request, response=resp
            )
        except httpx.RequestError as exc:
            error = exc
        if attempt == API_MAX_ATTEMPTS:
            raise error
        delay = API_RETRY_BASE_SEC * 2 ** (attempt - 1)
        log.warning(
            "API unavailable for session_id=%s (%s) — retry %d/%d in %.0fs",
            row.session_id, error, attempt, API_MAX_ATTEMPTS - 1, delay,
        )
        time.sleep(delay)
    raise RuntimeError("unreachable")


# 
# Kafka publish helpers
# 

def _publish_inference_result(producer, api_response: dict, latency_ms: float) -> None:
    """Publish a KafkaInferenceResult to the 'inference-results' topic."""
    result = KafkaInferenceResult(
        schema_version="1.0",
        session_id=api_response.get("session_id", ""),
        security_score=float(api_response.get("security_score", 0.0)),
        severity=api_response.get("severity", ""),
        traffic_class=api_response.get("traffic_class", ""),
        traffic_confidence=float(api_response.get("traffic_confidence", 0.0)),
        anomaly_score=float(api_response.get("anomaly_score", 0.0)),
        ai_confidence=float(api_response.get("ai_confidence", 0.0)),
        risk_flags=api_response.get("risk_flags", []),
    )
    msg = {
        **result.__dict__,
        "es_id": api_response.get("es_id"),
        "pipeline_latency_ms": round(latency_ms, 2),
        "published_at": datetime.now(timezone.utc).isoformat(),
    }
    producer.send(TOPIC_INFERENCE, value=msg)
    log.debug(
        "INFERENCE PUBLISHED | session_id=%s | score=%.1f | latency_ms=%.1f",
        result.session_id, result.security_score, latency_ms,
    )


def _publish_alert(producer, api_response: dict, row: IPsecFeatureRow) -> None:
    """Publish a KafkaAlert to the 'alerts' topic if score < threshold."""
    security_score = float(api_response.get("security_score", 100.0))
    if security_score >= ALERT_SCORE_THRESHOLD:
        return

    risk_flags: list = api_response.get("risk_flags", [])
    alert = KafkaAlert(
        schema_version="1.0",
        session_id=row.session_id,
        initiator_ip=row.initiator_ip,
        security_score=security_score,
        severity=api_response.get("severity", ""),
        top_risk_flag=risk_flags[0] if risk_flags else "",
        ts=row.ts,
    )
    msg = {
        **alert.__dict__,
        "published_at": datetime.now(timezone.utc).isoformat(),
    }
    producer.send(TOPIC_ALERTS, value=msg)
    log.warning(
        "ALERT PUBLISHED | session_id=%s | score=%.1f | severity=%s | top_flag=%s",
        alert.session_id, alert.security_score, alert.severity,
        alert.top_risk_flag[:80] if alert.top_risk_flag else "—",
    )


# 
# Latency
# 

def _end_to_end_latency_ms(envelope: dict, received_monotonic: float) -> float:
    """
    Milliseconds from the producer's `published_at` stamp to now (the result is
    stored in ES by the time /analyze returns). Falls back to the time spent in
    this consumer if the stamp is missing or unparseable.
    """
    stamp = envelope.get("published_at") if isinstance(envelope, dict) else None
    if stamp:
        try:
            published = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
            if published.tzinfo is None:
                published = published.replace(tzinfo=timezone.utc)
            elapsed = (datetime.now(timezone.utc) - published).total_seconds() * 1000.0
            if elapsed >= 0:
                return elapsed
        except ValueError:
            pass
    return (time.monotonic() - received_monotonic) * 1000.0


# 
# Latency tracker (rolling median)
# 

class LatencyTracker:
    """Tracks pipeline latency over a rolling window for metrics reporting."""

    def __init__(self, window: int = LATENCY_WINDOW_SIZE) -> None:
        self._window: Deque[float] = deque(maxlen=window)

    def record(self, latency_ms: float) -> None:
        self._window.append(latency_ms)

    def median(self) -> float:
        if not self._window:
            return 0.0
        s = sorted(self._window)
        n = len(s)
        mid = n // 2
        return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2.0

    def p95(self) -> float:
        if not self._window:
            return 0.0
        s = sorted(self._window)
        idx = max(0, int(len(s) * 0.95) - 1)
        return s[idx]


# 
# Core consume loop
# 

def run_consumer_loop(
    bootstrap: str = BOOTSTRAP_SERVERS,
    api_url: str = API_BASE_URL,
) -> None:
    """
    Long-running consume loop. Blocks the calling thread.
    """
    global API_BASE_URL
    API_BASE_URL = api_url  # allow override from CLI

    def _sigterm(_sig, _frame):
        raise KeyboardInterrupt  # unwind through the finally block below
    signal.signal(signal.SIGTERM, _sigterm)

    log.info(
        "Consumer starting | bootstrap=%s | group=%s | api=%s | alert_threshold=%.0f",
        bootstrap, CONSUMER_GROUP, api_url, ALERT_SCORE_THRESHOLD,
    )

    consumer = _make_consumer(bootstrap)
    producer = _make_producer(bootstrap)
    latency_tracker = LatencyTracker()

    # httpx client — reused across all requests (connection pool)
    http_client = httpx.Client(base_url=api_url, timeout=API_TIMEOUT_SEC)

    processed = 0
    errors = 0
    alerts_sent = 0

    try:
        for kafka_message in consumer:
            envelope = kafka_message.value
            received_at = time.monotonic()

            # -- Deserialise
            try:
                row = _deserialise(envelope)
            except (TypeError, ValueError, KeyError) as exc:
                errors += 1
                _dead_letter(
                    envelope,
                    reason="deserialisation_error",
                    detail=str(exc),
                )
                consumer.commit()
                continue

            session_id = row.session_id
            log.info("RECEIVED | session_id=%s | offset=%d", session_id, kafka_message.offset)

            # -- POST to /analyze 
            try:
                api_response = _call_analyze(http_client, row)
            except httpx.HTTPStatusError as exc:
                errors += 1
                log.error(
                    "API HTTP ERROR | session_id=%s | status=%d | body=%s",
                    session_id, exc.response.status_code, exc.response.text[:300],
                )
                _dead_letter(
                    envelope,
                    reason="api_http_error",
                    detail=f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
                )
                consumer.commit()
                continue
            except httpx.RequestError as exc:
                errors += 1
                log.error(
                    "API CONNECTION ERROR | session_id=%s | %s: %s",
                    session_id, type(exc).__name__, exc,
                )
                _dead_letter(envelope, reason="api_connection_error", detail=str(exc))
                consumer.commit()
                continue

            # -- Compute latency: feature publish -> inference result stored
            latency_ms = _end_to_end_latency_ms(envelope, received_at)
            latency_tracker.record(latency_ms)

            log.info(
                "ANALYZED | session_id=%s | score=%.1f | severity=%s | "
                "traffic=%s | latency_ms=%.1f",
                session_id,
                api_response.get("security_score", 0),
                api_response.get("severity", "?"),
                api_response.get("traffic_class", "?"),
                latency_ms,
            )

            # -- Publish inference result 
            try:
                _publish_inference_result(producer, api_response, latency_ms)
            except KafkaError as exc:
                log.error("Failed to publish inference result | session_id=%s | %s", session_id, exc)
                _dead_letter(
                    {"api_response": api_response},
                    reason="publish_inference_error",
                    detail=str(exc),
                )

            # -- Publish alert if needed 
            try:
                score = float(api_response.get("security_score", 100.0))
                if score < ALERT_SCORE_THRESHOLD:
                    _publish_alert(producer, api_response, row)
                    alerts_sent += 1
            except KafkaError as exc:
                log.error("Failed to publish alert | session_id=%s | %s", session_id, exc)

            # -- Flush + commit 
            try:
                producer.flush(timeout=3)
            except KafkaError as exc:
                log.error("Flush error after session %s: %s", session_id, exc)

            consumer.commit()
            processed += 1

            # -- Periodic stats log 
            if processed % 20 == 0:
                log.info(
                    "STATS | processed=%d | errors=%d | alerts=%d | "
                    "latency_median_ms=%.1f | latency_p95_ms=%.1f",
                    processed, errors, alerts_sent,
                    latency_tracker.median(), latency_tracker.p95(),
                )

    except KeyboardInterrupt:
        log.info("Consumer interrupted by user")
    except Exception as exc:
        log.critical("Unhandled exception in consumer loop: %s", exc, exc_info=True)
    finally:
        try:
            producer.flush(timeout=5)
            producer.close()
        except Exception:
            pass
        consumer.close()
        http_client.close()
        log.info(
            "Consumer stopped | processed=%d | errors=%d | alerts=%d",
            processed, errors, alerts_sent,
        )


# 
# Standalone entry point
# 

def main() -> None:
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] consumer | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        level=logging.INFO,
        stream=sys.stdout,
    )
    logging.getLogger("kafka").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)

    parser = argparse.ArgumentParser(description="IPsec Kafka feature row consumer")
    parser.add_argument(
        "--bootstrap", default=BOOTSTRAP_SERVERS,
        help=f"Kafka bootstrap servers (default: {BOOTSTRAP_SERVERS})",
    )
    parser.add_argument(
        "--api-url", default=API_BASE_URL,
        help=f"FastAPI base URL (default: {API_BASE_URL})",
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args()

    # Re-apply log level from CLI
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))

    run_consumer_loop(bootstrap=args.bootstrap, api_url=args.api_url)


if __name__ == "__main__":
    main()