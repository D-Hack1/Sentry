"""
kafka/producer.py — drains the watcher's staging queue and publishes feature
rows to the 'raw-features' Kafka topic in 100 ms batching windows.

The staging queue lives in the watcher's memory, so the producer runs as a
background thread *inside* the watcher process (features/watcher.py starts it).
Running this file directly simply launches the watcher with its producer:

    python kafka/producer.py --captures-dir capture/pcaps
    # identical to: python -m features.watcher --captures-dir capture/pcaps

Note: this directory is called `kafka/`, which is also the import name of the
kafka-python library. Always run these scripts by path (python kafka/x.py),
never as `python -m kafka.x`.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env")

from kafka import KafkaProducer  # noqa: E402  (kafka-python)
from kafka.errors import KafkaError  # noqa: E402

from features.kafka_serde import JsonValueSerializer, StrKeySerializer  # noqa: E402

BOOTSTRAP_SERVERS: str = os.getenv("KAFKA_BOOTSTRAP", "localhost:29092")
TOPIC_RAW_FEATURES: str = os.getenv("KAFKA_TOPIC_RAW_FEATURES", "raw-features")
DEFAULT_BATCH_MS: int = 100       # drain window in milliseconds
MAX_DRAIN_PER_CYCLE: int = 500    # never publish more than this in one window
CONNECT_RETRY_SEC: int = 5
MAX_CONNECT_RETRIES: int = 12     # give up after ~1 minute

log = logging.getLogger("producer")


def make_producer(bootstrap: str = BOOTSTRAP_SERVERS, retries: int = MAX_CONNECT_RETRIES) -> KafkaProducer:
    """KafkaProducer with JSON values; retries while Kafka is still starting."""
    last_exc: Optional[Exception] = None
    for attempt in range(1, retries + 1):
        try:
            producer = KafkaProducer(
                bootstrap_servers=bootstrap,
                key_serializer=StrKeySerializer(),
                value_serializer=JsonValueSerializer(),
                acks="all",
                retries=5,
                retry_backoff_ms=200,
                linger_ms=10,
                batch_size=65536,
                compression_type="gzip",
                request_timeout_ms=10_000,
                connections_max_idle_ms=30_000,
            )
            log.info("Kafka producer connected | bootstrap=%s | topic=%s", bootstrap, TOPIC_RAW_FEATURES)
            return producer
        except KafkaError as exc:
            last_exc = exc
            log.warning("Kafka not reachable (attempt %d/%d): %s", attempt, retries, exc)
            if attempt < retries:
                time.sleep(CONNECT_RETRY_SEC)
    raise RuntimeError(f"Could not connect to Kafka at {bootstrap}: {last_exc}")


def _dead_letter(msg: dict, reason: str) -> None:
    """Append an unpublishable message to the dead-letter JSONL file. Never raises."""
    try:
        path = os.getenv("PRODUCER_DEAD_LETTER_LOG", str(ROOT / ".run" / "producer_dead_letter.jsonl"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        entry = {"ts": datetime.now(timezone.utc).isoformat(), "reason": reason, "message": msg}
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")
    except Exception as exc:
        log.error("Dead-letter write failed: %s", exc)


def drain_and_publish(producer: KafkaProducer, staging_queue: "queue.Queue[dict]", batch_ms: int) -> int:
    """Publish everything that arrives in the queue within one `batch_ms` window."""
    deadline = time.monotonic() + batch_ms / 1000.0
    batch: List[dict] = []
    while len(batch) < MAX_DRAIN_PER_CYCLE:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            batch.append(staging_queue.get(timeout=remaining))
        except queue.Empty:
            break
    if not batch:
        return 0

    published = 0
    for msg in batch:
        session_id = (msg.get("feature_row") or {}).get("session_id", "unknown")
        msg["published_at"] = datetime.now(timezone.utc).isoformat()
        try:
            future = producer.send(TOPIC_RAW_FEATURES, key=session_id, value=msg)
            future.add_errback(lambda exc, m=msg: (log.error("SEND FAILED | %s", exc), _dead_letter(m, str(exc))))
            published += 1
        except KafkaError as exc:
            log.error("KAFKA ERROR | session_id=%s | %s", session_id, exc)
            _dead_letter(msg, str(exc))
    try:
        producer.flush(timeout=10)
    except KafkaError as exc:
        log.error("Flush error: %s", exc)
    log.info("BATCH | published=%d | queue_remaining=%d", published, staging_queue.qsize())
    return published


def run_producer_loop(
    staging_queue: "queue.Queue[dict]",
    bootstrap: str = BOOTSTRAP_SERVERS,
    batch_ms: int = DEFAULT_BATCH_MS,
    stop_event: Optional[threading.Event] = None,
    producer: Optional[KafkaProducer] = None,
) -> int:
    """
    Publish until stop_event is set AND the queue is empty (so nothing queued is
    lost on shutdown). Returns the number of messages published.
    """
    stop_event = stop_event or threading.Event()
    producer = producer or make_producer(bootstrap)
    total = 0
    try:
        while not (stop_event.is_set() and staging_queue.empty()):
            total += drain_and_publish(producer, staging_queue, batch_ms)
    finally:
        try:
            producer.flush(timeout=10)
            producer.close(timeout=10)
        except Exception as exc:
            log.error("Producer close error: %s", exc)
        log.info("Producer stopped | total_published=%d", total)
    return total


if __name__ == "__main__":
    from features.watcher import main as watcher_main

    watcher_main()
