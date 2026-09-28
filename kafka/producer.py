"""

Drains the STAGING_QUEUE populated by watcher.py and publishes feature rows
to the 'raw-features' Kafka topic in 100 ms batching windows.

Can run in-process (call run_producer_loop() in a background thread) or as a
standalone process (python -m kafka.producer).

Standalone usage:
    python -m kafka.producer [--bootstrap localhost:9092] [--batch-ms 100]

In-process usage (from watcher main or a supervisor):
    import threading
    from pipeline_kafka.producer import run_producer_loop
    t = threading.Thread(target=run_producer_loop, daemon=True)
    t.start()

"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import List

from kafka import KafkaProducer
from kafka.errors import KafkaError, KafkaConnectionError

from features.watcher import STAGING_QUEUE

# 
# Config (env overrides CLI defaults)
# 

BOOTSTRAP_SERVERS: str = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
TOPIC_RAW_FEATURES: str = "raw-features"
DEFAULT_BATCH_MS: int   = 100       # drain window in milliseconds
MAX_DRAIN_PER_CYCLE: int = 500      # safety cap — never block > 500 rows in one flush
CONNECT_RETRY_SEC: int  = 5         # seconds between Kafka connection retries
MAX_CONNECT_RETRIES: int = 12       # give up after 1 minute of retrying

log = logging.getLogger("producer")


# 
# Kafka producer factory
# 

def _make_producer(bootstrap: str, retries: int = MAX_CONNECT_RETRIES) -> KafkaProducer:
    """
    Build a KafkaProducer with JSON serialisation and delivery guarantees.
    Retries on KafkaConnectionError so the process survives a slow Kafka start.
    """
    for attempt in range(1, retries + 1):
        try:
            producer = KafkaProducer(
                bootstrap_servers=bootstrap,
                value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
                # Reliability settings
                acks="all",                 # wait for all in-sync replicas
                retries=5,
                retry_backoff_ms=200,
                # Batching — we handle our own 100ms window, but let Kafka batch
                # any residual messages within its own linger window too.
                linger_ms=10,
                batch_size=65536,           # 64 KB internal Kafka batch
                compression_type="gzip",
                # Connection
                request_timeout_ms=10_000,
                connections_max_idle_ms=30_000,
            )
            log.info("Kafka producer connected | bootstrap=%s", bootstrap)
            return producer
        except (KafkaConnectionError, KafkaError):
            log.warning(
                "Kafka not reachable (attempt %d/%d) — retrying in %ds",
                attempt, retries, CONNECT_RETRY_SEC,
            )
            if attempt < retries:
                time.sleep(CONNECT_RETRY_SEC)

    log.critical("Could not connect to Kafka after %d attempts — exiting", retries)
    sys.exit(1)


# 
# Delivery callback
# 

def _on_send_success(record_metadata, session_id: str) -> None:
    log.debug(
        "SENT | session_id=%s | topic=%s | partition=%d | offset=%d",
        session_id,
        record_metadata.topic,
        record_metadata.partition,
        record_metadata.offset,
    )


def _on_send_error(exc: Exception, session_id: str) -> None:
    log.error("SEND FAILED | session_id=%s | %s: %s", session_id, type(exc).__name__, exc)


# 
# Core batch-publish loop
# 

def _drain_and_publish(producer: KafkaProducer, batch_ms: int) -> int:
    """
    Collect everything currently in STAGING_QUEUE within a `batch_ms` window
    and publish each row as an independent Kafka message.

    Returns the number of messages published in this cycle.
    """
    deadline = time.monotonic() + (batch_ms / 1000.0)
    batch: List[dict] = []

    # Drain the queue until the window expires or cap is reached
    while time.monotonic() < deadline and len(batch) < MAX_DRAIN_PER_CYCLE:
        timeout_remaining = deadline - time.monotonic()
        if timeout_remaining <= 0:
            break
        try:
            msg = STAGING_QUEUE.get(timeout=timeout_remaining)
            batch.append(msg)
        except Exception:
            # queue.Empty — window expired with nothing left
            break

    if not batch:
        return 0

    published = 0
    for msg in batch:
        session_id = msg.get("feature_row", {}).get("session_id", "unknown")
        # Stamp publish time so consumer can compute pipeline latency
        msg["published_at"] = datetime.now(timezone.utc).isoformat()

        try:
            future = producer.send(TOPIC_RAW_FEATURES, value=msg)
            future.add_callback(_on_send_success, session_id=session_id)
            future.add_errback(_on_send_error, session_id=session_id)
            published += 1
        except KafkaError as exc:
            log.error(
                "KAFKA ERROR | session_id=%s | %s: %s — message dropped to dead-letter log",
                session_id, type(exc).__name__, exc,
            )
            _dead_letter(msg, reason=str(exc))

    # Flush after each batch so delivery callbacks fire promptly
    try:
        producer.flush(timeout=5)
    except KafkaError as exc:
        log.error("Flush error: %s", exc)

    log.info(
        "BATCH | published=%d | queue_remaining=%d | batch_window_ms=%d",
        published, STAGING_QUEUE.qsize(), batch_ms,
    )
    return published


# 
# Dead-letter logger
# 

def _dead_letter(msg: dict, reason: str) -> None:
    """
    Write un-publishable messages to a local dead-letter log file.
    Never raises — called from error paths where raising would lose the message.
    """
    try:
        dl_path = os.getenv("DEAD_LETTER_LOG", "/tmp/producer_dead_letter.jsonl")
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "message": msg,
        }
        with open(dl_path, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception as write_exc:
        log.error("Dead-letter write failed: %s", write_exc)


# 
# Public loop — called by thread or directly
# 

def run_producer_loop(
    bootstrap: str = BOOTSTRAP_SERVERS,
    batch_ms: int = DEFAULT_BATCH_MS,
) -> None:
    """
    Long-running loop. Blocks the calling thread.
    Designed to run as a daemon thread alongside watcher.py,
    or as a standalone process.
    """
    log.info(
        "Producer starting | bootstrap=%s | batch_ms=%d | topic=%s",
        bootstrap, batch_ms, TOPIC_RAW_FEATURES,
    )
    producer = _make_producer(bootstrap)
    total_published = 0

    try:
        while True:
            n = _drain_and_publish(producer, batch_ms)
            total_published += n
            # If the batch was empty, sleep briefly to avoid spinning.
            # If it was full, loop immediately — queue may have more.
            if n == 0:
                time.sleep(batch_ms / 1000.0)
    except KeyboardInterrupt:
        log.info("Producer interrupted — flushing remaining messages")
    finally:
        try:
            producer.flush(timeout=10)
        except Exception as exc:
            log.error("Final flush error: %s", exc)
        producer.close()
        log.info("Producer stopped | total_published=%d", total_published)


# 
# Standalone entry point
# 

def main() -> None:
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] producer | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        level=logging.INFO,
        stream=sys.stdout,
    )

    parser = argparse.ArgumentParser(description="IPsec Kafka feature row producer")
    parser.add_argument(
        "--bootstrap", default=BOOTSTRAP_SERVERS,
        help=f"Kafka bootstrap servers (default: {BOOTSTRAP_SERVERS})",
    )
    parser.add_argument(
        "--batch-ms", type=int, default=DEFAULT_BATCH_MS,
        help=f"Batch window in milliseconds (default: {DEFAULT_BATCH_MS})",
    )
    args = parser.parse_args()

    run_producer_loop(bootstrap=args.bootstrap, batch_ms=args.batch_ms)


if __name__ == "__main__":
    main()