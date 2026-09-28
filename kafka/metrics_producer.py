from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone

from kafka import KafkaConsumer, KafkaProducer, TopicPartition
from kafka.admin import KafkaAdminClient
from kafka.errors import KafkaError, KafkaConnectionError

BOOTSTRAP_SERVERS: str = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
TOPIC_RAW_FEATURES: str = os.getenv("KAFKA_TOPIC_RAW_FEATURES", "raw-features")
TOPIC_INFERENCE: str = os.getenv("KAFKA_TOPIC_INFERENCE_RESULTS", "inference-results")
TOPIC_METRICS: str = os.getenv("KAFKA_TOPIC_PIPELINE_METRICS", "pipeline-metrics")
PIPELINE_CONSUMER_GROUP: str = "ipsec-consumer-group"
INTERVAL_SEC: float = 2.0
CONNECT_RETRY_SEC: int = 5
MAX_CONNECT_RETRIES: int = 12

log = logging.getLogger("metrics_producer")


def _retry(build_fn, retries=MAX_CONNECT_RETRIES):
    for attempt in range(1, retries + 1):
        try:
            return build_fn()
        except (KafkaConnectionError, KafkaError):
            log.warning(
                "Kafka not reachable (attempt %d/%d) — retrying in %ds",
                attempt, retries, CONNECT_RETRY_SEC,
            )
            if attempt < retries:
                time.sleep(CONNECT_RETRY_SEC)
    log.critical("Could not connect to Kafka after %d attempts — exiting", retries)
    sys.exit(1)


def _make_admin(bootstrap):
    return _retry(lambda: KafkaAdminClient(bootstrap_servers=bootstrap))


def _make_lag_consumer(bootstrap):
    return _retry(lambda: KafkaConsumer(bootstrap_servers=bootstrap))


def _make_tail_consumer(bootstrap, topic, value_deserializer):
    def build():
        consumer = KafkaConsumer(
            bootstrap_servers=bootstrap,
            enable_auto_commit=False,
            value_deserializer=value_deserializer,
        )
        partitions = consumer.partitions_for_topic(topic) or set()
        tps = [TopicPartition(topic, p) for p in partitions]
        consumer.assign(tps)
        if tps:
            consumer.seek_to_end(*tps)
        return consumer

    return _retry(build)


def _make_producer(bootstrap):
    return _retry(lambda: KafkaProducer(
        bootstrap_servers=bootstrap,
        value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
        acks="all",
        retries=5,
        retry_backoff_ms=200,
    ))


def _queue_depth(admin, lag_consumer):
    partitions = lag_consumer.partitions_for_topic(TOPIC_RAW_FEATURES)
    if not partitions:
        return 0

    tps = [TopicPartition(TOPIC_RAW_FEATURES, p) for p in partitions]
    end_offsets = lag_consumer.end_offsets(tps)

    try:
        committed = admin.list_group_offsets(PIPELINE_CONSUMER_GROUP).get(PIPELINE_CONSUMER_GROUP, {})
    except KafkaError:
        committed = {}

    depth = 0
    for tp in tps:
        end = end_offsets.get(tp, 0)
        offset_meta = committed.get(tp)
        current = offset_meta.offset if offset_meta and offset_meta.offset >= 0 else 0
        depth += max(0, end - current)
    return depth


def _sample_raw_features(sample_consumer, timeout_ms):
    count = 0
    total_bytes = 0
    per_partition = sample_consumer.poll(timeout_ms=timeout_ms)
    for records in per_partition.values():
        for record in records:
            count += 1
            total_bytes += len(record.value) if record.value else 0
    return count, total_bytes


def _sample_latency(latency_consumer, timeout_ms):
    values = []
    per_partition = latency_consumer.poll(timeout_ms=timeout_ms)
    for records in per_partition.values():
        for record in records:
            latency = record.value.get("pipeline_latency_ms")
            if latency is not None:
                values.append(float(latency))
    if not values:
        return 0.0
    return sum(values) / len(values)


class _Shutdown(Exception):
    pass


def _handle_sigterm(signum, frame):
    raise _Shutdown()


def run_metrics_loop(bootstrap=BOOTSTRAP_SERVERS, interval=INTERVAL_SEC):
    log.info("Metrics producer starting | bootstrap=%s | interval=%.1fs", bootstrap, interval)
    signal.signal(signal.SIGTERM, _handle_sigterm)

    admin = _make_admin(bootstrap)
    lag_consumer = _make_lag_consumer(bootstrap)
    sample_consumer = _make_tail_consumer(bootstrap, TOPIC_RAW_FEATURES, lambda b: b)
    latency_consumer = _make_tail_consumer(
        bootstrap, TOPIC_INFERENCE, lambda b: json.loads(b.decode("utf-8"))
    )
    producer = _make_producer(bootstrap)

    published = 0
    try:
        while True:
            cycle_start = time.monotonic()
            timeout_ms = int(interval * 1000 / 2)

            session_count, byte_count = _sample_raw_features(sample_consumer, timeout_ms)
            latency_ms = _sample_latency(latency_consumer, timeout_ms)
            queue_depth = _queue_depth(admin, lag_consumer)

            elapsed = max(time.monotonic() - cycle_start, interval)
            metrics = {
                "schema_version": "1.0",
                "ts": datetime.now(timezone.utc).isoformat(),
                "sessions_per_sec": round(session_count / elapsed, 3),
                "bytes_per_sec": round(byte_count / elapsed, 3),
                "kafka_queue_depth": queue_depth,
                "pipeline_latency_ms": round(latency_ms, 2),
            }

            try:
                producer.send(TOPIC_METRICS, value=metrics)
                producer.flush(timeout=5)
                published += 1
                log.info(
                    "METRICS | sessions_per_sec=%.2f | bytes_per_sec=%.1f | "
                    "queue_depth=%d | latency_ms=%.1f",
                    metrics["sessions_per_sec"], metrics["bytes_per_sec"],
                    metrics["kafka_queue_depth"], metrics["pipeline_latency_ms"],
                )
            except KafkaError as exc:
                log.error("Failed to publish pipeline metrics: %s", exc)

            remaining = interval - (time.monotonic() - cycle_start)
            if remaining > 0:
                time.sleep(remaining)
    except (KeyboardInterrupt, _Shutdown):
        log.info("Metrics producer interrupted")
    finally:
        for client in (sample_consumer, latency_consumer, lag_consumer):
            try:
                client.close()
            except Exception:
                pass
        try:
            producer.flush(timeout=5)
            producer.close()
        except Exception:
            pass
        try:
            admin.close()
        except Exception:
            pass
        log.info("Metrics producer stopped | published=%d", published)


def main():
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] metrics_producer | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        level=logging.INFO,
        stream=sys.stdout,
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("--bootstrap", default=BOOTSTRAP_SERVERS)
    parser.add_argument("--interval", type=float, default=INTERVAL_SEC)
    args = parser.parse_args()

    run_metrics_loop(bootstrap=args.bootstrap, interval=args.interval)


if __name__ == "__main__":
    main()
