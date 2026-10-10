# kafka/

Kafka glue for the streaming pipeline. Run these **by path** from the repository
root (`python kafka/consumer.py`), never as `python -m kafka.consumer`: the
directory name is also the import name of the kafka-python library.

| File | Role |
|---|---|
| `producer.py` | Library used by `features/watcher.py`: drains the watcher's in-memory staging queue and publishes feature rows to `raw-features` in 100 ms batches. Running it directly starts the watcher (the queue only exists inside that process). |
| `consumer.py` | `raw-features` → `POST /analyze` → `inference-results`; sessions with `security_score < 50` also go to `alerts`. Transient API failures are retried with backoff; malformed messages go to `.run/consumer_dead_letter.jsonl` — the loop never crashes on bad input. |
| `metrics_producer.py` | Every 2 s publishes `{ts, sessions_per_sec, bytes_per_sec, kafka_queue_depth, pipeline_latency_ms}` to `pipeline-metrics` (streamed to the dashboard by `GET /metrics`). Queue depth = consumer-group lag on `raw-features`; latency = median publish→stored time. |
| `health_check.py` | Exit 0 when Kafka is reachable and all four topics exist. |

## Topics

Created by the `kafka-init` container (`docker-compose.yml`): 1 partition,
replication factor 1, `retention.ms=21600000` (6 h).

| Topic | Producer | Consumer | Message |
|---|---|---|---|
| `raw-features` | watcher (producer.py) | consumer.py | `{schema_version, source, enqueued_at, published_at, feature_row: IPsecFeatureRow}` |
| `inference-results` | consumer.py | metrics_producer.py | `KafkaInferenceResult` + `es_id`, `pipeline_latency_ms` |
| `alerts` | consumer.py | — | `KafkaAlert` (score < 50) |
| `pipeline-metrics` | metrics_producer.py | API `/metrics` (SSE) | `KafkaPipelineMetrics` |

Message dataclasses live in `features/schema.py`; JSON (de)serializers in
`features/kafka_serde.py`.

## Configuration (`.env`)

`KAFKA_BOOTSTRAP` (default `localhost:29092`, the host-exposed listener),
`KAFKA_TOPIC_RAW_FEATURES`, `KAFKA_TOPIC_INFERENCE_RESULTS`, `KAFKA_TOPIC_ALERTS`,
`KAFKA_TOPIC_PIPELINE_METRICS`, `API_BASE_URL` (consumer → API, default `http://localhost:8000`).
