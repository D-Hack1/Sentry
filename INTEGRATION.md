# Integration Test

Date: 2026-09-28

## Stack

`make down && make up`, fresh volumes, no cached state.

| Container | Status |
|---|---|
| ipsec-initiator | Up |
| ipsec-responder | Up |
| ipsec-monitor | Up |
| pipeline-zookeeper | Up (healthy) |
| pipeline-kafka | Up (healthy) |
| pipeline-elasticsearch | Up (healthy) |

## Health checks

| Check | Result |
|---|---|
| `python kafka/health_check.py` | OK — reachable at localhost:29092, all 4 topics present |
| `python es/health_check.py` | OK — status=green, index `ipsec_sessions` exists |
| Kafka topics | `raw-features`, `inference-results`, `alerts`, `pipeline-metrics` — 1 partition, replication factor 1, retention.ms=21600000 each |
| `FastAPI /health` | Not tested — `api/main.py`, `api/correlator.py`, `api/report_generator.py` are still empty |

## Capture matrix

100/100 sessions captured and verified (`capture/pcaps/`), 50 tunnel / 50 transport, all 80 config combinations covered, IKE + ESP confirmed present in every PCAP.

## Metrics producer

`kafka/metrics_producer.py` run against the live stack with synthetic messages on `raw-features` and `inference-results`:

- `kafka_queue_depth` tracked lag on `raw-features` for the `ipsec-consumer-group` group correctly as messages were produced.
- `sessions_per_sec` / `bytes_per_sec` reflected messages sampled from `raw-features` in the same 2s cycle they arrived.
- `pipeline_latency_ms` reflected the average `pipeline_latency_ms` field sampled from `inference-results` in the same cycle.
- Clean shutdown on SIGTERM and SIGINT, no orphaned consumer group members.

## Issues found and fixed during this test

- `ES_JAVA_OPTS` in `.env` was quoted (`"-Xms512m -Xmx512m"`); `docker compose --env-file` does not strip quotes the way a shell does, so Elasticsearch failed to start reading it as a class name. Fixed by removing the quotes.
- `kafka/health_check.py` read `KAFKA_BOOTSTRAP_SERVERS`, but `kafka/producer.py` and `kafka/consumer.py` read `KAFKA_BOOTSTRAP`. Standardized on `KAFKA_BOOTSTRAP` in `.env`, `.env.example`, and `kafka/health_check.py`.
- Kafka topics were created with 3 partitions; dropped to 1 partition, replication factor 1, with `retention.ms=21600000` added.

## Known gaps

- `api/main.py` and the rest of `api/` are empty — `/health` and `/analyze` are not implemented yet, so the consumer (`kafka/consumer.py`) and this integration test cannot exercise the full pipeline end to end.
- `capture/pcaps/` is not version-controlled; share the 100-file set separately (see `LAB.md`).
