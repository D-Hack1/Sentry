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
| `FastAPI /health` | See the 2026-10-10 run below |

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

## Full-stack run — 2026-10-10

`./stop.sh && ./start.sh --no-lab`: everything bootstrapped and started in about 40 s.

| Check | Result |
|---|---|
| `GET /health` | `status: ok`. Kafka connected (4 topics), ES green, models loaded |
| `python scripts/e2e_test.py` | **35/35 checks passed** |
| Direct `/analyze` (7 real-PCAP fixture rows) | all 5 traffic classes correct; best-practice config 100/info; worst config 0/critical |
| Kafka path | `raw-features` → consumer → API → ES, result on `inference-results`, alert on `alerts` |
| Watcher path | synthetic IKEv2+ESP PCAP → watcher → producer → Kafka → consumer → ES in < 2 s; cipher parsed from IKE_SA_INIT, mode inferred by the protocol model |
| `/sessions` filters, `/stats`, `/report` PDF, `/metrics` SSE | all OK |
| Dashboard (headless Chromium) | Live feed, session detail, stats, metrics, report render live data, no console errors |
| `python -m pytest` | 239 passed |

### Issues found and fixed in this pass

- `ml/` (inference, scorer, explainability, train, evaluate, tests), `reports/template.html`,
  `data/verify.py`, `features/ike_field_table.py` were empty files — implemented.
- `elasticsearch==9.x` client is rejected by the 8.11 server — pinned `elasticsearch==8.19.3`;
  `AsyncElasticsearch` needs `aiohttp` (added).
- Models were trained with scikit-learn 1.9.1 but 1.8.0 was pinned — bumped; `matplotlib` added for `evaluate.py`.
- ES mapping (`ts` epoch_second, `evidence` text) conflicted with the documents the API writes — remapped;
  `es/init_index.py` now upgrades in place / recreates empty incompatible indices.
- Elasticsearch `memlock` ulimit removed (only meaningful with `bootstrap.memory_lock`; fails on rootless/restricted Docker).
- Compose project pinned to `name: sentry` so `make promisc` finds the `sentry-monitor` image.
- `source .env` breaks on the unquoted `ES_JAVA_OPTS` value — shell scripts use `scripts/env.sh` instead.
- Watcher called non-existent `parse_pcap` / `extract_features`; its staging queue was never drained
  (producer ran in a separate process) — producer now runs as a thread inside the watcher; PCAPs are
  processed on close/rename/size-settle instead of 0.5 s after creation.

## Known gaps

- The capture-lab images (`initiator`, `responder`, `monitor`) could not be rebuilt in the 2026-10-10
  environment (Debian mirrors unreachable), so `make matrix` was not re-run; the pinned Debian package
  versions in their Dockerfiles must still exist on the mirror for `./start.sh` (without `--no-lab`) to build them.
- The protocol model was trained on ~1 sample per config class (macro-F1 0.15); config fields visible in
  plaintext IKE always come from the parser, the model only fills the encrypted ones.
