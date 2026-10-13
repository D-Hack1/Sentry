"""
scripts/e2e_test.py — end-to-end check of a running stack (./start.sh first).

Verifies every hop of the pipeline:
  1. API health                          GET /health is "ok"
  2. Direct analysis                     POST /analyze with the 7 real-PCAP fixture payloads
  3. Kafka path                          raw-features -> consumer -> /analyze -> ES,
                                         plus inference-results and alerts topics
  4. Watcher path                        synthetic PCAP in the capture dir -> watcher ->
                                         producer -> Kafka -> consumer -> ES
  5. Read endpoints                      /sessions filters, /sessions/{id}, /stats, /report/{id}
  6. Live metrics                        GET /metrics SSE delivers a data event

    python scripts/e2e_test.py [--api http://localhost:8000] [--skip-watcher]
Exit code 0 only if every check passed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env")

import httpx  # noqa: E402

from features.kafka_serde import JsonValueSerializer, SafeJsonDeserializer  # noqa: E402

FIXTURES = ROOT / "ml" / "tests" / "fixtures" / "test_payloads.json"
BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:29092")
TOPIC_RAW = os.getenv("KAFKA_TOPIC_RAW_FEATURES", "raw-features")
TOPIC_INFERENCE = os.getenv("KAFKA_TOPIC_INFERENCE_RESULTS", "inference-results")
TOPIC_ALERTS = os.getenv("KAFKA_TOPIC_ALERTS", "alerts")
CAPTURES_DIR = Path(os.getenv("CAPTURES_DIR") or ROOT / os.getenv("PCAP_DIR", "capture/pcaps"))

results: list[tuple[bool, str]] = []


def check(ok: bool, label: str) -> bool:
    results.append((ok, label))
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}", flush=True)
    return ok


def wait_for_session(client: httpx.Client, session_id: str, timeout: float) -> dict | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        resp = client.get(f"/sessions/{session_id}")
        if resp.status_code == 200:
            return resp.json()
        time.sleep(1)
    return None


def topic_has(topic: str, session_id: str, timeout: float = 20.0) -> bool:
    from kafka import KafkaConsumer, TopicPartition

    consumer = KafkaConsumer(bootstrap_servers=BOOTSTRAP, enable_auto_commit=False,
                             value_deserializer=SafeJsonDeserializer())
    try:
        tps = [TopicPartition(topic, p) for p in (consumer.partitions_for_topic(topic) or [])]
        consumer.assign(tps)
        consumer.seek_to_beginning(*tps)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for batch in consumer.poll(timeout_ms=1000).values():
                if any(m.value.get("session_id") == session_id for m in batch):
                    return True
        return False
    finally:
        consumer.close()


def step_health(client: httpx.Client) -> bool:
    print("1. Health")
    deadline = time.monotonic() + 60
    body = {}
    while time.monotonic() < deadline:
        try:
            body = client.get("/health").json()
            if body.get("status") == "ok":
                break
        except httpx.HTTPError:
            pass
        time.sleep(2)
    return check(body.get("status") == "ok", f"/health status ok ({json.dumps(body)[:160]})")


def step_direct(client: httpx.Client) -> list[dict]:
    print("2. POST /analyze with real-PCAP fixture payloads")
    docs = []
    expected = {"web", "voip", "video_stream", "file_transfer", "icmp"}
    for payload in json.loads(FIXTURES.read_text()):
        resp = client.post("/analyze", json=payload)
        if not check(resp.status_code == 200, f"analyze {payload['session_id']} -> {resp.status_code}"):
            continue
        doc = resp.json()
        docs.append(doc)
        want = next((c for c in expected if f"_{c}_" in payload["session_id"]), None)
        if want:  # the 5 real-PCAP rows have a known traffic class
            check(doc["traffic_class"] == want, f"  traffic_class {doc['traffic_class']} == {want}")
        check(bool(doc["evidence"]) and doc["es_id"], "  evidence present and es_id assigned")
    best = next((d for d in docs if d["session_id"] == "test_best_practice_config"), None)
    worst = next((d for d in docs if d["session_id"] == "test_critical_config_alert"), None)
    check(bool(best) and best["security_score"] == 100 and best["risk_flags"] == [], "best-practice config scores 100 with no flags")
    check(bool(worst) and worst["severity"] == "critical", "critical config scores critical")
    return docs


def step_kafka(client: httpx.Client) -> None:
    print("3. Kafka path: raw-features -> consumer -> API -> ES -> inference-results / alerts")
    from kafka import KafkaProducer

    payload = json.loads(FIXTURES.read_text())[-1]  # critical config -> must raise an alert
    session_id = f"e2e_kafka_{uuid.uuid4().hex[:8]}"
    envelope = {"schema_version": "1.0", "source": "e2e_test",
                "published_at": datetime.now(timezone.utc).isoformat(),
                "feature_row": {**payload, "session_id": session_id, "ts": time.time()}}
    producer = KafkaProducer(bootstrap_servers=BOOTSTRAP,
                             value_serializer=JsonValueSerializer())
    producer.send(TOPIC_RAW, envelope).get(timeout=10)
    producer.close()
    doc = wait_for_session(client, session_id, 60)
    check(doc is not None, f"consumer analysed {session_id} into Elasticsearch")
    check(topic_has(TOPIC_INFERENCE, session_id), f"{TOPIC_INFERENCE} has a result for {session_id}")
    check(topic_has(TOPIC_ALERTS, session_id), f"{TOPIC_ALERTS} has an alert for {session_id} (score < 50)")


def step_watcher(client: httpx.Client) -> None:
    print(f"4. Watcher path: synthetic PCAP -> {CAPTURES_DIR}")
    from synth_pcap import write_capture

    session_id = f"e2e_watcher_voip_{uuid.uuid4().hex[:8]}"
    path = write_capture(CAPTURES_DIR, session_id, "voip", "aes256_cbc", "group19", seed=1)
    try:
        doc = wait_for_session(client, session_id, 90)
        if check(doc is not None, f"watcher -> Kafka -> consumer -> ES for {session_id}"):
            check(doc["cipher_suite"] == "aes256_cbc" and doc["config_source"]["cipher_suite"] == "parser",
                  "cipher parsed from the IKE_SA_INIT plaintext")
            check(doc["config_source"]["mode"] == "model", "mode (encrypted in IKE_AUTH) filled by protocol model")
            check(doc["esp_packet_count"] > 300, f"ESP features extracted ({doc['esp_packet_count']} packets)")
    finally:
        path.unlink(missing_ok=True)
        (ROOT / "data" / "features" / f"{session_id}.parquet").unlink(missing_ok=True)


def step_reads(client: httpx.Client, docs: list[dict]) -> None:
    print("5. Read endpoints")
    listing = client.get("/sessions", params={"page_size": 5}).json()
    check(listing.get("total", 0) >= len(docs) and len(listing["items"]) <= 5 and "pages" in listing,
          f"/sessions pagination (total={listing.get('total')})")
    crit = client.get("/sessions", params={"severity": "critical"}).json()
    check(crit["total"] >= 1 and all(i["severity"] == "critical" for i in crit["items"]), "/sessions?severity=critical")
    nf = client.get("/sessions/does-not-exist")
    check(nf.status_code == 404 and nf.json()["error"]["code"] == "SESSION_NOT_FOUND", "404 error envelope")
    stats = client.get("/stats").json()
    check(stats["total_sessions"] >= len(docs) and len(stats["score_histogram"]) == 10, "/stats aggregates")
    if docs:
        report = client.get(f"/report/{docs[0]['es_id']}")
        check(report.status_code == 200 and report.content.startswith(b"%PDF"), f"/report PDF ({len(report.content)} bytes)")


def step_metrics(api: str) -> None:
    print("6. GET /metrics SSE")
    got = False
    try:
        with httpx.stream("GET", f"{api}/metrics", timeout=httpx.Timeout(20.0)) as resp:
            start = time.monotonic()
            for line in resp.iter_lines():
                if line.startswith("data:"):
                    data = json.loads(line[5:])
                    got = {"sessions_per_sec", "kafka_queue_depth", "pipeline_latency_ms"} <= set(data)
                    break
                if time.monotonic() - start > 15:
                    break
    except httpx.HTTPError as exc:
        print(f"    {exc}")
    check(got, "metrics event received (metrics producer -> Kafka -> SSE)")


def main() -> int:
    parser = argparse.ArgumentParser(description="End-to-end test of the running stack")
    parser.add_argument("--api", default=os.getenv("API_BASE_URL", "http://localhost:8000"))
    parser.add_argument("--skip-watcher", action="store_true")
    args = parser.parse_args()

    client = httpx.Client(base_url=args.api, timeout=60)
    if not step_health(client):
        print("API not healthy — is the stack running? (./start.sh)")
        return 1
    docs = step_direct(client)
    step_kafka(client)
    if not args.skip_watcher:
        step_watcher(client)
    step_reads(client, docs)
    step_metrics(args.api)

    failed = [label for ok, label in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    for label in failed:
        print(f"  FAILED: {label}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
