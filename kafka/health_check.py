import os
import sys
from pathlib import Path

from confluent_kafka.admin import AdminClient
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

REQUIRED_TOPIC_VARS = (
    "KAFKA_TOPIC_RAW_FEATURES",
    "KAFKA_TOPIC_INFERENCE_RESULTS",
    "KAFKA_TOPIC_ALERTS",
    "KAFKA_TOPIC_PIPELINE_METRICS",
)


def main():
    bootstrap = os.environ.get("KAFKA_BOOTSTRAP")
    if not bootstrap:
        print("FAIL: KAFKA_BOOTSTRAP not set")
        return 1

    expected = []
    for var in REQUIRED_TOPIC_VARS:
        value = os.environ.get(var)
        if not value:
            print(f"FAIL: {var} not set")
            return 1
        expected.append(value)

    try:
        metadata = AdminClient({"bootstrap.servers": bootstrap}).list_topics(timeout=10)
    except Exception as exc:
        print(f"FAIL: cannot reach Kafka at {bootstrap}: {exc}")
        return 1

    missing = [t for t in expected if t not in metadata.topics]
    if missing:
        print(f"FAIL: missing topics: {', '.join(missing)}")
        return 1

    print(f"OK: Kafka reachable at {bootstrap}, topics present: {', '.join(expected)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
