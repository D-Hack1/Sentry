import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from elasticsearch import Elasticsearch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from es.init_index import es_url_from_env  # noqa: E402


def main():
    host = es_url_from_env()
    index = os.environ.get("ES_INDEX")
    if not index:
        print("FAIL: ES_INDEX must be set")
        return 1

    try:
        client = Elasticsearch(host)
        status = client.cluster.health(timeout="10s")["status"]
        exists = client.indices.exists(index=index)
        stats = client.indices.stats(index=index) if exists else None
    except Exception as exc:
        print(f"FAIL: cannot reach Elasticsearch at {host}: {exc}")
        return 1

    if status not in ("green", "yellow"):
        print(f"FAIL: cluster status is {status}")
        return 1
    if not exists:
        print(f"FAIL: index {index} does not exist")
        return 1

    total = stats["_all"]["primaries"]
    doc_count = total["docs"]["count"]
    size_bytes = total["store"]["size_in_bytes"]
    print(f"OK: Elasticsearch at {host} status={status}")
    print(f"OK: index {index} docs={doc_count} size_bytes={size_bytes}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
