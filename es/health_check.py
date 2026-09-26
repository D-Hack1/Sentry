import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from elasticsearch import Elasticsearch

load_dotenv(Path(__file__).resolve().parent.parent / ".env")


def main():
    host = os.environ.get("ES_HOST")
    index = os.environ.get("ES_INDEX")
    if not host or not index:
        print("FAIL: ES_HOST and ES_INDEX must be set")
        return 1

    try:
        client = Elasticsearch(host)
        status = client.cluster.health(timeout="10s")["status"]
        exists = client.indices.exists(index=index)
    except Exception as exc:
        print(f"FAIL: cannot reach Elasticsearch at {host}: {exc}")
        return 1

    if status == "red":
        print("FAIL: cluster status is red")
        return 1
    if not exists:
        print(f"FAIL: index {index} does not exist")
        return 1

    print(f"OK: Elasticsearch at {host} status={status}, index {index} present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
