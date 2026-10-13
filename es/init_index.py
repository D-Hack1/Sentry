"""
es/init_index.py — create (or upgrade) the ipsec_sessions index.

    python es/init_index.py              # create if missing, add any new fields
    python es/init_index.py --recreate   # drop and recreate (DELETES all sessions)

The mapping matches the documents written by api/main.py (POST /analyze).
The API calls ensure_index() itself at startup, so running this by hand is optional.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from elasticsearch import Elasticsearch

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

KEYWORD = {"type": "keyword"}
INTEGER = {"type": "integer"}
LONG = {"type": "long"}
FLOAT = {"type": "float"}
DOUBLE = {"type": "double"}
BOOLEAN = {"type": "boolean"}
IP = {"type": "ip"}
TEXT = {"type": "text"}
DATE = {"type": "date"}  # strict_date_optional_time || epoch_millis

PROPERTIES = {
    # identity
    "es_id": KEYWORD,
    "session_id": KEYWORD,
    "ts": DATE,                     # ISO 8601 session start
    "ts_epoch": DOUBLE,             # original unix timestamp
    "analyzed_at": DATE,
    "initiator_ip": IP,
    "responder_ip": IP,
    "initiator_port": INTEGER,
    "responder_port": INTEGER,
    "duration": FLOAT,
    # IKE
    "ike_version": INTEGER,
    "ike_exchange_type": INTEGER,
    "ike_initiator_spi": KEYWORD,
    "sa_proposal_count": INTEGER,
    "ke_dh_group": INTEGER,
    "ike_nat_traversal": BOOLEAN,
    "ike_packet_count": INTEGER,
    "ike_handshake_duration": FLOAT,
    # resolved config
    "mode": KEYWORD,
    "cipher_suite": KEYWORD,
    "auth_algo": KEYWORD,
    "dh_group": KEYWORD,
    "pfs_enabled": BOOLEAN,
    "key_lifetime_sec": INTEGER,
    "esp_spi": KEYWORD,
    "config_source": {"properties": {f: KEYWORD for f in ("mode", "cipher_suite", "dh_group", "pfs_enabled")}},
    "predicted_config": KEYWORD,
    "config_confidence": FLOAT,
    # ESP metadata
    "esp_packet_count": LONG,
    "esp_bytes_total": LONG,
    "esp_pkt_size_mean": FLOAT,
    "esp_pkt_size_std": FLOAT,
    "esp_pkt_size_min": FLOAT,
    "esp_pkt_size_max": FLOAT,
    "esp_iat_mean": FLOAT,
    "esp_iat_std": FLOAT,
    "esp_iat_min": FLOAT,
    "esp_iat_max": FLOAT,
    "esp_burst_count": INTEGER,
    "esp_burst_size_mean": FLOAT,
    "esp_bytes_per_sec": FLOAT,
    "esp_pkts_per_sec": FLOAT,
    "asymmetry_ratio": FLOAT,
    "esp_pkt_size_entropy": FLOAT,
    "esp_iat_entropy": FLOAT,
    "esp_active_fraction": FLOAT,
    # model + scorer outputs
    "traffic_class": KEYWORD,
    "traffic_confidence": FLOAT,
    "anomaly_score": FLOAT,
    "anomaly_label": KEYWORD,
    "ai_confidence": FLOAT,
    "security_score": FLOAT,
    "severity": KEYWORD,
    "risk_flags": KEYWORD,
    "recommendations": TEXT,
    "evidence": TEXT,
    "config_evidence": TEXT,
    "report_id": KEYWORD,
    # correlation (api/correlator.py)
    "adjusted_security_score": FLOAT,
    "adjusted_severity": KEYWORD,
    "correlation": {
        "properties": {
            "initiator_ip": IP,
            "weak_session_count": INTEGER,
            "recent_weak_sessions": {"type": "object", "enabled": False},
            "pattern_detected": BOOLEAN,
            "pattern_description": TEXT,
            "correlation_confidence": FLOAT,
            "recommended_action": TEXT,
        }
    },
    # ground truth (only present on replayed lab captures)
    "label_config": KEYWORD,
    "label_traffic": KEYWORD,
}

INDEX_SETTINGS = {"number_of_shards": 1, "number_of_replicas": 0}


def es_url_from_env() -> str:
    """ES_HOST may be a full URL (http://localhost:9200) or a bare host plus ES_PORT."""
    host = os.environ.get("ES_HOST", "http://localhost:9200").strip()
    if "://" in host:
        return host.rstrip("/")
    return f"http://{host}:{os.environ.get('ES_PORT', '9200')}"


def _leaf_types(props: dict, prefix: str = "") -> dict:
    out = {}
    for name, spec in props.items():
        path = f"{prefix}{name}"
        if "properties" in spec:
            out.update(_leaf_types(spec["properties"], f"{path}."))
        else:
            out[path] = (spec.get("type", "object"), spec.get("format"))
    return out


def mapping_conflicts(existing_props: dict) -> list[str]:
    """Fields whose existing type/format differs from PROPERTIES (cannot be changed in place)."""
    wanted = _leaf_types(PROPERTIES)
    have = _leaf_types(existing_props)
    return [
        f"{path}: has {have[path]}, expected {spec}"
        for path, spec in wanted.items()
        if path in have and have[path] != spec
    ]


def ensure_index(client: Elasticsearch, index: str, recreate: bool = False) -> str:
    """
    Make sure `index` exists with a compatible mapping. Returns a status string.
    An existing index with an incompatible mapping is recreated automatically only
    if it is empty; otherwise RuntimeError tells the operator to pass --recreate.
    """
    if client.indices.exists(index=index):
        if recreate:
            client.indices.delete(index=index)
        else:
            existing = client.indices.get_mapping(index=index)[index]["mappings"].get("properties", {})
            conflicts = mapping_conflicts(existing)
            if conflicts:
                docs = client.count(index=index)["count"]
                if docs:
                    raise RuntimeError(
                        f"index {index} holds {docs} docs with an incompatible mapping "
                        f"({'; '.join(conflicts[:3])}). Run: python es/init_index.py --recreate"
                    )
                client.indices.delete(index=index)
            else:
                client.indices.put_mapping(index=index, properties=PROPERTIES)
                return f"index {index} already exists (mapping up to date)"
    client.indices.create(
        index=index,
        settings=INDEX_SETTINGS,
        mappings={"dynamic": "true", "properties": PROPERTIES},
    )
    return f"index {index} created"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Create the Elasticsearch sessions index")
    parser.add_argument("--recreate", action="store_true", help="Delete and recreate the index")
    args = parser.parse_args(argv)

    index = os.environ.get("ES_INDEX", "ipsec_sessions")
    url = es_url_from_env()
    try:
        status = ensure_index(Elasticsearch(url), index, recreate=args.recreate)
    except Exception as exc:
        print(f"FAIL: {exc}")
        return 1
    print(f"OK: {status} at {url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
