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
BOOLEAN = {"type": "boolean"}
IP = {"type": "ip"}

PROPERTIES = {
    "session_id": KEYWORD,
    "ts": {"type": "date", "format": "epoch_second"},
    "initiator_ip": IP,
    "responder_ip": IP,
    "initiator_port": INTEGER,
    "responder_port": INTEGER,
    "duration": FLOAT,
    "ike_version": INTEGER,
    "ike_exchange_type": INTEGER,
    "ike_initiator_spi": KEYWORD,
    "sa_proposal_count": INTEGER,
    "ke_dh_group": INTEGER,
    "ike_nat_traversal": BOOLEAN,
    "ike_packet_count": INTEGER,
    "ike_handshake_duration": FLOAT,
    "mode": KEYWORD,
    "cipher_suite": KEYWORD,
    "auth_algo": KEYWORD,
    "dh_group": KEYWORD,
    "pfs_enabled": BOOLEAN,
    "key_lifetime_sec": INTEGER,
    "esp_spi": KEYWORD,
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
    "traffic_class": KEYWORD,
    "traffic_confidence": FLOAT,
    "anomaly_score": FLOAT,
    "security_score": FLOAT,
    "severity": KEYWORD,
    "risk_flags": KEYWORD,
    "ai_confidence": FLOAT,
    "evidence": {"type": "text"},
    "report_id": KEYWORD,
    "label_config": KEYWORD,
    "label_traffic": KEYWORD,
}


def main():
    host = os.environ.get("ES_HOST")
    index = os.environ.get("ES_INDEX")
    if not host or not index:
        print("FAIL: ES_HOST and ES_INDEX must be set")
        return 1

    client = Elasticsearch(host)
    if client.indices.exists(index=index):
        print(f"OK: index {index} already exists")
        return 0

    client.indices.create(
        index=index,
        settings={"number_of_shards": 1, "number_of_replicas": 0},
        mappings={"dynamic": "true", "properties": PROPERTIES},
    )
    print(f"OK: index {index} created")
    return 0


if __name__ == "__main__":
    sys.exit(main())
