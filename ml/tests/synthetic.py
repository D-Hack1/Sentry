"""Synthetic, well-separated sessions for training-pipeline tests (never used for real models)."""

from __future__ import annotations

import itertools
import json
from pathlib import Path

import numpy as np
import pandas as pd

from features.schema import CipherSuite, DHGroup, TrafficClass

# mean packet size, packet count, iat mean, pkt-size entropy per class
_PROFILES = {
    "web": (900.0, 1200, 0.004, 1.2),
    "voip": (240.0, 360, 0.022, 0.35),
    "video_stream": (1050.0, 300, 0.027, 2.0),
    "file_transfer": (1360.0, 15000, 0.0005, 0.45),
    "icmp": (120.0, 80, 0.10, 0.0),
}
_DH_NUM = {"group2": 2, "group5": 5, "group14": 14, "group19": 19, "group20": 20}


def make_dataset(features_dir: Path, labels_dir: Path, per_class: int = 12, seed: int = 0) -> list[str]:
    rng = np.random.default_rng(seed)
    features_dir.mkdir(parents=True, exist_ok=True)
    labels_dir.mkdir(parents=True, exist_ok=True)
    configs = list(itertools.product(["tunnel", "transport"], CipherSuite.ALL, DHGroup.ALL, [True, False]))
    ids = []
    n = 0
    for traffic in TrafficClass.ALL:
        size, count, iat, entropy = _PROFILES[traffic]
        for i in range(per_class):
            mode, cipher, dh, pfs = configs[n % len(configs)]
            n += 1
            sid = f"{mode}_{cipher.replace('_', '')}_{dh}_{'pfs' if pfs else 'nopfs'}_{traffic}_{i:03d}"
            jitter = rng.normal(1.0, 0.05)
            row = {
                "session_id": sid, "ts": 1735725600.0 + n, "initiator_ip": "10.10.0.2",
                "responder_ip": "10.10.0.3", "initiator_port": 500, "responder_port": 500,
                "duration": 8.0, "ike_version": 2, "ike_exchange_type": 34,
                "ike_initiator_spi": "0x1", "sa_proposal_count": 1, "ke_dh_group": _DH_NUM[dh],
                "ike_nat_traversal": False, "ike_packet_count": 8, "ike_handshake_duration": 0.3,
                "mode": None, "cipher_suite": cipher, "auth_algo": "hmac_sha256", "dh_group": dh,
                "pfs_enabled": None, "key_lifetime_sec": None, "esp_spi": "0xdeadbeef",
                "esp_packet_count": int(count * jitter), "esp_bytes_total": int(count * size * jitter),
                "esp_pkt_size_mean": size * jitter, "esp_pkt_size_std": size * 0.2,
                "esp_pkt_size_min": 68.0, "esp_pkt_size_max": 1500.0,
                "esp_iat_mean": iat * jitter, "esp_iat_std": iat * 0.5, "esp_iat_min": 0.0001,
                "esp_iat_max": iat * 10, "esp_burst_count": 20, "esp_burst_size_mean": 5.0,
                "esp_bytes_per_sec": count * size / 8.0, "esp_pkts_per_sec": count / 8.0,
                "asymmetry_ratio": 1.0, "esp_pkt_size_entropy": entropy,
                "esp_iat_entropy": 1.0, "esp_active_fraction": 0.9,
            }
            pd.DataFrame([row]).to_parquet(features_dir / f"{sid}.parquet", index=False)
            label = {"session_id": sid, "mode": mode, "cipher_suite": cipher, "dh_group": dh,
                     "pfs_enabled": pfs, "traffic_class": traffic, "ike_version": 2,
                     "key_lifetime_sec": 3600}
            (labels_dir / f"{sid}.json").write_text(json.dumps(label), encoding="utf-8")
            ids.append(sid)
    return ids
