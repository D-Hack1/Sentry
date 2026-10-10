"""
data/make_labels.py — write one ground-truth label JSON per capture-matrix PCAP.

    python data/make_labels.py --from-pcaps [--pcap-dir capture/pcaps] [--labels-dir data/labels]

Label format (data/labels/<session_id>.json):
    {
      "session_id": "tunnel_aes256gcm_group19_pfs_web_001",
      "capture_time": "2025-01-01T10:00:00Z",
      "duration_sec": 60.0,
      "ike_version": 2,
      "mode": "tunnel",
      "cipher_suite": "aes256_gcm",
      "dh_group": "group19",
      "pfs_enabled": true,
      "key_lifetime_sec": 3600,
      "traffic_class": "web",
      "initiator_ip": "10.10.0.2",
      "responder_ip": "10.10.0.3",
      "ground_truth_security_score": 100.0,
      "ground_truth_severity": "info"
    }

ike_version and key_lifetime_sec come from the lab template
(capture/templates/ipsec.conf.j2: keyexchange=ikev2, lifetime=1h).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from data.labels import parse_session_id  # noqa: E402
from ml.scorer import score_session  # noqa: E402

LAB_IKE_VERSION = 2
LAB_CHILD_SA_LIFETIME_SEC = 3600


def _capture_window(pcap_path: Path) -> tuple[str | None, float | None]:
    """First-packet time (ISO 8601) and capture duration, read from the pcap headers."""
    from scapy.utils import RawPcapReader

    first = last = None
    try:
        with RawPcapReader(str(pcap_path)) as reader:
            for _, meta in reader:
                ts = meta.sec + meta.usec / 1e6 if hasattr(meta, "usec") else float(meta.sec)
                first = ts if first is None else first
                last = ts
    except Exception:
        return None, None
    if first is None:
        return None, None
    iso = datetime.fromtimestamp(first, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return iso, round(last - first, 3)


def build_label(pcap_path: Path) -> dict | None:
    session_id = pcap_path.stem
    parsed = parse_session_id(session_id)
    if parsed is None:
        return None
    capture_time, duration = _capture_window(pcap_path)
    label = {
        "session_id": session_id,
        "capture_time": capture_time,
        "duration_sec": duration,
        "ike_version": LAB_IKE_VERSION,
        "mode": parsed["mode"],
        "cipher_suite": parsed["cipher_suite"],
        "dh_group": parsed["dh_group"],
        "pfs_enabled": parsed["pfs_enabled"],
        "key_lifetime_sec": LAB_CHILD_SA_LIFETIME_SEC,
        "traffic_class": parsed["traffic_class"],
        "initiator_ip": os.getenv("INITIATOR_IP", "10.10.0.2"),
        "responder_ip": os.getenv("RESPONDER_IP", "10.10.0.3"),
    }
    score = score_session(label)
    label["ground_truth_security_score"] = score["security_score"]
    label["ground_truth_severity"] = score["severity"]
    return label


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Generate label JSON files from capture PCAP names")
    parser.add_argument("--from-pcaps", action="store_true", required=True,
                        help="Derive labels from the capture-matrix PCAP filenames")
    parser.add_argument("--pcap-dir", type=Path,
                        default=ROOT / os.getenv("PCAP_DIR", "capture/pcaps"))
    parser.add_argument("--labels-dir", type=Path, default=ROOT / "data" / "labels")
    parser.add_argument("--overwrite", action="store_true", help="Rewrite existing label files")
    args = parser.parse_args(argv)

    pcaps = sorted(args.pcap_dir.rglob("*.pcap"))
    if not pcaps:
        print(f"FAIL: no .pcap files under {args.pcap_dir}")
        return 1
    args.labels_dir.mkdir(parents=True, exist_ok=True)
    written = skipped = 0
    bad = []
    for pcap in pcaps:
        target = args.labels_dir / f"{pcap.stem}.json"
        if target.exists() and not args.overwrite:
            skipped += 1
            continue
        label = build_label(pcap)
        if label is None:
            bad.append(pcap.name)
            continue
        target.write_text(json.dumps(label, indent=2) + "\n", encoding="utf-8")
        written += 1
    print(f"labels written={written} skipped_existing={skipped} unparseable={len(bad)}")
    for name in bad:
        print(f"  cannot derive label from filename: {name}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
