"""
data/labels.py — shared helpers for ground-truth label files.

Capture-matrix PCAPs are named by the configuration the lab applied:
    <mode>_<cipher>_<dh>_<pfs|nopfs>_<traffic>_<seq>.pcap
    e.g. tunnel_aes256gcm_group19_pfs_video_stream_001.pcap

That name is the *ground truth* for training labels only. The feature
extractor (features/ike_parser.py) never reads it.
"""

from __future__ import annotations

import re
from typing import Optional

from features.schema import CipherSuite, DHGroup, TrafficClass, TunnelMode

# capture/gen_config.py spells ciphers without the underscore
CIPHER_FROM_FILENAME = {c.replace("_", ""): c for c in CipherSuite.ALL}

SESSION_RE = re.compile(
    r"^(?P<mode>tunnel|transport)_(?P<cipher>[a-z0-9]+)_(?P<dh>group\d+)_"
    r"(?P<pfs>pfs|nopfs)_(?P<traffic>[a-z_]+)_(?P<seq>\d+)$"
)

REQUIRED_LABEL_KEYS = (
    "session_id", "mode", "cipher_suite", "dh_group", "pfs_enabled", "traffic_class",
)


def parse_session_id(session_id: str) -> Optional[dict]:
    """Decode a capture-matrix session id; None if it does not follow the convention."""
    match = SESSION_RE.match(session_id)
    if not match:
        return None
    cipher = CIPHER_FROM_FILENAME.get(match["cipher"])
    if cipher is None or match["dh"] not in DHGroup.ALL or match["traffic"] not in TrafficClass.ALL:
        return None
    return {
        "mode": match["mode"],
        "cipher_suite": cipher,
        "dh_group": match["dh"],
        "pfs_enabled": match["pfs"] == "pfs",
        "traffic_class": match["traffic"],
        "seq": match["seq"],
    }


def validate_label(label: dict) -> list[str]:
    """Return a list of problems with a label dict (empty list = valid)."""
    problems = [f"missing key '{k}'" for k in REQUIRED_LABEL_KEYS if k not in label]
    if problems:
        return problems
    if label["mode"] not in TunnelMode.ALL:
        problems.append(f"invalid mode '{label['mode']}'")
    if label["cipher_suite"] not in CipherSuite.ALL:
        problems.append(f"invalid cipher_suite '{label['cipher_suite']}'")
    if label["dh_group"] not in DHGroup.ALL:
        problems.append(f"invalid dh_group '{label['dh_group']}'")
    if not isinstance(label["pfs_enabled"], bool):
        problems.append("pfs_enabled must be a boolean")
    if label["traffic_class"] not in TrafficClass.ALL:
        problems.append(f"invalid traffic_class '{label['traffic_class']}'")
    return problems
