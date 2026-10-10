"""
data/verify.py — check that every PCAP has a matching label file and vice versa.

    python data/verify.py [--pcap-dir capture/pcaps] [--labels-dir data/labels]

Checks:
  * every <session_id>.pcap has data/labels/<session_id>.json
  * every label file has a PCAP
  * each label's session_id equals its filename / PCAP stem
  * each label has valid enum values (mode, cipher, DH group, PFS, traffic class)
  * the label agrees with the configuration encoded in the PCAP filename

Exits 1 and lists every problem if anything is wrong ("fail loudly").
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from data.labels import parse_session_id, validate_label  # noqa: E402


def verify(pcap_dir: Path, labels_dir: Path) -> list[str]:
    problems: list[str] = []
    pcaps = {p.stem: p for p in sorted(pcap_dir.rglob("*.pcap"))}
    labels = {p.stem: p for p in sorted(labels_dir.glob("*.json"))} if labels_dir.is_dir() else {}

    if not pcaps:
        problems.append(f"no PCAPs found under {pcap_dir}")
    for stem in sorted(set(pcaps) - set(labels)):
        problems.append(f"PCAP without label: {pcaps[stem].name}")
    for stem in sorted(set(labels) - set(pcaps)):
        problems.append(f"label without PCAP: {labels[stem].name}")

    for stem, path in sorted(labels.items()):
        try:
            label = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            problems.append(f"{path.name}: invalid JSON ({exc})")
            continue
        if not isinstance(label, dict):
            problems.append(f"{path.name}: expected a JSON object")
            continue
        if label.get("session_id") != stem:
            problems.append(f"{path.name}: session_id '{label.get('session_id')}' != filename '{stem}'")
        problems.extend(f"{path.name}: {p}" for p in validate_label(label))
        expected = parse_session_id(stem)
        if expected:
            for key in ("mode", "cipher_suite", "dh_group", "pfs_enabled", "traffic_class"):
                if key in label and label[key] != expected[key]:
                    problems.append(
                        f"{path.name}: {key}={label[key]!r} contradicts filename ({expected[key]!r})"
                    )
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Verify PCAP <-> label pairing")
    parser.add_argument("--pcap-dir", type=Path, default=ROOT / os.getenv("PCAP_DIR", "capture/pcaps"))
    parser.add_argument("--labels-dir", type=Path, default=ROOT / "data" / "labels")
    args = parser.parse_args(argv)

    problems = verify(args.pcap_dir, args.labels_dir)
    if problems:
        print(f"FAIL: {len(problems)} problem(s)")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    count = len(list(args.pcap_dir.rglob("*.pcap")))
    print(f"OK: {count} PCAPs, every one paired with a valid label")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
