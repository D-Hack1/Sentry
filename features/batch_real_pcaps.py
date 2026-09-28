from __future__ import annotations

import argparse
from pathlib import Path

from features.ike_parser import parse_ike_pcap
from features.pipeline import process_pcap


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT_DIR = ROOT / "data" / "raw" / "pcaps"
DEFAULT_OUTPUT_DIR = ROOT / "data" / "validation" / "real_pcaps"


def process_all_pcaps(
    input_dir: Path = DEFAULT_INPUT_DIR,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> tuple[int, int, list[tuple[Path, Exception]], int]:
    pcap_paths = sorted(input_dir.rglob("*.pcap"))
    successes = 0
    failures: list[tuple[Path, Exception]] = []
    for pcap_path in pcap_paths:
        try:
            ike_fields = parse_ike_pcap(str(pcap_path))
            if process_pcap(pcap_path, ike_fields, output_dir) is None:
                raise RuntimeError("pipeline returned no feature row")
            successes += 1
        except Exception as error:
            failures.append((pcap_path, error))
            print(f"FAILED {pcap_path}: {error}")
    parquet_count = len(list(output_dir.glob("*.parquet")))
    print(f"PCAP count: {len(pcap_paths)}")
    print(f"Successes: {successes}")
    print(f"Failures: {len(failures)}")
    print(f"Parquet count: {parquet_count}")
    return len(pcap_paths), successes, failures, parquet_count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()
    _, _, failures, _ = process_all_pcaps(args.input_dir, args.output_dir)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
