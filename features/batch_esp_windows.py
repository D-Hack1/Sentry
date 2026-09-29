from __future__ import annotations

import logging
from pathlib import Path

from features.esp_windows import process_pcap_windows


INPUT_DIR = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "capture"
    / "pcaps"
)

OUTPUT_DIR = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "features"
    / "windows"
)

# A capture with fewer than this many ESP packets is not useful
# for behavioral window extraction.
MIN_ESP_PACKETS = 5


def main() -> None:

    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s: %(message)s",
    )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    pcaps = sorted(
        INPUT_DIR.glob("*.pcap")
    )

    print(
        f"[+] Found {len(pcaps)} PCAPs"
    )

    successful = []
    failed = []

    total_windows = 0

    for index, pcap in enumerate(
        pcaps,
        start=1,
    ):

        print(
            f"\n[{index}/{len(pcaps)}] "
            f"{pcap.name}"
        )

        try:

            rows = process_pcap_windows(
                pcap_path=pcap,
                output_dir=OUTPUT_DIR,
            )

            if not rows:
                print(
                    "    [SKIP] "
                    "No valid ESP windows"
                )

                failed.append(
                    (
                        pcap.name,
                        "No valid ESP windows",
                    )
                )

                continue

            # Count packets across all windows.
            total_packets = sum(
                row["packet_count"]
                for row in rows
            )

            if total_packets < MIN_ESP_PACKETS:

                print(
                    f"    [SKIP] "
                    f"Only {total_packets} ESP packets"
                )

                failed.append(
                    (
                        pcap.name,
                        f"Only {total_packets} ESP packets",
                    )
                )

                # Remove the generated file because this capture
                # should not become training data.
                output_file = (
                    OUTPUT_DIR
                    / f"{rows[0]['session_id']}.parquet"
                )

                if output_file.exists():
                    output_file.unlink()

                continue

            successful.append(
                pcap.name
            )

            total_windows += len(
                rows
            )

            print(
                f"    [OK] "
                f"{total_packets} ESP packets, "
                f"{len(rows)} windows"
            )

        except Exception as exc:

            print(
                f"    [FAILED] "
                f"{type(exc).__name__}: {exc}"
            )

            failed.append(
                (
                    pcap.name,
                    f"{type(exc).__name__}: {exc}",
                )
            )

    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print("=" * 70)
    print("BATCH EXTRACTION SUMMARY")
    print("=" * 70)

    print(
        f"Total PCAPs       : {len(pcaps)}"
    )

    print(
        f"Successful         : {len(successful)}"
    )

    print(
        f"Failed / skipped   : {len(failed)}"
    )

    print(
        f"Total windows      : {total_windows}"
    )

    print(
        f"Output directory   : {OUTPUT_DIR}"
    )

    if failed:

        print()
        print("FAILED / SKIPPED:")
        print("-" * 70)

        for filename, reason in failed:

            print(
                f"{filename}"
            )

            print(
                f"    {reason}"
            )

    print()
    print(
        "[+] Batch extraction complete."
    )


if __name__ == "__main__":
    main()