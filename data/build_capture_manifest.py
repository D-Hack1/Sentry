"""
Build a metadata manifest for the generated IPsec PCAP dataset.

IMPORTANT:
This manifest is dataset metadata only.

The ML feature extractor does NOT use these values to calculate
behavioral features.

The values are extracted from the established PCAP naming convention
so that we can perform dataset analysis and evaluation.
"""

from pathlib import Path
import csv
import re


PCAP_DIR = Path("data/capture/pcaps")
OUTPUT_FILE = Path("data/capture_manifest.csv")


# ---------------------------------------------------------------------
# Filename format
#
# <mode>_<cipher>_<dh>_<pfs>_<traffic_class>_<capture_id>.pcap
#
# Example:
#
# transport_aes128cbc_group14_nopfs_web_001.pcap
# ---------------------------------------------------------------------

FILENAME_PATTERN = re.compile(
    r"^(?P<mode>transport|tunnel)_"
    r"(?P<cipher>aes128cbc|aes256cbc|aes128gcm|aes256gcm)_"
    r"(?P<dh>group2|group5|group14|group19|group20)_"
    r"(?P<pfs>pfs|nopfs)_"
    r"(?P<traffic_class>web|voip|video_stream|file_transfer|icmp)_"
    r"(?P<capture_id>\d+)"
    r"\.pcap$",
    re.IGNORECASE,
)


CIPHER_MAP = {
    "aes128cbc": "aes128_cbc",
    "aes256cbc": "aes256_cbc",
    "aes128gcm": "aes128_gcm",
    "aes256gcm": "aes256_gcm",
}


def parse_filename(filename: str):
    """
    Parse metadata from a generated PCAP filename.
    """

    match = FILENAME_PATTERN.match(filename)

    if not match:
        raise ValueError(
            f"Filename does not match expected format: {filename}"
        )

    values = match.groupdict()

    cipher_raw = values["cipher"].lower()

    return {
        "session_id": Path(filename).stem,
        "pcap": filename,
        "mode": values["mode"].lower(),
        "cipher_suite": CIPHER_MAP[cipher_raw],
        "dh_group": values["dh"].lower(),
        "pfs": values["pfs"].lower(),
        "traffic_class": values["traffic_class"].lower(),
        "capture_id": values["capture_id"],
    }


def main():

    print("=" * 70)
    print("BUILDING PCAP CAPTURE MANIFEST")
    print("=" * 70)

    files = sorted(
        PCAP_DIR.glob("*.pcap")
    )

    print(f"[+] Found {len(files)} PCAPs")

    if not files:
        raise RuntimeError(
            f"No PCAPs found in {PCAP_DIR}"
        )

    records = []
    failures = []

    for pcap in files:

        try:
            record = parse_filename(
                pcap.name
            )

            records.append(record)

        except ValueError as exc:
            failures.append(
                (pcap.name, str(exc))
            )

    if failures:
        print()
        print("[ERROR] Could not parse:")
        for filename, reason in failures:
            print(
                f"  {filename}: {reason}"
            )

        raise RuntimeError(
            "Some PCAP filenames could not be parsed."
        )

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "session_id",
        "pcap",
        "mode",
        "cipher_suite",
        "dh_group",
        "pfs",
        "traffic_class",
        "capture_id",
    ]

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(records)

    print(
        f"[OK] Wrote {len(records)} records"
    )

    print(
        f"[OK] Output: {OUTPUT_FILE}"
    )

    # ---------------------------------------------------------------
    # Dataset summary
    # ---------------------------------------------------------------

    print()
    print("=" * 70)
    print("TRAFFIC CLASS DISTRIBUTION")
    print("=" * 70)

    traffic_counts = {}

    for record in records:
        key = record["traffic_class"]
        traffic_counts[key] = (
            traffic_counts.get(key, 0) + 1
        )

    for key in sorted(traffic_counts):
        print(
            f"{key:<20} {traffic_counts[key]}"
        )

    print()
    print("=" * 70)
    print("VPN MODE DISTRIBUTION")
    print("=" * 70)

    mode_counts = {}

    for record in records:
        key = record["mode"]
        mode_counts[key] = (
            mode_counts.get(key, 0) + 1
        )

    for key in sorted(mode_counts):
        print(
            f"{key:<20} {mode_counts[key]}"
        )

    print()
    print("[+] Manifest generation complete.")


if __name__ == "__main__":
    main()