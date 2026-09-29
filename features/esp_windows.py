from __future__ import annotations

import argparse
import logging
from math import log2
from pathlib import Path
from statistics import fmean, pstdev
from typing import Any

import numpy as np


LOGGER = logging.getLogger(__name__)


# ============================================================
# CONSTANTS
# ============================================================

WINDOW_SIZE_SEC = 1.0

# Packets separated by <= 10 ms are considered part
# of the same burst.
BURST_IAT_MAX = 0.01

# A gap > 100 ms terminates a burst.
BURST_GAP_MIN = 0.1

DEFAULT_OUTPUT_DIR = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "features"
    / "windows"
)


# ============================================================
# PUBLIC API
# ============================================================

def process_pcap_windows(
    pcap_path: str | Path,
    output_dir: str | Path | None = None,
) -> list[dict[str, Any]]:
    """
    Parse IKE information from a PCAP and extract
    1-second behavioral ESP windows.

    The existing IKE parser is used to obtain:

        - session_id
        - initiator_ip
        - responder_ip
        - esp_spi

    The resulting behavioral features do NOT use VPN
    configuration fields such as:

        - cipher_suite
        - dh_group
        - mode
        - pfs_enabled

    This keeps the behavioral feature extraction independent
    from the VPN configuration.
    """

    from features.ike_parser import parse_ike_pcap

    pcap_path = Path(pcap_path)

    if not pcap_path.exists():
        raise FileNotFoundError(
            f"PCAP not found: {pcap_path}"
        )

    # --------------------------------------------------------
    # Step 1:
    # Parse IKE information
    # --------------------------------------------------------

    LOGGER.info(
        "Parsing IKE information from %s",
        pcap_path,
    )

    ike_fields = parse_ike_pcap(
        str(pcap_path)
    )

    # --------------------------------------------------------
    # Step 2:
    # Validate fields required for ESP matching
    # --------------------------------------------------------

    required_fields = (
        "initiator_ip",
        "responder_ip",
        "esp_spi",
    )

    missing = [
        field
        for field in required_fields
        if field not in ike_fields
        or ike_fields[field] is None
        or (
            field == "esp_spi"
            and ike_fields[field] == "0x0"
        )
    ]

    if missing:
        LOGGER.warning(
            "Cannot extract ESP windows from %s. "
            "Missing IKE fields: %s",
            pcap_path,
            ", ".join(missing),
        )

        return []

    # --------------------------------------------------------
    # Step 3:
    # Read raw PCAP
    # --------------------------------------------------------

    packets = _read_packets(
        pcap_path
    )

    # --------------------------------------------------------
    # Step 4:
    # Find ESP packets belonging to this session
    # --------------------------------------------------------

    esp_packets = _matching_esp_packets(
        packets=packets,
        esp_spi=ike_fields["esp_spi"],
        initiator_ip=str(
            ike_fields["initiator_ip"]
        ),
        responder_ip=str(
            ike_fields["responder_ip"]
        ),
    )

    if not esp_packets:
        LOGGER.warning(
            "No matching ESP packets found in %s",
            pcap_path,
        )

        return []

    LOGGER.info(
        "Found %d matching ESP packets",
        len(esp_packets),
    )

    # --------------------------------------------------------
    # Step 5:
    # Split ESP traffic into 1-second windows
    # --------------------------------------------------------

    windows = _extract_windows(
        esp_packets=esp_packets,
        initiator_ip=str(
            ike_fields["initiator_ip"]
        ),
    )

    # --------------------------------------------------------
    # Step 6:
    # Add session identifiers
    # --------------------------------------------------------

    session_id = str(
        ike_fields.get("session_id")
        or pcap_path.stem
    )

    for index, row in enumerate(windows):

        row["session_id"] = session_id

        row["window_index"] = index

    # Keep identifiers at the beginning of the row.
    windows = [
        _order_row(row)
        for row in windows
    ]

    # --------------------------------------------------------
    # Step 7:
    # Write Parquet
    # --------------------------------------------------------

    destination = Path(
        output_dir
        or DEFAULT_OUTPUT_DIR
    )

    destination.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path = (
        destination
        / f"{session_id}.parquet"
    )

    _write_parquet(
        windows,
        output_path,
    )

    LOGGER.info(
        "Extracted %d ESP windows from %s -> %s",
        len(windows),
        pcap_path,
        output_path,
    )

    return windows


# ============================================================
# PCAP READING
# ============================================================

def _read_packets(
    pcap_path: str | Path,
):
    """
    Read packets from the raw PCAP using Scapy.
    """

    from scapy.all import rdpcap

    return list(
        rdpcap(
            str(pcap_path)
        )
    )


# ============================================================
# ESP PACKET MATCHING
# ============================================================

def _matching_esp_packets(
    packets,
    esp_spi: Any,
    initiator_ip: str,
    responder_ip: str,
):
    """
    Select ESP packets belonging to the IPsec session.

    The supplied ESP SPI identifies the primary direction.

    The reverse-direction SPI is inferred by finding the SPI
    whose packets overlap most strongly with the primary ESP
    session.
    """

    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.ipsec import ESP

    expected_spi = _spi_as_int(
        esp_spi
    )

    endpoint_packets = []

    # --------------------------------------------------------
    # Find all ESP packets between the two endpoints
    # --------------------------------------------------------

    for packet in packets:

        if not packet.haslayer(ESP):
            continue

        ip_layer = (
            packet.getlayer(IP)
            or packet.getlayer(IPv6)
        )

        if ip_layer is None:
            continue

        endpoints = (
            str(ip_layer.src),
            str(ip_layer.dst),
        )

        if endpoints not in {
            (
                initiator_ip,
                responder_ip,
            ),
            (
                responder_ip,
                initiator_ip,
            ),
        }:
            continue

        endpoint_packets.append(
            (
                packet,
                packet[ESP],
                endpoints,
            )
        )

    # --------------------------------------------------------
    # Primary direction
    # --------------------------------------------------------

    primary_packets = [
        item
        for item in endpoint_packets
        if int(item[1].spi) == expected_spi
    ]

    if not primary_packets:
        return []

    primary_timestamps = [
        float(packet.time)
        for packet, _, _ in primary_packets
    ]

    primary_start = min(
        primary_timestamps
    )

    primary_end = max(
        primary_timestamps
    )

    reverse_endpoints = (
        primary_packets[0][2][1],
        primary_packets[0][2][0],
    )

    # --------------------------------------------------------
    # Find possible reverse-direction SPIs
    # --------------------------------------------------------

    reverse_packets: dict[int, list] = {}

    for item in endpoint_packets:

        if item[2] != reverse_endpoints:
            continue

        spi = int(
            item[1].spi
        )

        reverse_packets.setdefault(
            spi,
            [],
        ).append(item)

    # --------------------------------------------------------
    # Score reverse SPIs
    # --------------------------------------------------------

    scores = {}

    for spi, packets_for_spi in reverse_packets.items():

        timestamps = [
            float(packet.time)
            for packet, _, _ in packets_for_spi
        ]

        overlap_start = max(
            primary_start,
            min(timestamps),
        )

        overlap_end = min(
            primary_end,
            max(timestamps),
        )

        if overlap_start > overlap_end:
            continue

        overlap_duration = (
            overlap_end
            - overlap_start
        )

        overlapping_packet_count = sum(
            primary_start
            <= timestamp
            <= primary_end
            for timestamp in timestamps
        )

        scores[spi] = (
            overlap_duration,
            overlapping_packet_count,
        )

    # --------------------------------------------------------
    # Select best reverse SPI
    # --------------------------------------------------------

    reverse_spi = None

    if scores:

        best_score = max(
            scores.values()
        )

        best_spis = [
            spi
            for spi, score in scores.items()
            if score == best_score
        ]

        # Only use reverse SPI when the match is unambiguous.
        if len(best_spis) == 1:
            reverse_spi = best_spis[0]

    # --------------------------------------------------------
    # Selected SPIs
    # --------------------------------------------------------

    selected_spis = {
        expected_spi
    }

    if reverse_spi is not None:
        selected_spis.add(
            reverse_spi
        )

    # --------------------------------------------------------
    # Return matching packets
    # --------------------------------------------------------

    return [
        (
            packet,
            packet[ESP],
        )
        for packet, esp, _ in endpoint_packets
        if int(esp.spi) in selected_spis
    ]


def _spi_as_int(
    esp_spi: Any,
) -> int:
    """
    Convert an ESP SPI represented as:

        123456
        0x123456
        "0xc6f91cad"

    into an integer.
    """

    if isinstance(
        esp_spi,
        int,
    ):
        return esp_spi

    value = str(
        esp_spi
    )

    try:
        return int(
            value,
            0,
        )

    except ValueError:
        return int(
            value,
            16,
        )


# ============================================================
# WINDOW EXTRACTION
# ============================================================

def _extract_windows(
    esp_packets,
    initiator_ip: str,
) -> list[dict[str, Any]]:
    """
    Split ESP traffic into 1-second behavioral windows.

    The first ESP packet becomes time zero.

    Example:

        first ESP packet = 100.25s

        window 0:
            [100.25, 101.25)

        window 1:
            [101.25, 102.25)

        window 2:
            [102.25, 103.25)
    """

    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6

    ordered_packets = sorted(
        esp_packets,
        key=lambda item: float(
            item[0].time
        ),
    )

    if not ordered_packets:
        return []

    first_timestamp = float(
        ordered_packets[0][0].time
    )

    last_timestamp = float(
        ordered_packets[-1][0].time
    )

    duration = (
        last_timestamp
        - first_timestamp
    )

    # Include the final partially filled second.
    number_of_windows = (
        int(
            duration
            // WINDOW_SIZE_SEC
        )
        + 1
    )

    grouped_packets: list[list] = [
        []
        for _ in range(
            number_of_windows
        )
    ]

    # --------------------------------------------------------
    # Assign every packet to a window
    # --------------------------------------------------------

    for packet, esp in ordered_packets:

        timestamp = float(
            packet.time
        )

        relative_time = (
            timestamp
            - first_timestamp
        )

        window_index = int(
            relative_time
            // WINDOW_SIZE_SEC
        )

        # Protect against floating-point edge cases.
        window_index = min(
            window_index,
            number_of_windows - 1,
        )

        ip_layer = (
            packet.getlayer(IP)
            or packet.getlayer(IPv6)
        )

        if ip_layer is None:
            continue

        if (
            str(ip_layer.src)
            == initiator_ip
        ):
            direction = "outbound"
        else:
            direction = "inbound"

        grouped_packets[
            window_index
        ].append(
            {
                "timestamp": timestamp,
                "size": len(
                    bytes(esp)
                ),
                "direction": direction,
            }
        )

    # --------------------------------------------------------
    # Calculate features for every window
    # --------------------------------------------------------

    rows = []

    for window_index, window_packets in enumerate(
        grouped_packets
    ):

        window_start = (
            window_index
            * WINDOW_SIZE_SEC
        )

        window_end = (
            window_start
            + WINDOW_SIZE_SEC
        )

        features = _calculate_window_features(
            window_packets
        )

        row = {
            "window_start": window_start,
            "window_end": window_end,
            **features,
        }

        rows.append(row)

    return rows


# ============================================================
# FEATURE CALCULATION
# ============================================================

def _calculate_window_features(
    packets: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Calculate all behavioral features for one 1-second window.
    """

    if not packets:
        return _zero_features()

    packets = sorted(
        packets,
        key=lambda packet: packet[
            "timestamp"
        ],
    )

    # --------------------------------------------------------
    # Basic values
    # --------------------------------------------------------

    timestamps = [
        float(
            packet["timestamp"]
        )
        for packet in packets
    ]

    sizes = [
        float(
            packet["size"]
        )
        for packet in packets
    ]

    packet_count = len(
        packets
    )

    total_bytes = sum(
        sizes
    )

    # --------------------------------------------------------
    # Inter-arrival times
    # --------------------------------------------------------

    iats = [
        later - earlier
        for earlier, later in zip(
            timestamps,
            timestamps[1:],
        )
    ]

    # Protect against tiny negative values due to timestamp
    # precision.
    iats = [
        max(
            0.0,
            value,
        )
        for value in iats
    ]

    # --------------------------------------------------------
    # Direction
    # --------------------------------------------------------

    outbound_packets = [
        packet
        for packet in packets
        if packet["direction"]
        == "outbound"
    ]

    inbound_packets = [
        packet
        for packet in packets
        if packet["direction"]
        == "inbound"
    ]

    outbound_packet_count = len(
        outbound_packets
    )

    inbound_packet_count = len(
        inbound_packets
    )

    outbound_bytes = sum(
        packet["size"]
        for packet in outbound_packets
    )

    inbound_bytes = sum(
        packet["size"]
        for packet in inbound_packets
    )

    # --------------------------------------------------------
    # Burst features
    # --------------------------------------------------------

    burst_sizes = _burst_sizes(
        iats
    )

    burst_packet_count = sum(
        burst_sizes
    )

    # --------------------------------------------------------
    # Activity features
    # --------------------------------------------------------

    active_time = _active_time(
        iats
    )

    active_fraction = min(
        1.0,
        max(
            0.0,
            active_time
            / WINDOW_SIZE_SEC,
        ),
    )

    idle_fraction = (
        1.0
        - active_fraction
    )

    # --------------------------------------------------------
    # Return feature vector
    # --------------------------------------------------------

    return {

        # ====================================================
        # VOLUME
        # ====================================================

        "packet_count": packet_count,

        "bytes_total": total_bytes,

        # ====================================================
        # PACKET SIZE
        # ====================================================

        "pkt_size_mean": _mean(
            sizes
        ),

        "pkt_size_std": _std(
            sizes
        ),

        "pkt_size_min": _minimum(
            sizes
        ),

        "pkt_size_max": _maximum(
            sizes
        ),

        "pkt_size_p25": _percentile(
            sizes,
            25,
        ),

        "pkt_size_p50": _percentile(
            sizes,
            50,
        ),

        "pkt_size_p75": _percentile(
            sizes,
            75,
        ),

        "pkt_size_p90": _percentile(
            sizes,
            90,
        ),

        "pkt_size_p95": _percentile(
            sizes,
            95,
        ),

        # ====================================================
        # IAT
        # ====================================================

        "iat_mean": _mean(
            iats
        ),

        "iat_std": _std(
            iats
        ),

        "iat_min": _minimum(
            iats
        ),

        "iat_max": _maximum(
            iats
        ),

        "iat_p25": _percentile(
            iats,
            25,
        ),

        "iat_p50": _percentile(
            iats,
            50,
        ),

        "iat_p75": _percentile(
            iats,
            75,
        ),

        "iat_p90": _percentile(
            iats,
            90,
        ),

        "iat_p95": _percentile(
            iats,
            95,
        ),

        # ====================================================
        # DIRECTION
        # ====================================================

        "inbound_packets": (
            inbound_packet_count
        ),

        "outbound_packets": (
            outbound_packet_count
        ),

        "inbound_bytes": (
            inbound_bytes
        ),

        "outbound_bytes": (
            outbound_bytes
        ),

        "packet_ratio": (
            outbound_packet_count
            / (
                inbound_packet_count
                + 1.0
            )
        ),

        "byte_ratio": (
            outbound_bytes
            / (
                inbound_bytes
                + 1.0
            )
        ),

        # ====================================================
        # RATE
        # ====================================================

        "packets_per_sec": (
            packet_count
            / WINDOW_SIZE_SEC
        ),

        "bytes_per_sec": (
            total_bytes
            / WINDOW_SIZE_SEC
        ),

        # ====================================================
        # BURST
        # ====================================================

        "burst_count": len(
            burst_sizes
        ),

        "mean_burst_size": (
            fmean(
                burst_sizes
            )
            if burst_sizes
            else 0.0
        ),

        "max_burst_size": (
            max(
                burst_sizes
            )
            if burst_sizes
            else 0
        ),

        "burst_fraction": (
            burst_packet_count
            / packet_count
            if packet_count > 0
            else 0.0
        ),

        # ====================================================
        # DISTRIBUTION
        # ====================================================

        "packet_size_entropy": (
            _shannon_entropy(
                sizes,
                bin_size=64.0,
            )
        ),

        "iat_entropy": (
            _shannon_entropy(
                iats,
                bin_size=0.005,
            )
        ),

        # ====================================================
        # ACTIVITY
        # ====================================================

        "active_time_fraction": (
            active_fraction
        ),

        "idle_time_fraction": (
            idle_fraction
        ),
    }


# ============================================================
# BURST DETECTION
# ============================================================

def _burst_sizes(
    iats: list[float],
) -> list[int]:
    """
    Detect bursts using IAT.

    A burst contains at least 2 packets.

    <= 10 ms:
        continue the burst

    > 100 ms:
        definitely terminate the burst

    10-100 ms:
        terminate the current burst
    """

    if not iats:
        return []

    burst_sizes = []

    current_size = 1

    for interval in iats:

        # --------------------------------------------
        # Very small gap:
        # same burst
        # --------------------------------------------

        if interval <= BURST_IAT_MAX:

            current_size += 1

            continue

        # --------------------------------------------
        # Large gap:
        # terminate burst
        # --------------------------------------------

        if interval > BURST_GAP_MIN:

            if current_size > 1:
                burst_sizes.append(
                    current_size
                )

            current_size = 1

            continue

        # --------------------------------------------
        # Medium gap:
        # terminate current burst
        # --------------------------------------------

        if current_size > 1:

            burst_sizes.append(
                current_size
            )

        current_size = 1

    # Final burst
    if current_size > 1:

        burst_sizes.append(
            current_size
        )

    return burst_sizes


# ============================================================
# ACTIVITY
# ============================================================

def _active_time(
    iats: list[float],
) -> float:
    """
    Estimate active time within a 1-second window.

    Gaps below 500 ms are considered active.
    """

    if not iats:
        return 0.0

    active_time = sum(
        interval
        for interval in iats
        if interval < 0.5
    )

    return min(
        WINDOW_SIZE_SEC,
        active_time,
    )


# ============================================================
# STATISTICAL HELPERS
# ============================================================

def _mean(
    values: list[float],
) -> float:

    if not values:
        return 0.0

    return float(
        fmean(values)
    )


def _std(
    values: list[float],
) -> float:

    if len(values) <= 1:
        return 0.0

    return float(
        pstdev(values)
    )


def _minimum(
    values: list[float],
) -> float:

    if not values:
        return 0.0

    return float(
        min(values)
    )


def _maximum(
    values: list[float],
) -> float:

    if not values:
        return 0.0

    return float(
        max(values)
    )


def _percentile(
    values: list[float],
    percentile: float,
) -> float:

    if not values:
        return 0.0

    return float(
        np.percentile(
            values,
            percentile,
        )
    )


# ============================================================
# ENTROPY
# ============================================================

def _shannon_entropy(
    values: list[float],
    bin_size: float,
) -> float:
    """
    Calculate Shannon entropy after discretizing values
    into fixed-size bins.
    """

    if not values:
        return 0.0

    if bin_size <= 0:
        raise ValueError(
            "bin_size must be greater than zero"
        )

    counts: dict[int, int] = {}

    for value in values:

        bucket = int(
            float(value)
            // bin_size
        )

        counts[bucket] = (
            counts.get(
                bucket,
                0,
            )
            + 1
        )

    total = len(
        values
    )

    entropy = 0.0

    for count in counts.values():

        probability = (
            count
            / total
        )

        entropy -= (
            probability
            * log2(
                probability
            )
        )

    return float(
        entropy
    )


# ============================================================
# EMPTY WINDOW
# ============================================================

def _zero_features() -> dict[str, Any]:
    """
    Return feature values for an empty 1-second window.
    """

    return {

        # ====================================================
        # VOLUME
        # ====================================================

        "packet_count": 0,

        "bytes_total": 0,

        # ====================================================
        # PACKET SIZE
        # ====================================================

        "pkt_size_mean": 0.0,

        "pkt_size_std": 0.0,

        "pkt_size_min": 0.0,

        "pkt_size_max": 0.0,

        "pkt_size_p25": 0.0,

        "pkt_size_p50": 0.0,

        "pkt_size_p75": 0.0,

        "pkt_size_p90": 0.0,

        "pkt_size_p95": 0.0,

        # ====================================================
        # IAT
        # ====================================================

        "iat_mean": 0.0,

        "iat_std": 0.0,

        "iat_min": 0.0,

        "iat_max": 0.0,

        "iat_p25": 0.0,

        "iat_p50": 0.0,

        "iat_p75": 0.0,

        "iat_p90": 0.0,

        "iat_p95": 0.0,

        # ====================================================
        # DIRECTION
        # ====================================================

        "inbound_packets": 0,

        "outbound_packets": 0,

        "inbound_bytes": 0,

        "outbound_bytes": 0,

        "packet_ratio": 0.0,

        "byte_ratio": 0.0,

        # ====================================================
        # RATE
        # ====================================================

        "packets_per_sec": 0.0,

        "bytes_per_sec": 0.0,

        # ====================================================
        # BURST
        # ====================================================

        "burst_count": 0,

        "mean_burst_size": 0.0,

        "max_burst_size": 0,

        "burst_fraction": 0.0,

        # ====================================================
        # DISTRIBUTION
        # ====================================================

        "packet_size_entropy": 0.0,

        "iat_entropy": 0.0,

        # ====================================================
        # ACTIVITY
        # ====================================================

        "active_time_fraction": 0.0,

        "idle_time_fraction": 1.0,
    }


# ============================================================
# ROW ORDERING
# ============================================================

def _order_row(
    row: dict[str, Any],
) -> dict[str, Any]:
    """
    Keep identifiers at the beginning of the Parquet schema.
    """

    ordered = {

        "session_id": row[
            "session_id"
        ],

        "window_index": row[
            "window_index"
        ],

        "window_start": row[
            "window_start"
        ],

        "window_end": row[
            "window_end"
        ],
    }

    for key, value in row.items():

        if key not in ordered:

            ordered[key] = value

    return ordered


# ============================================================
# PARQUET OUTPUT
# ============================================================

def _write_parquet(
    rows: list[dict[str, Any]],
    output_path: str | Path,
) -> Path:
    """
    Write all windows belonging to one session into
    a single Parquet file.
    """

    import pandas as pd

    output_path = Path(
        output_path
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    dataframe = pd.DataFrame(
        rows
    )

    dataframe.to_parquet(
        output_path,
        index=False,
    )

    return output_path


# ============================================================
# CLI
# ============================================================

def main() -> None:
    """
    Command-line interface.

    Usage:

        python -m features.esp_windows <pcap>

    Example:

        python -m features.esp_windows \
            data/capture/pcaps/example.pcap
    """

    parser = argparse.ArgumentParser(
        description=(
            "SIH 2026 - Extract 1-second "
            "behavioral ESP features from "
            "an IPsec PCAP."
        )
    )

    parser.add_argument(
        "pcap",
        help="Path to the input PCAP file.",
    )

    parser.add_argument(
        "--output-dir",
        default=None,
        help=(
            "Directory for generated window "
            "Parquet files. "
            "Default: data/features/windows"
        ),
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )

    args = parser.parse_args()

    # --------------------------------------------------------
    # Logging
    # --------------------------------------------------------

    logging.basicConfig(
        level=(
            logging.DEBUG
            if args.verbose
            else logging.INFO
        ),
        format=(
            "%(levelname)s: "
            "%(message)s"
        ),
    )

    # --------------------------------------------------------
    # Process
    # --------------------------------------------------------

    try:

        rows = process_pcap_windows(
            pcap_path=args.pcap,
            output_dir=args.output_dir,
        )

        if not rows:

            print(
                "[-] No ESP windows were extracted."
            )

            return

        output_dir = Path(
            args.output_dir
            or DEFAULT_OUTPUT_DIR
        )

        output_path = (
            output_dir
            / (
                rows[0]["session_id"]
                + ".parquet"
            )
        )

        print()
        print(
            "[+] ESP window extraction successful"
        )

        print(
            f"[+] Session : "
            f"{rows[0]['session_id']}"
        )

        print(
            f"[+] Windows : "
            f"{len(rows)}"
        )

        print(
            f"[+] Output  : "
            f"{output_path}"
        )

        print()
        print(
            "[+] First window:"
        )

        for key, value in rows[0].items():

            print(
                f"    {key:28s}: "
                f"{value}"
            )

    except Exception as exc:

        print(
            f"[-] Error processing PCAP: "
            f"{exc}"
        )

        raise


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()