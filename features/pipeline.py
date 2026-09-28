from __future__ import annotations

import logging
from dataclasses import MISSING, fields
from math import log2
from pathlib import Path
from statistics import fmean, pstdev
from typing import Any, Mapping

from features.schema import IPsecFeatureRow


LOGGER = logging.getLogger(__name__)
ESP_FIELD_NAMES = tuple(IPsecFeatureRow.ESP_FEATURE_NAMES)
BURST_IAT_MAX = 0.01
BURST_GAP_MIN = 0.1
PARSER_FIELD_NAMES = tuple(
    field.name
    for field in fields(IPsecFeatureRow)
    if field.name not in {*ESP_FIELD_NAMES, "session_id", "ts", "duration"}
    and field.default is MISSING
    and field.default_factory is MISSING
)
DEFAULT_FEATURES_DIR = Path(__file__).resolve().parents[1] / "data" / "features"


def process_pcap(
    pcap_path: str | Path,
    ike_fields: Mapping[str, Any] | None,
    output_dir: str | Path | None = None,
) -> dict[str, Any] | None:
    if not ike_fields or ike_fields.get("ike_parse_failed"):
        LOGGER.warning("ike_parse_failed: no IKE fields for %s", pcap_path)
        return None

    missing_fields = [
        field_name
        for field_name in PARSER_FIELD_NAMES
        if field_name not in ike_fields or ike_fields[field_name] is None
    ]
    if missing_fields:
        LOGGER.warning(
            "ike_parse_failed: missing %s for %s",
            ", ".join(missing_fields),
            pcap_path,
        )
        return None

    packets = _read_packets(pcap_path)
    timestamps = [float(packet.time) for packet in packets]
    session_id = str(ike_fields.get("session_id") or Path(pcap_path).stem)
    ts = min(timestamps) if timestamps else ike_fields.get("ts")
    duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0

    if ts is None:
        LOGGER.warning("ike_parse_failed: no capture timestamp for %s", pcap_path)
        return None

    esp_packets = _matching_esp_packets(
        packets,
        ike_fields["esp_spi"],
        str(ike_fields["initiator_ip"]),
        str(ike_fields["responder_ip"]),
    )
    esp_features = _esp_features(
        esp_packets,
        str(ike_fields["initiator_ip"]),
        duration,
    )
    row_data = {
        field_name: ike_fields[field_name]
        for field_name in PARSER_FIELD_NAMES
    }
    row_data.update(
        session_id=session_id,
        ts=float(ts),
        duration=float(duration),
        **esp_features,
    )
    row = IPsecFeatureRow(**row_data).to_dict()
    _write_parquet(row, output_dir or DEFAULT_FEATURES_DIR)
    return row


def _read_packets(pcap_path: str | Path) -> list[Any]:
    from scapy.all import rdpcap

    return list(rdpcap(str(pcap_path)))


def _matching_esp_packets(
    packets: list[Any],
    esp_spi: str,
    initiator_ip: str,
    responder_ip: str,
) -> list[tuple[Any, Any]]:
    from scapy.layers.ipsec import ESP
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6

    expected_spi = _spi_as_int(esp_spi)
    endpoint_packets = []
    for packet in packets:
        if not packet.haslayer(ESP):
            continue
        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        if ip_layer is None:
            continue
        endpoints = str(ip_layer.src), str(ip_layer.dst)
        if endpoints not in {
            (initiator_ip, responder_ip),
            (responder_ip, initiator_ip),
        }:
            continue
        endpoint_packets.append((packet, packet[ESP], endpoints))

    primary_packets = [
        item for item in endpoint_packets if int(item[1].spi) == expected_spi
    ]
    if not primary_packets:
        return []

    reverse_endpoints = (primary_packets[0][2][1], primary_packets[0][2][0])
    primary_timestamps = [float(packet.time) for packet, _, _ in primary_packets]
    primary_start = min(primary_timestamps)
    primary_end = max(primary_timestamps)
    reverse_packets: dict[int, list[tuple[Any, Any, tuple[str, str]]]] = {}
    for item in endpoint_packets:
        if item[2] == reverse_endpoints:
            reverse_packets.setdefault(int(item[1].spi), []).append(item)

    scores: dict[int, tuple[float, int]] = {}
    for spi, packets_for_spi in reverse_packets.items():
        timestamps = [float(packet.time) for packet, _, _ in packets_for_spi]
        overlap_start = max(primary_start, min(timestamps))
        overlap_end = min(primary_end, max(timestamps))
        if overlap_start > overlap_end:
            continue
        scores[spi] = (
            overlap_end - overlap_start,
            sum(primary_start <= timestamp <= primary_end for timestamp in timestamps),
        )

    reverse_spi = None
    if scores:
        best_score = max(scores.values())
        best_spis = [spi for spi, score in scores.items() if score == best_score]
        if len(best_spis) == 1:
            reverse_spi = best_spis[0]
    selected_spis = {expected_spi}
    if reverse_spi is not None:
        selected_spis.add(reverse_spi)
    return [
        (packet, packet[ESP])
        for packet, esp, _ in endpoint_packets
        if int(esp.spi) in selected_spis
    ]


def _spi_as_int(esp_spi: str) -> int:
    try:
        return int(esp_spi, 0)
    except ValueError:
        return int(esp_spi, 16)


def _esp_features(
    esp_packets: list[tuple[Any, Any]],
    initiator_ip: str,
    duration: float,
) -> dict[str, int | float]:
    if len(esp_packets) < 5:
        return _zero_esp_features()

    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6

    ordered_packets = sorted(esp_packets, key=lambda item: float(item[0].time))
    timestamps = [float(packet.time) for packet, _ in ordered_packets]
    sizes = [len(bytes(esp)) for _, esp in ordered_packets]
    inter_arrival_times = [
        later - earlier for earlier, later in zip(timestamps, timestamps[1:])
    ]
    outbound_bytes = 0
    inbound_bytes = 0
    for packet, esp in ordered_packets:
        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        if ip_layer is None:
            continue
        if str(ip_layer.src) == initiator_ip:
            outbound_bytes += len(bytes(esp))
        else:
            inbound_bytes += len(bytes(esp))

    total_bytes = sum(sizes)
    burst_sizes = _burst_sizes(inter_arrival_times)
    return {
        "esp_packet_count": len(ordered_packets),
        "esp_bytes_total": total_bytes,
        "esp_pkt_size_mean": fmean(sizes),
        "esp_pkt_size_std": pstdev(sizes),
        "esp_pkt_size_min": float(min(sizes)),
        "esp_pkt_size_max": float(max(sizes)),
        "esp_iat_mean": fmean(inter_arrival_times),
        "esp_iat_std": pstdev(inter_arrival_times),
        "esp_iat_min": min(inter_arrival_times),
        "esp_iat_max": max(inter_arrival_times),
        "esp_burst_count": len(burst_sizes),
        "esp_burst_size_mean": fmean(burst_sizes) if burst_sizes else 0.0,
        "esp_bytes_per_sec": total_bytes / duration if duration > 0 else 0.0,
        "esp_pkts_per_sec": len(ordered_packets) / duration if duration > 0 else 0.0,
        "asymmetry_ratio": outbound_bytes / (inbound_bytes + 1),
        "esp_pkt_size_entropy": _shannon_entropy(sizes, 64),
        "esp_iat_entropy": _shannon_entropy(inter_arrival_times, 0.005),
        "esp_active_fraction": (
            sum(interval for interval in inter_arrival_times if interval < 0.5) / duration
            if duration > 0
            else 0.0
        ),
    }


def _burst_sizes(inter_arrival_times: list[float]) -> list[int]:
    burst_sizes: list[int] = []
    current_size = 1
    for interval in inter_arrival_times:
        if interval < BURST_IAT_MAX:
            current_size += 1
            continue
        if interval > BURST_GAP_MIN:
            if current_size > 1:
                burst_sizes.append(current_size)
            current_size = 1
    if current_size > 1:
        burst_sizes.append(current_size)
    return burst_sizes


def _shannon_entropy(values: list[float | int], bin_size: float) -> float:
    counts: dict[int, int] = {}
    for value in values:
        bucket = int(float(value) // bin_size)
        counts[bucket] = counts.get(bucket, 0) + 1
    total = len(values)
    return -sum(
        (count / total) * log2(count / total)
        for count in counts.values()
    )


def _zero_esp_features() -> dict[str, int | float]:
    return {
        "esp_packet_count": 0,
        "esp_bytes_total": 0,
        "esp_pkt_size_mean": 0.0,
        "esp_pkt_size_std": 0.0,
        "esp_pkt_size_min": 0.0,
        "esp_pkt_size_max": 0.0,
        "esp_iat_mean": 0.0,
        "esp_iat_std": 0.0,
        "esp_iat_min": 0.0,
        "esp_iat_max": 0.0,
        "esp_burst_count": 0,
        "esp_burst_size_mean": 0.0,
        "esp_bytes_per_sec": 0.0,
        "esp_pkts_per_sec": 0.0,
        "asymmetry_ratio": 0.0,
        "esp_pkt_size_entropy": 0.0,
        "esp_iat_entropy": 0.0,
        "esp_active_fraction": 0.0,
    }


def _write_parquet(row: Mapping[str, Any], output_dir: str | Path) -> Path:
    import pandas as pd

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    output_path = destination / f"{row['session_id']}.parquet"
    pd.DataFrame([row]).to_parquet(output_path, index=False)
    return output_path
