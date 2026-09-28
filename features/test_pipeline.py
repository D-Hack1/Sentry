from scapy.all import ESP, IP

from features.pipeline import _burst_sizes, _esp_features, _matching_esp_packets, process_pcap


INITIATOR = "10.10.0.2"
RESPONDER = "10.10.0.3"
PRIMARY_SPI = 0x1001
REVERSE_SPI = 0x2002


def _packet(src, dst, spi, timestamp, data=b"payload"):
    packet = IP(src=src, dst=dst) / ESP(spi=spi, seq=1, data=data)
    packet.time = timestamp
    return packet


def _session_packets(count=5):
    return [
        _packet(
            INITIATOR if index % 2 == 0 else RESPONDER,
            RESPONDER if index % 2 == 0 else INITIATOR,
            PRIMARY_SPI if index % 2 == 0 else REVERSE_SPI,
            index,
        )
        for index in range(count)
    ]


def test_matching_esp_packets_includes_both_directional_spis_only():
    packets = _session_packets()
    packets.extend(
        [
            _packet(INITIATOR, RESPONDER, 0x3003, 6),
            _packet("10.10.0.9", "10.10.0.10", PRIMARY_SPI, 7),
        ]
    )

    matched = _matching_esp_packets(packets, hex(PRIMARY_SPI), INITIATOR, RESPONDER)

    assert len(matched) == 5
    assert {int(esp.spi) for _, esp in matched} == {PRIMARY_SPI, REVERSE_SPI}


def test_matching_esp_packets_prefers_the_unique_overlapping_reverse_spi():
    packets = [
        _packet(INITIATOR, RESPONDER, PRIMARY_SPI, 10),
        _packet(INITIATOR, RESPONDER, PRIMARY_SPI, 20),
        _packet(INITIATOR, RESPONDER, PRIMARY_SPI, 30),
        _packet(RESPONDER, INITIATOR, 0x3003, 1),
        _packet(RESPONDER, INITIATOR, 0x3003, 5),
        _packet(RESPONDER, INITIATOR, REVERSE_SPI, 12),
        _packet(RESPONDER, INITIATOR, REVERSE_SPI, 25),
    ]

    matched = _matching_esp_packets(packets, hex(PRIMARY_SPI), INITIATOR, RESPONDER)

    assert {int(esp.spi) for _, esp in matched} == {PRIMARY_SPI, REVERSE_SPI}


def test_matching_esp_packets_rejects_ambiguous_reverse_spis():
    packets = [
        _packet(INITIATOR, RESPONDER, PRIMARY_SPI, 10),
        _packet(INITIATOR, RESPONDER, PRIMARY_SPI, 30),
        _packet(RESPONDER, INITIATOR, REVERSE_SPI, 12),
        _packet(RESPONDER, INITIATOR, REVERSE_SPI, 28),
        _packet(RESPONDER, INITIATOR, 0x3003, 12),
        _packet(RESPONDER, INITIATOR, 0x3003, 28),
    ]

    matched = _matching_esp_packets(packets, hex(PRIMARY_SPI), INITIATOR, RESPONDER)

    assert {int(esp.spi) for _, esp in matched} == {PRIMARY_SPI}


def test_matching_esp_packets_requires_the_primary_spi_at_session_endpoints():
    packets = [_packet(RESPONDER, INITIATOR, REVERSE_SPI, 1)]

    assert _matching_esp_packets(packets, hex(PRIMARY_SPI), INITIATOR, RESPONDER) == []


def test_matching_esp_packets_keeps_a_single_direction():
    packets = [
        _packet(INITIATOR, RESPONDER, PRIMARY_SPI, 1),
        _packet(INITIATOR, RESPONDER, PRIMARY_SPI, 2),
    ]

    matched = _matching_esp_packets(packets, hex(PRIMARY_SPI), INITIATOR, RESPONDER)

    assert len(matched) == 2
    assert {int(esp.spi) for _, esp in matched} == {PRIMARY_SPI}


def test_matching_esp_packets_supports_a_primary_spi_in_the_reverse_direction():
    packets = [
        _packet(RESPONDER, INITIATOR, PRIMARY_SPI, 1),
        _packet(INITIATOR, RESPONDER, REVERSE_SPI, 2),
        _packet(RESPONDER, INITIATOR, PRIMARY_SPI, 3),
    ]

    matched = _matching_esp_packets(packets, hex(PRIMARY_SPI), INITIATOR, RESPONDER)

    assert {int(esp.spi) for _, esp in matched} == {PRIMARY_SPI, REVERSE_SPI}


def test_esp_features_use_combined_directional_bytes_and_asymmetry():
    outbound = _packet(INITIATOR, RESPONDER, PRIMARY_SPI, 1, b"a" * 10)
    inbound = _packet(RESPONDER, INITIATOR, REVERSE_SPI, 2, b"b" * 20)
    packets = [outbound, inbound, _packet(INITIATOR, RESPONDER, PRIMARY_SPI, 3), _packet(RESPONDER, INITIATOR, REVERSE_SPI, 4), _packet(INITIATOR, RESPONDER, PRIMARY_SPI, 5)]

    matched = _matching_esp_packets(packets, hex(PRIMARY_SPI), INITIATOR, RESPONDER)
    features = _esp_features(matched, INITIATOR, 4.0)

    expected_outbound = sum(len(bytes(esp)) for packet, esp in matched if packet[IP].src == INITIATOR)
    expected_inbound = sum(len(bytes(esp)) for packet, esp in matched if packet[IP].src == RESPONDER)
    assert features["esp_packet_count"] == 5
    assert features["esp_bytes_total"] == expected_outbound + expected_inbound
    assert features["asymmetry_ratio"] == expected_outbound / (expected_inbound + 1)


def test_zero_rule_uses_combined_packet_count():
    below = _matching_esp_packets(_session_packets(4), hex(PRIMARY_SPI), INITIATOR, RESPONDER)
    at_limit = _matching_esp_packets(_session_packets(5), hex(PRIMARY_SPI), INITIATOR, RESPONDER)
    above_limit = _matching_esp_packets(_session_packets(6), hex(PRIMARY_SPI), INITIATOR, RESPONDER)

    assert _esp_features(below, INITIATOR, 3.0)["esp_packet_count"] == 0
    assert _esp_features(at_limit, INITIATOR, 4.0)["esp_packet_count"] == 5
    assert _esp_features(above_limit, INITIATOR, 5.0)["esp_packet_count"] == 6


def test_esp_features_sort_combined_packets_before_iat_calculation():
    packets = [
        _packet(INITIATOR, RESPONDER, PRIMARY_SPI, 3),
        _packet(RESPONDER, INITIATOR, REVERSE_SPI, 2),
        _packet(INITIATOR, RESPONDER, PRIMARY_SPI, 5),
        _packet(RESPONDER, INITIATOR, REVERSE_SPI, 4),
        _packet(INITIATOR, RESPONDER, PRIMARY_SPI, 1),
    ]

    matched = _matching_esp_packets(packets, hex(PRIMARY_SPI), INITIATOR, RESPONDER)
    features = _esp_features(matched, INITIATOR, 4.0)

    assert features["esp_iat_mean"] == 1.0
    assert features["esp_iat_min"] == 1.0
    assert features["esp_iat_max"] == 1.0


def test_burst_sizes_only_end_after_gaps_greater_than_100ms():
    assert _burst_sizes([0.005, 0.05, 0.005]) == [3]
    assert _burst_sizes([0.005, 0.101, 0.005]) == [2, 2]


def test_process_pcap_uses_both_directional_spis(monkeypatch, tmp_path):
    packets = _session_packets()
    ike_fields = {
        "session_id": "dual_spi",
        "initiator_ip": INITIATOR,
        "responder_ip": RESPONDER,
        "initiator_port": 500,
        "responder_port": 500,
        "ike_version": 2,
        "ike_exchange_type": 34,
        "ike_initiator_spi": "0x1",
        "sa_proposal_count": 1,
        "ke_dh_group": 14,
        "ike_nat_traversal": False,
        "ike_packet_count": 2,
        "ike_handshake_duration": 1.0,
        "mode": "tunnel",
        "cipher_suite": "aes256_gcm",
        "auth_algo": "aes_gcm",
        "dh_group": "group14",
        "pfs_enabled": False,
        "key_lifetime_sec": 3600,
        "esp_spi": hex(PRIMARY_SPI),
    }
    monkeypatch.setattr("features.pipeline._read_packets", lambda _: packets)
    monkeypatch.setattr("features.pipeline._write_parquet", lambda row, _: None)

    row = process_pcap(tmp_path / "dual_spi.pcap", ike_fields, tmp_path)

    assert row is not None
    assert row["esp_packet_count"] == 5
