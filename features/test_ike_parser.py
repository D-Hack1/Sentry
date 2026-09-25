"""
features/test_ike_parser.py
===========================
Unit test verifying IKE parser functionality using synthetic PCAP captures.
Tests both IKEv2 and IKEv1 packet dissection and schema compatibility with IPsecFeatureRow.
"""

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import IP, UDP, wrpcap, Ether, ESP
import scapy.contrib.ikev2 as ikev2
import scapy.layers.isakmp as isakmp

from features.ike_parser import parse_ike_pcap
from features.schema import IPsecFeatureRow


def test_ikev2_parsing():
    print("Testing IKEv2 Dissection:")
    temp_pcap = os.path.join(tempfile.gettempdir(), "test_ikev2_session_001.pcap")

    # 1. Craft IKE_SA_INIT Request
    init_spi = b"\x12\x34\x56\x78\x9a\xbc\xde\xf0"
    
    # SA Proposal with AES256-GCM, DH Group 19
    trans_encr = ikev2.IKEv2_Transform(
        transform_type=1,
        transform_id=20,  # AES-GCM
        key_length=256
    )
    trans_dh = ikev2.IKEv2_Transform(
        transform_type=4,
        transform_id=19  # Group 19 (ECP-256)
    )
    proposal = ikev2.IKEv2_Proposal(
        proposal=1,
        proto="IKE",
        SPIsize=0,
        trans=trans_encr
    )
    sa_payload = ikev2.IKEv2_SA(prop=proposal)
    ke_payload = ikev2.IKEv2_KE(group=19, ke=b"\xaa" * 64)
    nonce_payload = ikev2.IKEv2_Nonce(nonce=b"\xbb" * 32)

    v2_init = (
        IP(src="10.10.0.2", dst="10.10.0.3") /
        UDP(sport=500, dport=500) /
        ikev2.IKEv2(init_SPI=init_spi, resp_SPI=b"\x00" * 8, exch_type=34, flags="Initiator") /
        sa_payload /
        ke_payload /
        nonce_payload
    )

    # 2. Craft IKE_SA_INIT Response
    resp_spi = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"
    v2_resp = (
        IP(src="10.10.0.3", dst="10.10.0.2") /
        UDP(sport=500, dport=500) /
        ikev2.IKEv2(init_SPI=init_spi, resp_SPI=resp_spi, exch_type=34, flags="Response") /
        sa_payload /
        ke_payload /
        nonce_payload
    )

    # 3. Craft ESP packets with child SA SPI
    child_spi = 0xc0ffee01
    esp_pkt1 = IP(src="10.10.0.2", dst="10.10.0.3") / ESP(spi=child_spi, seq=1, data=b"encrypted_data_1")
    esp_pkt2 = IP(src="10.10.0.3", dst="10.10.0.2") / ESP(spi=child_spi, seq=2, data=b"encrypted_data_2")

    # Write synthetic PCAP
    wrpcap(temp_pcap, [v2_init, v2_resp, esp_pkt1, esp_pkt2])

    try:
        features = parse_ike_pcap(temp_pcap)
        print("Extracted Features:")
        for k, v in features.items():
            print(f"  {k:24s}: {v}")

        assert features["ike_version"] == 2
        assert features["ike_exchange_type"] == 34
        assert features["ike_initiator_spi"] == "0x123456789abcdef0"
        assert features["ke_dh_group"] == 19
        assert features["dh_group"] == "group19"
        assert features["cipher_suite"] == "aes256_gcm"
        assert features["initiator_ip"] == "10.10.0.2"
        assert features["responder_ip"] == "10.10.0.3"
        assert features["initiator_port"] == 500
        assert features["responder_port"] == 500
        assert features["esp_spi"] == "0xc0ffee01"
        assert features["mode"] == "tunnel"
        assert features["ike_packet_count"] == 2

        # Verify compatibility with IPsecFeatureRow (Gowri/Ebin schema)
        row_fields = {
            **features,
            # Fill dummy ESP features for schema instantiation test
            "esp_packet_count": 2,
            "esp_bytes_total": 64,
            "esp_pkt_size_mean": 32.0,
            "esp_pkt_size_std": 0.0,
            "esp_pkt_size_min": 32.0,
            "esp_pkt_size_max": 32.0,
            "esp_iat_mean": 0.01,
            "esp_iat_std": 0.0,
            "esp_iat_min": 0.01,
            "esp_iat_max": 0.01,
            "esp_burst_count": 1,
            "esp_burst_size_mean": 2.0,
            "esp_bytes_per_sec": 64.0,
            "esp_pkts_per_sec": 2.0,
            "asymmetry_ratio": 1.0,
            "esp_pkt_size_entropy": 0.0,
            "esp_iat_entropy": 0.0,
            "esp_active_fraction": 1.0,
        }
        feature_row = IPsecFeatureRow.from_dict(row_fields)
        assert feature_row.session_id == features["session_id"]
        assert feature_row.dh_group == "group19"
        assert feature_row.cipher_suite == "aes256_gcm"
        print("[PASS] IKEv2 Dissection & Schema Compatibility Verified!")

    finally:
        if os.path.exists(temp_pcap):
            os.remove(temp_pcap)


def test_ikev1_parsing():
    print("\nTesting IKEv1 (ISAKMP) Dissection:")
    temp_pcap = os.path.join(tempfile.gettempdir(), "test_ikev1_session_002.pcap")

    cookie = b"\xaa\xbb\xcc\xdd\x11\x22\x33\x44"
    isakmp_pkt = (
        IP(src="10.10.0.2", dst="10.10.0.3") /
        UDP(sport=500, dport=500) /
        isakmp.ISAKMP(init_cookie=cookie, exch_type=2)
    )
    wrpcap(temp_pcap, [isakmp_pkt])

    try:
        features = parse_ike_pcap(temp_pcap)
        print("Extracted Features:")
        for k, v in features.items():
            print(f"  {k:24s}: {v}")

        assert features["ike_version"] == 1
        assert features["ike_exchange_type"] == 2
        assert features["ike_initiator_spi"] == "0xaabbccdd11223344"
        print("[PASS] IKEv1 Dissection Verified!")
    finally:
        if os.path.exists(temp_pcap):
            os.remove(temp_pcap)


if __name__ == "__main__":
    test_ikev2_parsing()
    test_ikev1_parsing()
    print("\nAll IKE parser tests passed successfully!")
