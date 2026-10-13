import json

from scapy.all import IP, UDP, Raw, wrpcap

from data import make_labels, verify
from data.labels import parse_session_id


def _pcap(path, start=1_735_725_600.0):
    packets = []
    for i in range(3):
        pkt = IP(src="10.10.0.2", dst="10.10.0.3") / UDP(sport=500, dport=500) / Raw(b"x" * 40)
        pkt.time = start + i
        packets.append(pkt)
    wrpcap(str(path), packets)


def test_parse_session_id():
    assert parse_session_id("tunnel_aes256gcm_group19_pfs_video_stream_001") == {
        "mode": "tunnel", "cipher_suite": "aes256_gcm", "dh_group": "group19",
        "pfs_enabled": True, "traffic_class": "video_stream", "seq": "001",
    }
    assert parse_session_id("transport_aes128cbc_group2_nopfs_icmp_002")["pfs_enabled"] is False
    assert parse_session_id("random_capture") is None
    assert parse_session_id("tunnel_des_group19_pfs_web_001") is None


def test_make_labels_then_verify(tmp_path):
    pcaps, labels = tmp_path / "pcaps", tmp_path / "labels"
    pcaps.mkdir()
    _pcap(pcaps / "tunnel_aes256gcm_group19_pfs_web_001.pcap")
    _pcap(pcaps / "transport_aes128cbc_group2_nopfs_file_transfer_002.pcap")

    assert make_labels.main(["--from-pcaps", "--pcap-dir", str(pcaps), "--labels-dir", str(labels)]) == 0
    label = json.loads((labels / "tunnel_aes256gcm_group19_pfs_web_001.json").read_text())
    assert label["cipher_suite"] == "aes256_gcm"
    assert label["capture_time"] == "2025-01-01T10:00:00Z"
    assert label["duration_sec"] == 2.0
    assert label["ground_truth_severity"] == "info"

    assert verify.verify(pcaps, labels) == []
    assert verify.main(["--pcap-dir", str(pcaps), "--labels-dir", str(labels)]) == 0


def test_verify_fails_loudly(tmp_path):
    pcaps, labels = tmp_path / "pcaps", tmp_path / "labels"
    pcaps.mkdir()
    labels.mkdir()
    _pcap(pcaps / "tunnel_aes256gcm_group19_pfs_web_001.pcap")
    (labels / "orphan.json").write_text(json.dumps({"session_id": "orphan"}))
    (labels / "tunnel_aes256gcm_group19_pfs_web_001.json").write_text(json.dumps({
        "session_id": "tunnel_aes256gcm_group19_pfs_web_001", "mode": "tunnel",
        "cipher_suite": "aes256_gcm", "dh_group": "group19", "pfs_enabled": False,
        "traffic_class": "web",
    }))
    problems = verify.verify(pcaps, labels)
    assert any("label without PCAP: orphan.json" in p for p in problems)
    assert any("pfs_enabled=False contradicts filename" in p for p in problems)
    assert verify.main(["--pcap-dir", str(pcaps), "--labels-dir", str(labels)]) == 1
