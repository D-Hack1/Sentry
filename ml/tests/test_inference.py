import math

import pytest

from ml.inference import (
    analyze_dict,
    anomaly_label,
    infer,
    load_fixture_payloads,
    load_models,
    resolve_config,
)

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")

# Real-PCAP payloads (ml/tests/fixtures/test_payloads.json) -> expected traffic class
EXPECTED_TRAFFIC = {
    "transport_aes128cbc_group14_nopfs_web_001": "web",
    "transport_aes128cbc_group19_pfs_voip_001": "voip",
    "transport_aes128cbc_group19_nopfs_video_stream_001": "video_stream",
    "transport_aes128cbc_group20_pfs_file_transfer_001": "file_transfer",
    "transport_aes128cbc_group14_pfs_icmp_001": "icmp",
}


@pytest.fixture(scope="module")
def models():
    try:
        return load_models()
    except FileNotFoundError as exc:
        pytest.skip(str(exc))


@pytest.fixture(scope="module")
def payloads():
    return {p["session_id"]: p for p in load_fixture_payloads()}


def test_load_models_fails_fast_on_missing_files(tmp_path):
    with pytest.raises(FileNotFoundError, match="protocol_model.joblib"):
        load_models(tmp_path)


@pytest.mark.parametrize("session_id,expected", sorted(EXPECTED_TRAFFIC.items()))
def test_real_payloads_classified_correctly(models, payloads, session_id, expected):
    assert infer(payloads[session_id], models)["traffic_class"] == expected


def test_contract_fields_and_ranges(models, payloads):
    for payload in payloads.values():
        result = analyze_dict(payload, models)
        for key in ("session_id", "ike_version", "mode", "cipher_suite", "dh_group", "pfs_enabled",
                    "traffic_class", "traffic_confidence", "anomaly_score", "ai_confidence",
                    "security_score", "severity", "risk_flags", "evidence"):
            assert key in result
        assert 0.0 <= result["traffic_confidence"] <= 1.0
        assert 0.0 <= result["ai_confidence"] <= 1.0
        assert 0.0 <= result["security_score"] <= 100.0
        assert result["anomaly_score"] >= 0 and math.isfinite(result["anomaly_score"])
        assert isinstance(result["risk_flags"], list)
        assert len(result["evidence"]) >= 1


def test_parsed_config_is_never_overridden_by_model(models, payloads):
    payload = payloads["transport_aes128cbc_group14_nopfs_web_001"]
    result = analyze_dict(payload, models)
    assert (result["mode"], result["cipher_suite"], result["dh_group"], result["pfs_enabled"]) == (
        "transport", "aes128_cbc", "group14", False)
    assert set(result["config_source"].values()) == {"parser"}


def test_unobserved_config_is_filled_from_model(models, payloads):
    payload = dict(payloads["transport_aes128cbc_group14_pfs_icmp_001"], mode=None, pfs_enabled=None)
    result = analyze_dict(payload, models)
    assert result["mode"] in ("tunnel", "transport")
    assert isinstance(result["pfs_enabled"], bool)
    assert result["config_source"]["mode"] == "model"
    assert result["config_source"]["cipher_suite"] == "parser"


def test_security_demo_payloads(models, payloads):
    best = analyze_dict(payloads["test_best_practice_config"], models)
    assert (best["security_score"], best["severity"], best["risk_flags"]) == (100.0, "info", [])
    worst = analyze_dict(payloads["test_critical_config_alert"], models)
    assert worst["severity"] == "critical" and worst["security_score"] < 40
    assert len(worst["risk_flags"]) >= 5


def test_resolve_config_prefers_parser():
    resolved, source = resolve_config(
        {"mode": "tunnel", "cipher_suite": "", "dh_group": "group2", "pfs_enabled": None},
        {"mode": "transport", "cipher_suite": "aes256_gcm", "dh_group": "group20", "pfs_enabled": True},
    )
    assert resolved == {"mode": "tunnel", "cipher_suite": "aes256_gcm", "dh_group": "group2", "pfs_enabled": True}
    assert source == {"mode": "parser", "cipher_suite": "model", "dh_group": "parser", "pfs_enabled": "model"}


def test_anomaly_label_bands():
    assert anomaly_label(0.60, 0.58) == "anomalous"
    assert anomaly_label(0.55, 0.58) == "slightly_unusual"
    assert anomaly_label(0.50, 0.58) == "normal"
