import itertools

import pytest

from features.schema import CipherSuite, DHGroup
from features.security_rules import SECURITY_RULES, score_to_severity
from ml.scorer import score_session


def _row(**overrides):
    row = {
        "ike_version": 2,
        "mode": "tunnel",
        "cipher_suite": "aes256_gcm",
        "auth_algo": "aes_gcm",
        "dh_group": "group20",
        "pfs_enabled": True,
        "key_lifetime_sec": 3600,
        "ike_nat_traversal": False,
    }
    row.update(overrides)
    return row


def test_best_practice_config_is_info_with_no_flags():
    result = score_session(_row())
    assert result["security_score"] == 100.0
    assert result["severity"] == "info"
    assert result["risk_flags"] == []
    assert result["recommendations"] == []


def test_known_strong_config_aes256cbc_group14_scores_90():
    # Documented in TRAINING_RESULTS.md: tunnel, AES-256-CBC, group14, PFS, IKEv2 -> 90 / info
    result = score_session(_row(cipher_suite="aes256_cbc", auth_algo="hmac_sha256", dh_group="group14"))
    assert result["security_score"] == 90.0
    assert result["severity"] == "info"


@pytest.mark.parametrize("dh_group", ["group2", "group5"])
def test_known_weak_configs_are_critical(dh_group):
    result = score_session(_row(
        ike_version=1, cipher_suite="aes128_cbc", auth_algo="hmac_sha1",
        dh_group=dh_group, pfs_enabled=False, key_lifetime_sec=86400,
    ))
    assert result["security_score"] == 0.0
    assert result["severity"] == "critical"
    assert len(result["risk_flags"]) >= 5


def test_flags_and_recommendations_ordered_by_penalty():
    result = score_session(_row(
        ike_version=1, cipher_suite="aes128_cbc", auth_algo="hmac_sha1",
        dh_group="group2", pfs_enabled=False, key_lifetime_sec=86400,
    ))
    penalties = [SECURITY_RULES[k]["penalty"] for k in result["applied_rules"]]
    assert penalties == sorted(penalties, reverse=True)
    assert result["risk_flags"][0] == SECURITY_RULES["dh_group2"]["flag"]
    assert result["recommendations"][0] == SECURITY_RULES["dh_group2"]["recommendation"]


def test_score_is_deterministic():
    row = _row(cipher_suite="aes128_cbc", dh_group="group14", pfs_enabled=False)
    assert all(score_session(row) == score_session(row) for _ in range(10))


def test_score_is_clamped():
    assert score_session(_row())["security_score"] <= 100.0
    worst = _row(ike_version=1, cipher_suite="aes128_cbc", auth_algo="hmac_md5", dh_group="group2",
                 pfs_enabled=False, key_lifetime_sec=86400, ike_nat_traversal=True)
    assert score_session(worst)["security_score"] == 0.0


def test_unobserved_fields_never_penalise():
    result = score_session(_row(pfs_enabled=None, key_lifetime_sec=None, ike_version=0))
    assert "pfs_disabled" not in result["applied_rules"]
    assert not any(k.startswith("key_lifetime") for k in result["applied_rules"])
    assert "ikev1" not in result["applied_rules"]


def test_string_booleans_are_understood():
    assert "pfs_disabled" in score_session(_row(pfs_enabled="false"))["applied_rules"]
    assert "nat_traversal" in score_session(_row(ike_nat_traversal="true"))["applied_rules"]


@pytest.mark.parametrize(
    "cipher,dh,pfs,ike",
    list(itertools.product(CipherSuite.ALL, DHGroup.ALL, [True, False], [1, 2])),
)
def test_every_config_combo_scores_consistently(cipher, dh, pfs, ike):
    result = score_session(_row(cipher_suite=cipher, dh_group=dh, pfs_enabled=pfs, ike_version=ike))
    assert 0.0 <= result["security_score"] <= 100.0
    assert result["severity"] == score_to_severity(result["security_score"])
    assert len(result["risk_flags"]) == len([k for k in result["applied_rules"] if SECURITY_RULES[k]["flag"]])


@pytest.mark.parametrize(
    "score,severity",
    [(0, "critical"), (39.9, "critical"), (40, "high"), (59.9, "high"), (60, "medium"),
     (74.9, "medium"), (75, "low"), (89.9, "low"), (90, "info"), (100, "info")],
)
def test_severity_thresholds(score, severity):
    assert score_to_severity(score) == severity
