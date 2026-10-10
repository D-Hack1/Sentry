import itertools

import pytest

from features.schema import CipherSuite, DHGroup
from ml.explainability import (
    ESP_DESCRIPTIONS,
    ESP_FEATURE_NAMES,
    FEATURE_LABELS,
    IKE_DESCRIPTIONS,
    IKE_FEATURE_NAMES,
    NO_DOMINANT_FEATURE,
    TRAFFIC_PHRASES,
    explain_config,
    explain_traffic,
)
from ml.inference import load_fixture_payloads, load_models

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


@pytest.fixture(scope="module")
def models():
    try:
        return load_models()
    except FileNotFoundError as exc:
        pytest.skip(str(exc))


@pytest.fixture(scope="module")
def payloads():
    return load_fixture_payloads()


def _describes_known_feature(text, descriptions):
    return text == NO_DOMINANT_FEATURE or any(desc in text for desc in descriptions.values())


def test_feature_labels_cover_spec_features():
    for name in ("esp_pkt_size_std", "esp_iat_std", "esp_burst_count", "asymmetry_ratio",
                 "ke_dh_group", "sa_proposal_count", "ike_handshake_duration",
                 "esp_bytes_per_sec", "ike_nat_traversal", "pfs_enabled"):
        assert FEATURE_LABELS[name]
    assert set(ESP_DESCRIPTIONS) == set(ESP_FEATURE_NAMES)
    assert set(IKE_DESCRIPTIONS) == set(IKE_FEATURE_NAMES)


def test_traffic_evidence_for_real_payloads(models, payloads):
    for payload in payloads:
        evidence = explain_traffic(payload, models.traffic_model, models.encoder)
        assert 1 <= len(evidence) <= 5
        assert all(isinstance(e, str) and e for e in evidence)
        assert all(_describes_known_feature(e, ESP_DESCRIPTIONS) for e in evidence)
        predicted = models.encoder["traffic_encoder"].inverse_transform(
            [models.traffic_model.predict_proba(
                [[float(payload[f]) for f in ESP_FEATURE_NAMES]])[0].argmax()]
        )[0]
        assert any(TRAFFIC_PHRASES[predicted] in e for e in evidence)


@pytest.mark.parametrize(
    "cipher,dh,pfs,nat",
    list(itertools.product(CipherSuite.ALL, DHGroup.ALL, [True, False], [True, False])),
)
def test_config_evidence_for_every_config_combo(models, payloads, cipher, dh, pfs, nat):
    row = dict(payloads[0], cipher_suite=cipher, dh_group=dh, pfs_enabled=pfs,
               ke_dh_group=int(dh.replace("group", "")), ike_nat_traversal=nat,
               initiator_port=4500 if nat else 500, responder_port=4500 if nat else 500)
    evidence = explain_config(row, models.protocol_model, models.encoder)
    assert 1 <= len(evidence) <= 5
    assert all(_describes_known_feature(e, IKE_DESCRIPTIONS) for e in evidence)


def test_explanations_are_deterministic(models, payloads):
    first = explain_traffic(payloads[1], models.traffic_model, models.encoder)
    assert all(explain_traffic(payloads[1], models.traffic_model, models.encoder) == first for _ in range(3))


def test_missing_values_do_not_crash(models):
    row = {name: None for name in ESP_FEATURE_NAMES + IKE_FEATURE_NAMES}
    assert explain_traffic(row, models.traffic_model, models.encoder)
    assert explain_config(row, models.protocol_model, models.encoder)
