"""Offline tests for the API helpers (no Elasticsearch / Kafka needed)."""

import json

import pytest
from fastapi.testclient import TestClient

from api import report_generator
from api.correlator import WEAK_CIPHERS, WEAK_DH_GROUPS
from es.init_index import PROPERTIES, mapping_conflicts
from ml.inference import analyze_dict, load_fixture_payloads, load_models

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


@pytest.fixture(scope="module")
def critical_session():
    payload = load_fixture_payloads()[-1]
    return {**payload, **analyze_dict(payload, load_models()), "es_id": "abc", "ts": "2025-01-01T11:00:00Z"}


def test_report_html_has_every_section(critical_session):
    html = report_generator.render_report_html(critical_session)
    for section in ("Executive Summary", "Security Score", "Session Metadata", "Risk Flags",
                    "MITRE ATT&amp;CK", "Recommendations", "AI Evidence"):
        assert section in html
    assert "T0842" in html and "T0859" in html and "T0830" in html
    assert html.count('class="flag"') == len(critical_session["risk_flags"])


def test_pdf_renders(critical_session):
    pdf = report_generator.generate_pdf_report(critical_session)
    assert pdf.startswith(b"%PDF-") and len(pdf) > 5000


def test_report_accepts_legacy_dict_evidence(critical_session):
    legacy = dict(critical_session, evidence={"traffic": ["t1"], "config": ["c1"]})
    html = report_generator.render_report_html(legacy)
    assert "t1" in html and "c1" in html


def test_flag_severity_prefixes():
    assert report_generator._flag_severity("CRITICAL: x") == "critical"
    assert report_generator._flag_severity("INFO: NAT-T") == "info"
    assert report_generator._flag_severity("no prefix") == "info"


def test_mapping_conflict_detection():
    assert mapping_conflicts(PROPERTIES) == []
    old = {"ts": {"type": "date", "format": "epoch_second"}, "evidence": {"type": "keyword"}}
    conflicts = mapping_conflicts(old)
    assert any(c.startswith("ts:") for c in conflicts) and any(c.startswith("evidence:") for c in conflicts)


def test_correlator_weak_sets_follow_rule_table():
    assert WEAK_CIPHERS == {"aes128_cbc", "aes256_cbc"}
    assert WEAK_DH_GROUPS == {"group2", "group5"}


def test_analyze_validation_envelope():
    from api.main import app

    with TestClient(app) as client:  # lifespan loads models; ES may be down -> still starts
        resp = client.post("/analyze", json={"session_id": "x"})
        assert resp.status_code == 422
        body = resp.json()
        assert body["error"]["code"] == "VALIDATION_ERROR"
        assert json.dumps(body)  # serialisable
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["models"]["traffic_model"] is True
