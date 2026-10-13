"""
ml/inference.py — model loading + full per-session analysis.

    models = load_models()                 # fails fast if any artefact is missing
    raw    = infer(feature_row, models)    # the three ML models only
    result = analyze_dict(feature_row, models)   # models + config resolution
                                                 # + scorer + SHAP evidence

Run directly for a smoke test over the real-PCAP payload fixtures:
    python ml/inference.py

See ml/INFERENCE_SCHEMA.md for the output contract.
"""

from __future__ import annotations

import json
import math
import os
import sys
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from features.schema import IPsecFeatureRow, ProtocolModelTarget  # noqa: E402
from ml.explainability import (  # noqa: E402
    ESP_FEATURE_NAMES,
    IKE_FEATURE_NAMES,
    explain_config,
    explain_traffic,
    feature_vector,
)
from ml.scorer import score_session  # noqa: E402

ML_DIR = Path(__file__).resolve().parent
DEFAULT_MODEL_DIR = Path(os.getenv("MODEL_DIR", str(ML_DIR)))
FIXTURE_PATH = ML_DIR / "tests" / "fixtures" / "test_payloads.json"

MODEL_FILES: dict[str, str] = {
    "protocol_model": "protocol_model.joblib",
    "traffic_model": "traffic_model.joblib",
    "anomaly_model": "anomaly_model.joblib",
    "encoder": "encoder.joblib",
}

CONFIG_FIELDS = ("mode", "cipher_suite", "dh_group", "pfs_enabled")

# Width of the "slightly_unusual" band below the IsolationForest's own
# decision threshold (-offset_, set by contamination during training).
SLIGHTLY_UNUSUAL_MARGIN = 0.04


@dataclass
class Models:
    protocol_model: Any
    traffic_model: Any
    anomaly_model: Any
    encoder: dict
    model_dir: Path

    @property
    def anomaly_threshold(self) -> float:
        """anomaly_score at/above which IsolationForest itself calls a session an outlier."""
        return float(-self.anomaly_model.offset_)


def load_models(model_dir: Optional[str | Path] = None) -> Models:
    """Load all four artefacts. Raises FileNotFoundError naming every missing file."""
    import joblib

    directory = Path(model_dir) if model_dir else DEFAULT_MODEL_DIR
    missing = [name for name in MODEL_FILES.values() if not (directory / name).is_file()]
    if missing:
        raise FileNotFoundError(
            f"Missing model artefacts in {directory}: {', '.join(missing)}. "
            "Run `python ml/train.py` (needs data/features/*.parquet) first."
        )
    loaded = {}
    with warnings.catch_warnings():
        # xgboost warns when unpickling a model saved by another build; harmless.
        warnings.filterwarnings("ignore", category=UserWarning)
        for attr, fname in MODEL_FILES.items():
            loaded[attr] = joblib.load(directory / fname)
    encoder = loaded["encoder"]
    if not isinstance(encoder, dict) or not {"protocol_encoder", "traffic_encoder"} <= set(encoder):
        raise ValueError("encoder.joblib must be a dict with protocol_encoder and traffic_encoder")
    return Models(model_dir=directory, **loaded)


def anomaly_label(score: float, threshold: float) -> str:
    if score >= threshold:
        return "anomalous"
    if score >= threshold - SLIGHTLY_UNUSUAL_MARGIN:
        return "slightly_unusual"
    return "normal"


def infer(feature_row: Mapping[str, Any], models: Models) -> dict:
    """Run the three ML models on one feature row (no scoring / SHAP)."""
    ike_x = feature_vector(feature_row, IKE_FEATURE_NAMES)
    esp_x = feature_vector(feature_row, ESP_FEATURE_NAMES)

    # Model 1 — protocol identification (IKE features → combined config label)
    config_probs = models.protocol_model.predict_proba(ike_x)[0]
    config_index = int(np.argmax(config_probs))
    predicted_label = str(models.encoder["protocol_encoder"].inverse_transform([config_index])[0])
    config_confidence = float(config_probs[config_index])

    # Model 2 — traffic classification (ESP metadata → traffic class)
    traffic_probs = models.traffic_model.predict_proba(esp_x)[0]
    traffic_index = int(np.argmax(traffic_probs))
    traffic_class = str(models.encoder["traffic_encoder"].inverse_transform([traffic_index])[0])
    traffic_confidence = float(traffic_probs[traffic_index])

    # Model 3 — IsolationForest; negated so higher = more anomalous
    anomaly_score = float(-models.anomaly_model.score_samples(esp_x)[0])

    return {
        "predicted_config_label": predicted_label,
        "predicted_config": ProtocolModelTarget.parse_config_label(predicted_label),
        "config_index": config_index,
        "config_confidence": config_confidence,
        "traffic_class": traffic_class,
        "traffic_index": traffic_index,
        "traffic_confidence": traffic_confidence,
        "anomaly_score": anomaly_score,
        "anomaly_label": anomaly_label(anomaly_score, models.anomaly_threshold),
        "ai_confidence": float(
            IPsecFeatureRow.compute_ai_confidence(config_confidence, traffic_confidence)
        ),
    }


def resolve_config(
    feature_row: Mapping[str, Any], predicted_config: Mapping[str, Any]
) -> tuple[dict, dict]:
    """
    Plaintext IKE values parsed from the capture are ground truth; the protocol
    model only fills fields the parser could not observe (None / empty).
    Returns (resolved_fields, source_per_field).
    """
    resolved, source = {}, {}
    for field in CONFIG_FIELDS:
        value = feature_row.get(field)
        if value is None or value == "":
            resolved[field] = predicted_config.get(field)
            source[field] = "model"
        else:
            resolved[field] = value
            source[field] = "parser"
    return resolved, source


def _r(value: float, digits: int = 4) -> float:
    return round(float(value), digits)


def analyze_dict(feature_row: Mapping[str, Any], models: Models, explain: bool = True) -> dict:
    """
    Full analysis of one feature row — what POST /analyze returns (minus the
    Elasticsearch/correlation fields the API adds).
    """
    raw = infer(feature_row, models)
    resolved, source = resolve_config(feature_row, raw["predicted_config"])
    scored_row = {**feature_row, **resolved}
    score = score_session(scored_row)

    if explain:
        evidence = explain_traffic(
            feature_row, models.traffic_model, models.encoder, predicted_index=raw["traffic_index"]
        )
        config_evidence = explain_config(
            feature_row, models.protocol_model, models.encoder, predicted_index=raw["config_index"]
        )
    else:
        evidence, config_evidence = [], []

    return {
        "session_id": feature_row.get("session_id"),
        "ike_version": feature_row.get("ike_version"),
        "mode": resolved["mode"],
        "cipher_suite": resolved["cipher_suite"],
        "dh_group": resolved["dh_group"],
        "pfs_enabled": resolved["pfs_enabled"],
        "auth_algo": feature_row.get("auth_algo"),
        "key_lifetime_sec": feature_row.get("key_lifetime_sec"),
        "traffic_class": raw["traffic_class"],
        "traffic_confidence": _r(raw["traffic_confidence"]),
        "anomaly_score": _r(raw["anomaly_score"]),
        "anomaly_label": raw["anomaly_label"],
        "ai_confidence": _r(raw["ai_confidence"]),
        "security_score": score["security_score"],
        "severity": score["severity"],
        "risk_flags": score["risk_flags"],
        "recommendations": score["recommendations"],
        "evidence": evidence,
        "config_evidence": config_evidence,
        "predicted_config": raw["predicted_config_label"],
        "config_confidence": _r(raw["config_confidence"]),
        "config_source": source,
    }


def load_fixture_payloads(path: Path = FIXTURE_PATH) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main() -> int:
    models = load_models()
    payloads = load_fixture_payloads()
    print(f"Loaded models from {models.model_dir} | anomaly threshold={models.anomaly_threshold:.3f}")
    header = f"{'session_id':<52} {'traffic':<14} {'conf':>5} {'score':>6} {'severity':<9} {'anomaly':>7}"
    print(header)
    print("-" * len(header))
    for payload in payloads:
        result = analyze_dict(payload, models)
        print(
            f"{payload['session_id'][:52]:<52} {result['traffic_class']:<14} "
            f"{result['traffic_confidence']:>5.2f} {result['security_score']:>6.1f} "
            f"{result['severity']:<9} {result['anomaly_score']:>7.3f}"
        )
        if not math.isfinite(result["ai_confidence"]):
            print("  ai_confidence is not finite", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
