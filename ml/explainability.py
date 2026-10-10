"""
ml/explainability.py — SHAP explanations for the protocol and traffic models.

explain_traffic(row, model, encoder) -> top-5 human-readable evidence strings
explain_config(row, model, encoder)  -> top-5 human-readable evidence strings

SHAP values come from shap.TreeExplainer (exact TreeSHAP for XGBoost).
Only features that push the model *towards* its predicted class are reported;
if none do, the single most influential feature is reported instead, so the
result always contains at least one string (API contract requirement).

Direction words ("High"/"Low") compare the session's value with a reference
point learned from the model itself: the cover-weighted median of every split
threshold the booster uses for that feature. That is where the trees "cut"
the feature, so it is a model-derived notion of typical vs. atypical.
"""

from __future__ import annotations

import os
import sys
import threading
from typing import Any, Mapping, Optional, Sequence

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from features.schema import IPsecFeatureRow  # noqa: E402

IKE_FEATURE_NAMES: list[str] = list(IPsecFeatureRow.IKE_FEATURE_NAMES)
ESP_FEATURE_NAMES: list[str] = list(IPsecFeatureRow.ESP_FEATURE_NAMES)
TOP_K = 5

# Static feature labels from the task spec (bidir_ratio renamed to
# asymmetry_ratio to match the schema). Used for reports / tooltips.
FEATURE_LABELS: dict[str, str] = {
    "esp_pkt_size_std": "Irregular ESP packet sizes — consistent with VoIP/video",
    "esp_iat_std": "Variable inter-arrival times — consistent with bursty web traffic",
    "esp_burst_count": "High burst count — consistent with file transfer or streaming",
    "asymmetry_ratio": "Asymmetric flow — more data in one direction",
    "ke_dh_group": "DH group used in key exchange",
    "sa_proposal_count": "Number of SA proposals offered (higher = more flexible initiator)",
    "ike_handshake_duration": "IKE handshake took longer than expected",
    "esp_bytes_per_sec": "High throughput — consistent with video or file transfer",
    "ike_nat_traversal": "NAT traversal detected — UDP encapsulation in use",
    "pfs_enabled": "Perfect Forward Secrecy status",
}

# Short descriptions used to build per-session evidence sentences.
ESP_DESCRIPTIONS: dict[str, str] = {
    "esp_packet_count": "packet count",
    "esp_bytes_total": "total bytes transferred",
    "esp_pkt_size_mean": "mean packet size",
    "esp_pkt_size_std": "packet size variability",
    "esp_pkt_size_min": "minimum packet size",
    "esp_pkt_size_max": "maximum packet size",
    "esp_iat_mean": "mean inter-arrival time",
    "esp_iat_std": "inter-arrival time variability",
    "esp_iat_min": "minimum inter-arrival time",
    "esp_iat_max": "maximum inter-arrival time",
    "esp_burst_count": "burst count",
    "esp_burst_size_mean": "mean burst size",
    "esp_bytes_per_sec": "throughput in bytes/sec",
    "esp_pkts_per_sec": "packet rate in pkts/sec",
    "asymmetry_ratio": "outbound/inbound flow asymmetry",
    "esp_pkt_size_entropy": "packet size entropy",
    "esp_iat_entropy": "inter-arrival time entropy",
    "esp_active_fraction": "active-traffic fraction",
}

IKE_DESCRIPTIONS: dict[str, str] = {
    "ike_version": "IKE version",
    "ike_exchange_type": "IKE exchange type",
    "sa_proposal_count": "SA proposals offered",
    "ke_dh_group": "key-exchange DH group",
    "ike_nat_traversal": "NAT traversal",
    "ike_packet_count": "IKE packet count",
    "ike_handshake_duration": "IKE handshake duration",
    "initiator_port": "initiator UDP port",
    "responder_port": "responder UDP port",
}

TRAFFIC_PHRASES: dict[str, str] = {
    "web": "web browsing",
    "voip": "VoIP calls",
    "video_stream": "video streaming",
    "file_transfer": "bulk file transfer",
    "icmp": "ICMP probing",
}

NO_DOMINANT_FEATURE = (
    "No single feature dominated — prediction is based on the overall feature profile"
)

_cache_lock = threading.Lock()
_explainers: dict[int, Any] = {}
_references: dict[int, np.ndarray] = {}


# ── Feature vectors ──────────────────────────────────────────────────────────

def _to_float(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def feature_vector(row: Mapping[str, Any], names: Sequence[str]) -> np.ndarray:
    """Build a (1, n) float matrix in the frozen column order."""
    return np.array([[_to_float(row.get(name)) for name in names]], dtype=float)


# ── Cached SHAP explainer + reference points ─────────────────────────────────

def _explainer(model) -> Any:
    key = id(model)
    with _cache_lock:
        if key not in _explainers:
            import shap

            _explainers[key] = shap.TreeExplainer(model)
        return _explainers[key]


def _reference_points(model, n_features: int) -> np.ndarray:
    """Cover-weighted median split threshold per feature (NaN if never split on)."""
    key = id(model)
    with _cache_lock:
        if key in _references:
            return _references[key]
    refs = np.full(n_features, np.nan)
    try:
        trees = model.get_booster().trees_to_dataframe()
        splits = trees[trees["Feature"] != "Leaf"]
        for idx in range(n_features):
            fname = f"f{idx}"
            sub = splits[splits["Feature"] == fname]
            if sub.empty:
                continue
            order = np.argsort(sub["Split"].to_numpy())
            thresholds = sub["Split"].to_numpy()[order]
            weights = sub["Cover"].to_numpy()[order]
            cumulative = np.cumsum(weights)
            refs[idx] = float(thresholds[np.searchsorted(cumulative, cumulative[-1] / 2.0)])
    except Exception:  # explanation must never break inference
        pass
    with _cache_lock:
        _references[key] = refs
    return refs


def shap_for_class(model, x: np.ndarray, class_index: int) -> np.ndarray:
    """SHAP values (n_features,) of row x towards class `class_index`."""
    values = np.asarray(_explainer(model).shap_values(x))
    # shap>=0.45 returns (n_rows, n_features, n_classes) for multiclass
    if values.ndim == 3:
        return values[0, :, class_index]
    if values.ndim == 2:  # binary / single output
        return values[0]
    raise ValueError(f"Unexpected SHAP output shape {values.shape}")


def _pick_top(contributions: np.ndarray, top_k: int) -> list[int]:
    order = np.argsort(-contributions)
    positive = [int(i) for i in order if contributions[i] > 1e-9][:top_k]
    if positive:
        return positive
    strongest = int(np.argmax(np.abs(contributions)))
    return [strongest] if abs(contributions[strongest]) > 1e-9 else []


def _fmt(value: float) -> str:
    if value == 0:
        return "0"
    if float(value).is_integer() and abs(value) < 1e15:
        return f"{int(value):,}"
    magnitude = abs(value)
    if magnitude >= 1000:
        return f"{value:,.0f}"
    if magnitude >= 10:
        return f"{value:.1f}"
    if magnitude >= 0.01:
        return f"{value:.3f}".rstrip("0").rstrip(".")
    return f"{value:.2e}"


def _predicted_index(model, x: np.ndarray, predicted_index: Optional[int]) -> int:
    if predicted_index is not None:
        return int(predicted_index)
    return int(np.argmax(model.predict_proba(x)[0]))


# ── Public API ───────────────────────────────────────────────────────────────

def explain_traffic(
    feature_row: Mapping[str, Any],
    model,
    encoder: Optional[Mapping[str, Any]] = None,
    predicted_index: Optional[int] = None,
    top_k: int = TOP_K,
) -> list[str]:
    """Top-k SHAP evidence strings for the traffic classification model."""
    x = feature_vector(feature_row, ESP_FEATURE_NAMES)
    cls_idx = _predicted_index(model, x, predicted_index)
    label = str(cls_idx)
    if encoder and "traffic_encoder" in encoder:
        label = str(encoder["traffic_encoder"].inverse_transform([cls_idx])[0])
    phrase = TRAFFIC_PHRASES.get(label, label.replace("_", " "))

    contributions = shap_for_class(model, x, cls_idx)
    refs = _reference_points(model, len(ESP_FEATURE_NAMES))
    chosen = _pick_top(contributions, top_k)
    if not chosen:
        return [NO_DOMINANT_FEATURE]

    evidence = []
    for idx in chosen:
        name = ESP_FEATURE_NAMES[idx]
        value = float(x[0, idx])
        desc = ESP_DESCRIPTIONS[name]
        ref = refs[idx]
        if np.isnan(ref):
            level = "Observed"
        else:
            level = "High" if value > ref else "Low"
        verdict = "consistent with" if contributions[idx] > 0 else "atypical for"
        evidence.append(f"{level} {desc} ({_fmt(value)}) — {verdict} {phrase}")
    return evidence


def explain_config(
    feature_row: Mapping[str, Any],
    model,
    encoder: Optional[Mapping[str, Any]] = None,
    predicted_index: Optional[int] = None,
    top_k: int = TOP_K,
) -> list[str]:
    """Top-k SHAP evidence strings for the protocol-identification model."""
    x = feature_vector(feature_row, IKE_FEATURE_NAMES)
    cls_idx = _predicted_index(model, x, predicted_index)
    label = str(cls_idx)
    if encoder and "protocol_encoder" in encoder:
        label = str(encoder["protocol_encoder"].inverse_transform([cls_idx])[0])
    pretty = label.replace("__", " / ")

    contributions = shap_for_class(model, x, cls_idx)
    chosen = _pick_top(contributions, top_k)
    if not chosen:
        return [NO_DOMINANT_FEATURE]

    evidence = []
    for idx in chosen:
        name = IKE_FEATURE_NAMES[idx]
        value = float(x[0, idx])
        shown = ("yes" if value else "no") if name == "ike_nat_traversal" else _fmt(value)
        verdict = "supports" if contributions[idx] > 0 else "argues against"
        evidence.append(f"{IKE_DESCRIPTIONS[name]} = {shown} — {verdict} predicted config {pretty}")
    return evidence
