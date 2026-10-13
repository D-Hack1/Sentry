"""
ml/scorer.py — deterministic, rule-based IPsec security scorer (not ML).

Algorithm (per the SIH task spec):
  1. Start at 100.
  2. Apply every matching rule from features/security_rules.py
     (penalties subtract, bonuses add).
  3. Clamp to [0, 100].
  4. Map to severity: critical < 40 · high < 60 · medium < 75 · low < 90 · info ≥ 90.
  5. Return risk flags and recommendations ordered by penalty magnitude
     (highest-impact fix first).

Fields that could not be observed (None) never trigger a rule: the scorer
only judges what it can see. The API resolves missing config fields from the
protocol model before scoring, so in practice this only applies to
key_lifetime_sec when it is absent from the capture.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Mapping, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from features.security_rules import (  # noqa: E402
    SECURITY_RULES,
    key_lifetime_rule_key,
    score_to_severity,
)

BASE_SCORE = 100.0


def _as_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "1", "yes"):
            return True
        if lowered in ("false", "0", "no"):
            return False
        return None
    return bool(value)


def _as_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def matching_rule_keys(row: Mapping[str, Any]) -> list[str]:
    """Return the SECURITY_RULES keys that apply to this session, unordered."""
    keys: list[str] = []

    dh_group = row.get("dh_group")
    if dh_group and f"dh_{dh_group}" in SECURITY_RULES:
        keys.append(f"dh_{dh_group}")

    cipher = row.get("cipher_suite")
    if cipher and cipher in SECURITY_RULES:
        keys.append(cipher)

    auth = row.get("auth_algo")
    if auth and auth in SECURITY_RULES:
        keys.append(auth)

    ike_version = _as_int(row.get("ike_version"))
    if ike_version == 1:
        keys.append("ikev1")
    elif ike_version == 2:
        keys.append("ikev2")

    if _as_bool(row.get("pfs_enabled")) is False:
        keys.append("pfs_disabled")

    lifetime = _as_int(row.get("key_lifetime_sec"))
    if lifetime is not None:
        lifetime_key = key_lifetime_rule_key(lifetime)
        if lifetime_key:
            keys.append(lifetime_key)

    if _as_bool(row.get("ike_nat_traversal")) is True:
        keys.append("nat_traversal")

    return keys


def score_session(row: Mapping[str, Any]) -> dict:
    """
    Score one session's configuration.

    Returns:
        {
          "security_score": float in [0, 100],
          "severity": "critical" | "high" | "medium" | "low" | "info",
          "risk_flags": [str, ...],          # highest penalty first
          "recommendations": [str, ...],     # same order as risk_flags
          "applied_rules": [str, ...],       # SECURITY_RULES keys that fired
        }
    Deterministic: the same input always yields the same output.
    """
    keys = matching_rule_keys(row)
    # Stable ordering: biggest penalty first, then rule-table order.
    table_order = {key: i for i, key in enumerate(SECURITY_RULES)}
    keys.sort(key=lambda k: (-SECURITY_RULES[k]["penalty"], table_order[k]))

    score = BASE_SCORE
    risk_flags: list[str] = []
    recommendations: list[str] = []
    for key in keys:
        rule = SECURITY_RULES[key]
        score += rule["bonus"] - rule["penalty"]
        if rule["flag"]:
            risk_flags.append(rule["flag"])
        if rule["recommendation"]:
            recommendations.append(rule["recommendation"])

    score = float(max(0.0, min(100.0, score)))
    return {
        "security_score": score,
        "severity": score_to_severity(score),
        "risk_flags": risk_flags,
        "recommendations": recommendations,
        "applied_rules": keys,
    }
