"""
IPsec Security Scorer
---------------------

Evaluates the security configuration of an IPsec session using the
rules defined in security_rules.py.

Input:
    IPsecFeatureRow

Output:
    security_score
    severity
    risk_flags

The anomaly score from the Isolation Forest is intentionally NOT used
here. Anomaly detection and configuration security assessment are
separate signals.
"""

from __future__ import annotations

from typing import Any

from .security_rules import (
    SECURITY_RULES,
    key_lifetime_rule_key,
    score_to_severity,
)


# ---------------------------------------------------------------------
# Rule application
# ---------------------------------------------------------------------

def apply_rule(
    rule: dict[str, Any],
    penalties: list[int],
    bonuses: list[int],
    risk_flags: list[str],
    recommendations: list[str],
) -> None:
    """
    Apply one security rule.

    Penalties and bonuses are accumulated separately so that the final
    score can be calculated as:

        100 + bonuses - penalties

    Risk flags and recommendations are only added when the rule
    actually carries them.
    """

    penalty = int(
        rule.get("penalty", 0)
    )

    bonus = int(
        rule.get("bonus", 0)
    )

    flag = rule.get(
        "flag"
    )

    recommendation = rule.get(
        "recommendation",
        ""
    )

    if penalty > 0:
        penalties.append(penalty)

    if bonus > 0:
        bonuses.append(bonus)

    if flag:
        risk_flags.append(flag)

    if recommendation:
        recommendations.append(
            recommendation
        )


# ---------------------------------------------------------------------
# Main scoring function
# ---------------------------------------------------------------------

def calculate_security_score(row) -> dict:
    """
    Calculate the security score for an IPsecFeatureRow.

    Returns:
        {
            "security_score": int,
            "severity": str,
            "risk_flags": list[str],
            "recommendations": list[str],
            "penalty_points": int,
            "bonus_points": int
        }

    Base score:
        100

    Final score:
        100 + total bonuses - total penalties

    Final score is clamped to:
        0 <= score <= 100
    """

    penalties: list[int] = []
    bonuses: list[int] = []

    risk_flags: list[str] = []
    recommendations: list[str] = []

    # -------------------------------------------------------------
    # 1. DH GROUP
    # -------------------------------------------------------------

    if row.dh_group:
        rule_key = row.dh_group

        if rule_key in SECURITY_RULES:
            apply_rule(
                SECURITY_RULES[rule_key],
                penalties,
                bonuses,
                risk_flags,
                recommendations,
            )

    # -------------------------------------------------------------
    # 2. CIPHER SUITE
    # -------------------------------------------------------------

    if row.cipher_suite:
        rule_key = row.cipher_suite

        if rule_key in SECURITY_RULES:
            apply_rule(
                SECURITY_RULES[rule_key],
                penalties,
                bonuses,
                risk_flags,
                recommendations,
            )

    # -------------------------------------------------------------
    # 3. IKE VERSION
    # -------------------------------------------------------------

    if row.ike_version == 1:

        apply_rule(
            SECURITY_RULES["ikev1"],
            penalties,
            bonuses,
            risk_flags,
            recommendations,
        )

    elif row.ike_version == 2:

        apply_rule(
            SECURITY_RULES["ikev2"],
            penalties,
            bonuses,
            risk_flags,
            recommendations,
        )

    # -------------------------------------------------------------
    # 4. PERFECT FORWARD SECRECY
    # -------------------------------------------------------------

    if row.pfs_enabled is False:

        apply_rule(
            SECURITY_RULES["pfs_disabled"],
            penalties,
            bonuses,
            risk_flags,
            recommendations,
        )

    # -------------------------------------------------------------
    # 5. KEY LIFETIME
    # -------------------------------------------------------------

    if row.key_lifetime_sec is not None:

        rule_key = key_lifetime_rule_key(
            row.key_lifetime_sec
        )

        if rule_key:
            apply_rule(
                SECURITY_RULES[rule_key],
                penalties,
                bonuses,
                risk_flags,
                recommendations,
            )

    # -------------------------------------------------------------
    # 6. NAT TRAVERSAL
    # -------------------------------------------------------------

    if row.ike_nat_traversal is True:

        apply_rule(
            SECURITY_RULES["nat_traversal"],
            penalties,
            bonuses,
            risk_flags,
            recommendations,
        )

    # -------------------------------------------------------------
    # 7. AUTHENTICATION / INTEGRITY ALGORITHM
    # -------------------------------------------------------------

    if row.auth_algo:
        rule_key = row.auth_algo

        if rule_key in SECURITY_RULES:
            apply_rule(
                SECURITY_RULES[rule_key],
                penalties,
                bonuses,
                risk_flags,
                recommendations,
            )

    # -------------------------------------------------------------
    # 8. CALCULATE FINAL SCORE
    # -------------------------------------------------------------

    total_penalty = sum(
        penalties
    )

    total_bonus = sum(
        bonuses
    )

    raw_score = (
        100
        + total_bonus
        - total_penalty
    )

    # Clamp to [0, 100].
    security_score = max(
        0,
        min(
            100,
            raw_score,
        ),
    )

    # -------------------------------------------------------------
    # 9. SEVERITY
    # -------------------------------------------------------------

    severity = score_to_severity(
        security_score
    )

    return {
        "security_score": security_score,
        "severity": severity,
        "risk_flags": risk_flags,
        "recommendations": recommendations,
        "penalty_points": total_penalty,
        "bonus_points": total_bonus,
    }


# ---------------------------------------------------------------------
# Apply score directly to IPsecFeatureRow
# ---------------------------------------------------------------------

def score_feature_row(row):
    """
    Calculate the security assessment and write the results directly
    into an IPsecFeatureRow.

    Returns:
        The same IPsecFeatureRow instance.
    """

    result = calculate_security_score(
        row
    )

    row.security_score = result[
        "security_score"
    ]

    row.severity = result[
        "severity"
    ]

    row.risk_flags = result[
        "risk_flags"
    ]

    return row


# ---------------------------------------------------------------------
# Pretty-print helper
# ---------------------------------------------------------------------

def print_security_assessment(
    result: dict,
) -> None:
    """
    Print a human-readable security assessment.
    """

    print()
    print("=" * 70)
    print("IPSEC SECURITY ASSESSMENT")
    print("=" * 70)

    print(
        f"Security score : "
        f"{result['security_score']}/100"
    )

    print(
        f"Severity       : "
        f"{result['severity']}"
    )

    print(
        f"Penalty points : "
        f"{result['penalty_points']}"
    )

    print(
        f"Bonus points   : "
        f"{result['bonus_points']}"
    )

    print()

    if result["risk_flags"]:

        print("RISK FLAGS")
        print("-" * 70)

        for index, flag in enumerate(
            result["risk_flags"],
            start=1,
        ):
            print(
                f"{index}. {flag}"
            )

    else:

        print(
            "RISK FLAGS"
        )
        print("-" * 70)
        print(
            "No security risk flags triggered."
        )

    print()

    if result["recommendations"]:

        print(
            "RECOMMENDATIONS"
        )
        print("-" * 70)

        for index, recommendation in enumerate(
            result["recommendations"],
            start=1,
        ):
            print(
                f"{index}. {recommendation}"
            )

# ---------------------------------------------------------------------
# Standalone tests
# ---------------------------------------------------------------------

def main():
    """
    Rule-engine sanity tests.

    Tests both a deliberately weak IPsec configuration and
    a strong IPsec configuration.
    """

    # ================================================================
    # TEST 1: WEAK CONFIGURATION
    # ================================================================

    class WeakTestRow:
        dh_group = "dh_group2"
        cipher_suite = "aes128_cbc"
        ike_version = 1
        pfs_enabled = False
        key_lifetime_sec = 86400
        ike_nat_traversal = True
        auth_algo = "hmac_sha1"

    weak_row = WeakTestRow()

    weak_result = calculate_security_score(
        weak_row
    )

    print()
    print("=" * 70)
    print("TEST 1: WEAK IPSEC CONFIGURATION")
    print("=" * 70)

    print_security_assessment(
        weak_result
    )

    # ================================================================
    # TEST 2: STRONG CONFIGURATION
    # ================================================================

    class StrongTestRow:
        dh_group = "dh_group20"
        cipher_suite = "aes256_gcm"
        ike_version = 2
        pfs_enabled = True
        key_lifetime_sec = 3600
        ike_nat_traversal = False
        auth_algo = None

    strong_row = StrongTestRow()

    strong_result = calculate_security_score(
        strong_row
    )

    print()
    print()
    print("=" * 70)
    print("TEST 2: STRONG IPSEC CONFIGURATION")
    print("=" * 70)

    print_security_assessment(
        strong_result
    )

    # ================================================================
    # SUMMARY
    # ================================================================

    print()
    print("=" * 70)
    print("SCORING SUMMARY")
    print("=" * 70)

    print(
        f"Weak configuration   : "
        f"{weak_result['security_score']}/100 "
        f"({weak_result['severity']})"
    )

    print(
        f"Strong configuration : "
        f"{strong_result['security_score']}/100 "
        f"({strong_result['severity']})"
    )

    print("=" * 70)


if __name__ == "__main__":
    main()