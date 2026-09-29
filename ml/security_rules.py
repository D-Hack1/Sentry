
from __future__ import annotations
from typing import TypedDict, Optional


class SecurityRule(TypedDict):
    penalty: int            # Points deducted from base score (0 if bonus-only rule)
    bonus: int              # Points added to base score (0 if penalty-only rule)
    flag: Optional[str]     # Human-readable risk description shown in report (None for bonus rules)
    recommendation: str     # Actionable remediation step, ordered by impact in report


# Rule table
# Ordered by penalty magnitude (highest first).
# scorer.py applies ALL matching rules, sums net = bonuses - penalties,
# clamps final score to [0, 100].


SECURITY_RULES: dict[str, SecurityRule] = {

    # ── DH Groups
    # Matched against IPsecFeatureRow.dh_group (string from DHGroup enum)

    "dh_group2": {
        "penalty": 40,
        "bonus": 0,
        "flag": "CRITICAL: DH Group 2 (modp1024, 1024-bit) is cryptographically broken. "
                "Vulnerable to the Logjam attack — NSA-grade precomputation is feasible "
                "against 1024-bit DH. Sessions using this group offer no meaningful "
                "forward secrecy.",
        "recommendation": "Migrate immediately to DH Group 19 (ECP-256) or Group 20 (ECP-384). "
                          "In strongSwan: ike=aes256gcm16-prfsha384-ecp384!",
    },

    "dh_group5": {
        "penalty": 35,
        "bonus": 0,
        "flag": "HIGH: DH Group 5 (modp1536, 1536-bit) is below modern security recommendations. "
                "Considered weak against well-resourced state-level adversaries. "
                "Not recommended by NIST SP 800-77 Rev.1.",
        "recommendation": "Upgrade to DH Group 14 (modp2048) as a minimum. "
                          "Prefer Group 19 (ECP-256) or Group 20 (ECP-384) for new deployments.",
    },

    "dh_group14": {
        "penalty": 5,
        "bonus": 0,
        "flag": "LOW: DH Group 14 (modp2048) meets the minimum NIST recommendation but "
                "is a finite-field group. ECDH groups provide equivalent security at "
                "significantly lower computational cost.",
        "recommendation": "Consider upgrading to Group 19 (ECP-256) or Group 20 (ECP-384). "
                          "No urgent action required if Group 14 is enforced by policy.",
    },

    "dh_group19": {
        "penalty": 0,
        "bonus": 5,
        "flag": None,
        "recommendation": "",   # no action needed
    },

    "dh_group20": {
        "penalty": 0,
        "bonus": 10,
        "flag": None,
        "recommendation": "",
    },

    # ── Cipher Suites 
    # Matched against IPsecFeatureRow.cipher_suite (string from CipherSuite enum)

    "aes128_cbc": {
        "penalty": 15,
        "bonus": 0,
        "flag": "MEDIUM: AES-128-CBC is vulnerable to padding oracle attacks (BEAST, Lucky13, "
                "POODLE variants against ESP). CBC mode provides confidentiality only — "
                "authentication must come from a separate HMAC, which is also deprecated (SHA-1).",
        "recommendation": "Replace with AES-256-GCM (AEAD — provides both confidentiality and "
                          "authentication in one pass). In strongSwan: esp=aes256gcm16!",
    },

    "aes256_cbc": {
        "penalty": 10,
        "bonus": 0,
        "flag": "LOW: AES-256-CBC has an adequate key length but CBC mode carries inherent "
                "vulnerability to padding oracle attacks. Requires a separate HMAC for integrity.",
        "recommendation": "Prefer AES-256-GCM for authenticated encryption (AEAD). "
                          "In strongSwan: esp=aes256gcm16!",
    },

    "aes128_gcm": {
        "penalty": 0,
        "bonus": 5,
        "flag": None,
        "recommendation": "",
    },

    "aes256_gcm": {
        "penalty": 0,
        "bonus": 10,
        "flag": None,
        "recommendation": "",
    },

    # ── IKE Version 
    # Matched against IPsecFeatureRow.ike_version == 1

    "ikev1": {
        "penalty": 20,
        "bonus": 0,
        "flag": "HIGH: IKEv1 is a legacy protocol (RFC 2409, 1998). Superseded by IKEv2 "
                "(RFC 7296, 2014). IKEv1 Aggressive Mode exposes the identity hash in cleartext, "
                "enabling offline dictionary attacks. Lacks EAP, MOBIKE, and built-in NAT-T.",
        "recommendation": "Migrate to IKEv2. All modern VPN implementations (strongSwan, "
                          "OpenSwan, Cisco ASA ≥ 8.4, Palo Alto PAN-OS ≥ 7.0) support IKEv2.",
    },

    # ── Perfect Forward Secrecy 
    # Matched against IPsecFeatureRow.pfs_enabled == False

    "pfs_disabled": {
        "penalty": 25,
        "bonus": 0,
        "flag": "HIGH: Perfect Forward Secrecy (PFS) is disabled. Child SA keys are derived "
                "from the original IKE SA key material. If the long-term private key is ever "
                "compromised, ALL past session traffic can be decrypted retroactively "
                "(\"harvest now, decrypt later\" attack).",
        "recommendation": "Enable PFS by forcing a fresh DH exchange on every CREATE_CHILD_SA. "
                          "In strongSwan: esp=aes256gcm16-ecp384! (the trailing ! enforces PFS). "
                          "Confirm with: ip xfrm state | grep -i 'pfs'",
    },

    # ── Key Lifetime 
    # Matched via key_lifetime_rule_key() helper below

    "key_lifetime_86400": {
        "penalty": 10,
        "bonus": 0,
        "flag": "MEDIUM: Key lifetime is set to 86400 seconds (24 hours). Long key lifetimes "
                "extend the window of exposure if a session key is compromised. A leaked key "
                "decrypts up to 24 hours of traffic.",
        "recommendation": "Reduce key lifetime to 3600 seconds (1 hour) or less. "
                          "In strongSwan ipsec.conf: ikelifetime=1h, lifetime=1h, margintime=9m.",
    },

    "key_lifetime_28800": {
        "penalty": 5,
        "bonus": 0,
        "flag": "LOW: Key lifetime is set to 28800 seconds (8 hours). "
                "Consider reducing to 3600 seconds for better key hygiene.",
        "recommendation": "Set ikelifetime=1h and lifetime=1h in strongSwan ipsec.conf.",
    },

    # ── NAT Traversal 
    # Matched against IPsecFeatureRow.ike_nat_traversal == True

    "nat_traversal": {
        "penalty": 5,
        "bonus": 0,
        "flag": "INFO: NAT-T (RFC 3948) detected — IKE and ESP are UDP-encapsulated on port 4500. "
                "Outer UDP headers (source/dest port, packet size, timing) are visible to "
                "on-path observers even though ESP payload is encrypted.",
        "recommendation": "If both endpoints have routable IPs, disable NAT-T to eliminate "
                          "UDP header metadata leakage. In strongSwan: forceencaps=no. "
                          "If NAT is required, ensure the NAT device does not log UDP/4500 traffic.",
    },

    # ── Authentication / Integrity Algorithms ─────────────────────────────
    # Matched against IPsecFeatureRow.auth_algo

    "hmac_sha1": {
        "penalty": 10,
        "bonus": 0,
        "flag": "MEDIUM: HMAC-SHA1 is deprecated for new IPsec deployments (RFC 8221, 2017). "
                "SHA-1 collision resistance is weakened (SHAttered attack, 2017). "
                "While HMAC-SHA1 is not yet broken in practice, it is below current standards.",
        "recommendation": "Switch to HMAC-SHA-256 or HMAC-SHA-384 for integrity protection, "
                          "or move to an AEAD cipher (AES-GCM) that provides built-in authentication.",
    },

    "hmac_md5": {
        "penalty": 20,
        "bonus": 0,
        "flag": "HIGH: HMAC-MD5 is cryptographically broken — MD5 collision attacks are practical "
                "(Wang et al., 2004). Should not be used in any security-sensitive context. "
                "RFC 6151 explicitly prohibits MD5 for new security protocol designs.",
        "recommendation": "Immediately replace with HMAC-SHA-256 or an AEAD cipher suite (AES-GCM). "
                          "In strongSwan: ike=aes256gcm16-prfsha384-ecp384!",
    },

    # ── Positive / Bonus rules ─────────────────────────────────────────────
    # No flag, no recommendation — these only add to the score.
    # Matched against IPsecFeatureRow.ike_version == 2

    "ikev2": {
        "penalty": 0,
        "bonus": 5,
        "flag": None,
        "recommendation": "",
    },

}


# Key-lifetime threshold helper
# scorer.py calls this to resolve which key_lifetime rule key to apply.

def key_lifetime_rule_key(lifetime_sec: int) -> Optional[str]:
    """
    Return the SECURITY_RULES key for a given key_lifetime_sec value.
    Returns None if lifetime is within acceptable bounds (≤ 3600 s).

    Usage in scorer.py:
        rule_key = key_lifetime_rule_key(row.key_lifetime_sec)
        if rule_key:
            apply_rule(SECURITY_RULES[rule_key])
    """
    if lifetime_sec >= 86400:
        return "key_lifetime_86400"
    if lifetime_sec >= 28800:
        return "key_lifetime_28800"
    return None     # ≤ 3600 s — no penalty


# Score → Severity mapping
# Aligned with INFERENCE_SCHEMA.md thresholds.
# Duplicated here so Jaith / report_generator can import without scorer.py.

SEVERITY_THRESHOLDS: list[tuple[float, str]] = [
    (40.0,  "critical"),   # score < 40
    (60.0,  "high"),       # 40 ≤ score < 60
    (75.0,  "medium"),     # 60 ≤ score < 75
    (90.0,  "low"),        # 75 ≤ score < 90
    (101.0, "info"),       # score ≥ 90
]


def score_to_severity(score: float) -> str:
    """
    Map a numeric security_score [0, 100] to a severity label.

    Thresholds (from INFERENCE_SCHEMA.md):
        < 40   → critical
        40–59  → high
        60–74  → medium
        75–89  → low
        ≥ 90   → info
    """
    for threshold, label in SEVERITY_THRESHOLDS:
        if score < threshold:
            return label
    return "info"


# 
# Anomaly score interpretation thresholds
# Duplicated here for report_generator.py / Jaith's severity badge logic.
# Source: INFERENCE_SCHEMA.md — recalibrate after training on real PCAPs.
# 

ANOMALY_THRESHOLDS: list[tuple[float, str]] = [
    (0.40, "normal"),           # anomaly_score < 0.40
    (0.55, "slightly_unusual"), # 0.40 ≤ score < 0.55
    (999,  "anomalous"),        # score ≥ 0.55
]


def anomaly_score_label(score: float) -> str:
    """
    Map a continuous anomaly_score to a human label.
    Note: thresholds are heuristic on synthetic data.
    Recalibrate with real PCAPs before production.

        < 0.40  → 'normal'
        < 0.55  → 'slightly_unusual'
        ≥ 0.55  → 'anomalous'
    """
    for threshold, label in ANOMALY_THRESHOLDS:
        if score < threshold:
            return label
    return "anomalous"