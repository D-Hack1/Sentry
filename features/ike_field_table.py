"""
features/ike_field_table.py — lookup tables mapping raw IKE numeric values
(IANA "IKEv2 Parameters" registry) to human-readable strings.

    DH_GROUPS[19]        -> "group19_ecp256"
    dh_group_label(19)   -> "group19"            (schema / security_rules form)
    cipher_label(20, 256) -> "aes256_gcm"         (CipherSuite form)
"""

from __future__ import annotations

from typing import Optional

# Transform Type 4 — Diffie-Hellman group
DH_GROUPS: dict[int, str] = {
    2: "group2_1024",
    5: "group5_1536",
    14: "group14_2048",
    19: "group19_ecp256",
    20: "group20_ecp384",
}

# Transform Type 1 — encryption algorithm (key length comes from the Key Length attribute)
ENCR_ALGOS: dict[int, str] = {
    12: "aes_cbc",
    20: "aes_gcm",   # ENCR_AES_GCM_16 (16-octet ICV)
}

ENCR_KEY_LENS: dict[int, str] = {
    128: "128",
    256: "256",
}

# Transform Type 3 — integrity algorithm
AUTH_ALGOS: dict[int, str] = {
    1: "hmac_md5",      # AUTH_HMAC_MD5_96
    2: "hmac_sha1",     # AUTH_HMAC_SHA1_96
    12: "hmac_sha256",  # AUTH_HMAC_SHA2_256_128
    13: "hmac_sha384",  # AUTH_HMAC_SHA2_384_192
}

# Exchange types
IKEV2_EXCHANGE_TYPES: dict[int, str] = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
}

IKEV1_EXCHANGE_TYPES: dict[int, str] = {
    2: "MAIN_MODE",
    4: "AGGRESSIVE_MODE",
    5: "INFORMATIONAL",
    32: "QUICK_MODE",
}


def dh_group_label(group: Optional[int]) -> Optional[str]:
    """2 -> 'group2' (the form used by IPsecFeatureRow.dh_group and security_rules)."""
    if group is None or group not in DH_GROUPS:
        return None
    return f"group{group}"


def cipher_label(encr_id: Optional[int], key_length: Optional[int]) -> Optional[str]:
    """(12, 128) -> 'aes128_cbc'; (20, 256) -> 'aes256_gcm'; unknown -> None."""
    algo = ENCR_ALGOS.get(encr_id) if encr_id is not None else None
    bits = ENCR_KEY_LENS.get(key_length) if key_length is not None else None
    if algo is None or bits is None:
        return None
    family, mode = algo.split("_")
    return f"{family}{bits}_{mode}"


def auth_label(integ_id: Optional[int], encr_id: Optional[int] = None) -> Optional[str]:
    """AEAD ciphers (AES-GCM) carry their own integrity: report 'aes_gcm'."""
    if encr_id is not None and ENCR_ALGOS.get(encr_id) == "aes_gcm":
        return "aes_gcm"
    if integ_id is None:
        return None
    return AUTH_ALGOS.get(integ_id)


def exchange_type_label(ike_version: Optional[int], exchange_type: Optional[int]) -> Optional[str]:
    if exchange_type is None:
        return None
    table = IKEV1_EXCHANGE_TYPES if ike_version == 1 else IKEV2_EXCHANGE_TYPES
    return table.get(exchange_type)
