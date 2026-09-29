"""
Feature configuration for ESP behavioral ML.

This file defines exactly which behavioral features are used by the
Isolation Forest model.

Metadata columns are deliberately excluded.
"""

# ---------------------------------------------------------------------
# Metadata columns
# ---------------------------------------------------------------------

METADATA_COLUMNS = [
    "session_id",
    "window_index",
    "window_start",
    "window_end",
]


# ---------------------------------------------------------------------
# Features deliberately excluded because they duplicate other features
# ---------------------------------------------------------------------

# Every window is exactly 1 second, therefore:
#
#   packet_count == packets_per_sec
#   bytes_total  == bytes_per_sec
#
# We retain the rate representation because it describes traffic
# intensity explicitly.
#
# idle_time_fraction is the complement of active_time_fraction:
#
#   idle = 1 - active
#
# Therefore only active_time_fraction is retained.
REDUNDANT_FEATURES = [
    "packet_count",
    "bytes_total",
    "idle_time_fraction",
]


# ---------------------------------------------------------------------
# Behavioral features
# ---------------------------------------------------------------------

BEHAVIORAL_FEATURES = [
    # Packet size
    "pkt_size_mean",
    "pkt_size_std",
    "pkt_size_min",
    "pkt_size_max",
    "pkt_size_p25",
    "pkt_size_p50",
    "pkt_size_p75",
    "pkt_size_p90",
    "pkt_size_p95",

    # Inter-arrival time
    "iat_mean",
    "iat_std",
    "iat_min",
    "iat_max",
    "iat_p25",
    "iat_p50",
    "iat_p75",
    "iat_p90",
    "iat_p95",

    # Direction
    "inbound_packets",
    "outbound_packets",
    "inbound_bytes",
    "outbound_bytes",
    "packet_ratio",
    "byte_ratio",

    # Traffic rate
    "packets_per_sec",
    "bytes_per_sec",

    # Burst behavior
    "burst_count",
    "mean_burst_size",
    "max_burst_size",
    "burst_fraction",

    # Distribution
    "packet_size_entropy",
    "iat_entropy",

    # Activity
    "active_time_fraction",
]


# ---------------------------------------------------------------------
# Final model feature list
# ---------------------------------------------------------------------

MODEL_FEATURES = [
    feature
    for feature in BEHAVIORAL_FEATURES
    if feature not in REDUNDANT_FEATURES
]


def validate_feature_columns(columns):
    """
    Validate that the expected model features exist.
    """

    missing = [
        feature
        for feature in MODEL_FEATURES
        if feature not in columns
    ]

    if missing:
        raise ValueError(
            "Missing required ML features:\n"
            + "\n".join(f"  - {feature}" for feature in missing)
        )


def get_model_features():
    """Return the frozen model feature list."""
    return MODEL_FEATURES.copy()