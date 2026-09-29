"""
Evaluate the trained ESP behavioral Isolation Forest.

This evaluates anomaly scores against the capture metadata manifest.

IMPORTANT:
The manifest metadata is used ONLY for analysis/evaluation.
It is NOT passed into the Isolation Forest.

The model sees behavioral ESP features only.
"""

from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd

from .feature_config import MODEL_FEATURES
from .train import (
    load_window_dataset,
    split_by_session,
    prepare_features,
    transform_features,
)


# ---------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------

MANIFEST_PATH = Path("data/capture_manifest.csv")

MODEL_PATH = Path(
    "ml/models/isolation_forest.joblib"
)

SCALER_PATH = Path(
    "ml/models/behavior_scaler.joblib"
)

OUTPUT_DIR = Path(
    "ml/evaluation"
)

WINDOW_SCORES_PATH = (
    OUTPUT_DIR / "window_scores.csv"
)

SESSION_SCORES_PATH = (
    OUTPUT_DIR / "session_scores.csv"
)


# ---------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------

def load_manifest():
    """Load the PCAP metadata manifest."""

    if not MANIFEST_PATH.exists():
        raise FileNotFoundError(
            f"Manifest not found: {MANIFEST_PATH}"
        )

    manifest = pd.read_csv(
        MANIFEST_PATH
    )

    required = {
        "session_id",
        "pcap",
        "mode",
        "cipher_suite",
        "dh_group",
        "pfs",
        "traffic_class",
        "capture_id",
    }

    missing = required - set(
        manifest.columns
    )

    if missing:
        raise ValueError(
            "Manifest is missing columns: "
            + ", ".join(sorted(missing))
        )

    return manifest


def load_model():
    """Load trained model and scaler."""

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Model not found: {MODEL_PATH}"
        )

    if not SCALER_PATH.exists():
        raise FileNotFoundError(
            f"Scaler not found: {SCALER_PATH}"
        )

    model = joblib.load(
        MODEL_PATH
    )

    scaler = joblib.load(
        SCALER_PATH
    )

    return model, scaler


# ---------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------

def score_windows(
    df,
    model,
    scaler,
):
    """Calculate anomaly score and prediction for every window."""

    X = prepare_features(df)

    X_scaled = transform_features(
        scaler,
        X,
    )

    # Higher score = more anomalous.
    scores = -model.score_samples(
        X_scaled
    )

    predictions = model.predict(
        X_scaled
    )

    result = df[
        [
            "session_id",
            "window_index",
            "window_start",
            "window_end",
        ]
    ].copy()

    result["anomaly_score"] = scores

    result["prediction"] = predictions

    result["is_anomaly"] = (
        predictions == -1
    )

    return result


# ---------------------------------------------------------------------
# Session aggregation
# ---------------------------------------------------------------------

def aggregate_sessions(
    window_scores,
):
    """
    Aggregate window-level scores into one row per session.

    We retain several statistics rather than reducing the entire
    session to a single score.
    """

    grouped = (
        window_scores
        .groupby("session_id")
    )

    sessions = grouped.agg(
        windows=(
            "anomaly_score",
            "count",
        ),

        mean_anomaly_score=(
            "anomaly_score",
            "mean",
        ),

        median_anomaly_score=(
            "anomaly_score",
            "median",
        ),

        max_anomaly_score=(
            "anomaly_score",
            "max",
        ),

        p95_anomaly_score=(
            "anomaly_score",
            lambda x: np.percentile(
                x,
                95,
            ),
        ),

        anomalous_windows=(
            "is_anomaly",
            "sum",
        ),
    ).reset_index()

    sessions["anomaly_fraction"] = (
        sessions["anomalous_windows"]
        / sessions["windows"]
    )

    return sessions


# ---------------------------------------------------------------------
# Evaluation helpers
# ---------------------------------------------------------------------

def print_split_summary(
    name,
    df,
):
    """Print basic split statistics."""

    anomaly_count = int(
        df["is_anomaly"].sum()
    )

    total = len(df)

    fraction = (
        anomaly_count / total
        if total
        else 0
    )

    print()
    print(
        f"{name.upper()}"
    )
    print("-" * 70)

    print(
        f"Windows           : {total}"
    )

    print(
        f"Sessions          : "
        f"{df['session_id'].nunique()}"
    )

    print(
        f"Anomalous windows : "
        f"{anomaly_count}"
    )

    print(
        f"Anomaly fraction  : "
        f"{fraction:.2%}"
    )

    print(
        f"Mean score        : "
        f"{df['anomaly_score'].mean():.6f}"
    )

    print(
        f"Median score      : "
        f"{df['anomaly_score'].median():.6f}"
    )


def print_group_analysis(
    df,
    column,
    title,
):
    """
    Show anomaly statistics grouped by a metadata field.
    """

    print()
    print("=" * 70)
    print(title)
    print("=" * 70)

    result = (
        df.groupby(column)
        .agg(
            sessions=(
                "session_id",
                "nunique",
            ),

            windows=(
                "is_anomaly",
                "count",
            ),

            anomalous_windows=(
                "is_anomaly",
                "sum",
            ),

            mean_score=(
                "anomaly_score",
                "mean",
            ),

            median_score=(
                "anomaly_score",
                "median",
            ),
        )
        .reset_index()
    )

    result["anomaly_fraction"] = (
        result["anomalous_windows"]
        / result["windows"]
    )

    result = result.sort_values(
        "anomaly_fraction",
        ascending=False,
    )

    print(
        result.to_string(
            index=False,
            formatters={
                "mean_score": "{:.6f}".format,
                "median_score": "{:.6f}".format,
                "anomaly_fraction": "{:.2%}".format,
            },
        )
    )


# ---------------------------------------------------------------------
# Feature score analysis
# ---------------------------------------------------------------------

def print_score_distribution(
    df,
    name,
):
    """Print detailed score distribution."""

    scores = df[
        "anomaly_score"
    ]

    print()
    print(
        f"{name.upper()} SCORE DISTRIBUTION"
    )
    print("-" * 70)

    print(
        f"Min     : {scores.min():.6f}"
    )

    print(
        f"P25     : {scores.quantile(.25):.6f}"
    )

    print(
        f"Median  : {scores.median():.6f}"
    )

    print(
        f"P75     : {scores.quantile(.75):.6f}"
    )

    print(
        f"P90     : {scores.quantile(.90):.6f}"
    )

    print(
        f"P95     : {scores.quantile(.95):.6f}"
    )

    print(
        f"P99     : {scores.quantile(.99):.6f}"
    )

    print(
        f"Max     : {scores.max():.6f}"
    )


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():

    print("=" * 70)
    print("ESP BEHAVIORAL MODEL EVALUATION")
    print("=" * 70)

    # ---------------------------------------------------------------
    # Load
    # ---------------------------------------------------------------

    windows = load_window_dataset()

    manifest = load_manifest()

    model, scaler = load_model()

    print(
        f"[OK] Loaded {len(windows)} windows"
    )

    print(
        f"[OK] Loaded {len(manifest)} manifest records"
    )

    # ---------------------------------------------------------------
    # Verify manifest/session correspondence
    # ---------------------------------------------------------------

    window_sessions = set(
        windows["session_id"]
    )

    manifest_sessions = set(
        manifest["session_id"]
    )

    missing_from_manifest = (
        window_sessions
        - manifest_sessions
    )

    missing_from_windows = (
        manifest_sessions
        - window_sessions
    )

    if missing_from_manifest:
        raise RuntimeError(
            "Sessions missing from manifest:\n"
            + "\n".join(
                sorted(missing_from_manifest)
            )
        )

    if missing_from_windows:
        print(
            "[WARNING] Manifest contains sessions "
            "without window data:"
        )

        for session in sorted(
            missing_from_windows
        ):
            print(
                f"  - {session}"
            )

    print(
        "[OK] Window sessions matched to manifest"
    )

    # ---------------------------------------------------------------
    # Score all windows
    # ---------------------------------------------------------------

    scores = score_windows(
        windows,
        model,
        scaler,
    )

    # ---------------------------------------------------------------
    # Attach metadata
    # ---------------------------------------------------------------

    metadata_columns = [
        "session_id",
        "pcap",
        "mode",
        "cipher_suite",
        "dh_group",
        "pfs",
        "traffic_class",
        "capture_id",
    ]

    scores = scores.merge(
        manifest[metadata_columns],
        on="session_id",
        how="left",
        validate="many_to_one",
    )

    # ---------------------------------------------------------------
    # Recreate the exact session split used during training
    # ---------------------------------------------------------------

    (
        train_df,
        validation_df,
        test_df,
    ) = split_by_session(
        windows
    )

    train_sessions = set(
        train_df["session_id"]
    )

    validation_sessions = set(
        validation_df["session_id"]
    )

    test_sessions = set(
        test_df["session_id"]
    )

    scores["split"] = "unknown"

    scores.loc[
        scores["session_id"].isin(
            train_sessions
        ),
        "split",
    ] = "train"

    scores.loc[
        scores["session_id"].isin(
            validation_sessions
        ),
        "split",
    ] = "validation"

    scores.loc[
        scores["session_id"].isin(
            test_sessions
        ),
        "split",
    ] = "test"

    if (
        scores["split"] == "unknown"
    ).any():
        raise RuntimeError(
            "Some sessions were not assigned "
            "to train/validation/test."
        )

    # ---------------------------------------------------------------
    # Save window-level results
    # ---------------------------------------------------------------

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    scores.to_csv(
        WINDOW_SCORES_PATH,
        index=False,
    )

    # ---------------------------------------------------------------
    # Session-level results
    # ---------------------------------------------------------------

    session_scores = aggregate_sessions(
        scores
    )

    session_metadata = manifest[
        metadata_columns
    ].drop_duplicates(
        "session_id"
    )

    session_scores = session_scores.merge(
        session_metadata,
        on="session_id",
        how="left",
        validate="one_to_one",
    )

    session_scores["split"] = (
        session_scores["session_id"]
        .map(
            lambda x:
                "train"
                if x in train_sessions
                else (
                    "validation"
                    if x in validation_sessions
                    else "test"
                )
        )
    )

    session_scores.to_csv(
        SESSION_SCORES_PATH,
        index=False,
    )

    # ---------------------------------------------------------------
    # Overall split analysis
    # ---------------------------------------------------------------

    for split_name in [
        "train",
        "validation",
        "test",
    ]:

        split_data = scores[
            scores["split"] == split_name
        ]

        print_split_summary(
            split_name,
            split_data,
        )

        print_score_distribution(
            split_data,
            split_name,
        )

    # ---------------------------------------------------------------
    # Metadata analysis
    # ---------------------------------------------------------------

    print_group_analysis(
        scores,
        "traffic_class",
        "ANOMALY RATE BY TRAFFIC CLASS",
    )

    print_group_analysis(
        scores,
        "mode",
        "ANOMALY RATE BY VPN MODE",
    )

    print_group_analysis(
        scores,
        "cipher_suite",
        "ANOMALY RATE BY CIPHER",
    )

    print_group_analysis(
        scores,
        "dh_group",
        "ANOMALY RATE BY DH GROUP",
    )

    print_group_analysis(
        scores,
        "pfs",
        "ANOMALY RATE BY PFS",
    )

    # ---------------------------------------------------------------
    # Split × traffic class
    # ---------------------------------------------------------------

    print()
    print("=" * 70)
    print("ANOMALY RATE BY SPLIT AND TRAFFIC CLASS")
    print("=" * 70)

    cross = (
        scores.groupby(
            ["split", "traffic_class"]
        )
        .agg(
            windows=(
                "is_anomaly",
                "count",
            ),
            anomalies=(
                "is_anomaly",
                "sum",
            ),
            mean_score=(
                "anomaly_score",
                "mean",
            ),
        )
        .reset_index()
    )

    cross["anomaly_fraction"] = (
        cross["anomalies"]
        / cross["windows"]
    )

    print(
        cross.to_string(
            index=False,
            formatters={
                "mean_score": "{:.6f}".format,
                "anomaly_fraction": "{:.2%}".format,
            },
        )
    )

    # ---------------------------------------------------------------
    # Split × VPN mode
    # ---------------------------------------------------------------

    print()
    print("=" * 70)
    print("ANOMALY RATE BY SPLIT AND VPN MODE")
    print("=" * 70)

    cross_mode = (
        scores.groupby(
            ["split", "mode"]
        )
        .agg(
            windows=(
                "is_anomaly",
                "count",
            ),
            anomalies=(
                "is_anomaly",
                "sum",
            ),
            mean_score=(
                "anomaly_score",
                "mean",
            ),
        )
        .reset_index()
    )

    cross_mode["anomaly_fraction"] = (
        cross_mode["anomalies"]
        / cross_mode["windows"]
    )

    print(
        cross_mode.to_string(
            index=False,
            formatters={
                "mean_score": "{:.6f}".format,
                "anomaly_fraction": "{:.2%}".format,
            },
        )
    )

    # ---------------------------------------------------------------
    # Highest scoring sessions
    # ---------------------------------------------------------------

    print()
    print("=" * 70)
    print("TOP 10 MOST ANOMALOUS SESSIONS")
    print("=" * 70)

    top_sessions = (
        session_scores
        .sort_values(
            "max_anomaly_score",
            ascending=False,
        )
        .head(10)
    )

    print(
        top_sessions[
            [
                "session_id",
                "traffic_class",
                "mode",
                "cipher_suite",
                "dh_group",
                "pfs",
                "split",
                "windows",
                "anomalous_windows",
                "anomaly_fraction",
                "mean_anomaly_score",
                "max_anomaly_score",
            ]
        ].to_string(
            index=False,
            formatters={
                "anomaly_fraction":
                    "{:.2%}".format,
                "mean_anomaly_score":
                    "{:.6f}".format,
                "max_anomaly_score":
                    "{:.6f}".format,
            },
        )
    )

    # ---------------------------------------------------------------
    # Output
    # ---------------------------------------------------------------

    print()
    print("=" * 70)
    print("EVALUATION OUTPUT")
    print("=" * 70)

    print(
        f"Window scores  : {WINDOW_SCORES_PATH}"
    )

    print(
        f"Session scores : {SESSION_SCORES_PATH}"
    )

    print()
    print("[+] Evaluation complete.")


if __name__ == "__main__":
    main()