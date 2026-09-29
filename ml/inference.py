"""
ESP Behavioral Inference
-------------------------

Loads the trained Isolation Forest and RobustScaler and performs
anomaly detection on ESP behavioral windows.

Input:
    Behavioral feature DataFrame containing the frozen MODEL_FEATURES.

Output:
    DataFrame containing:
        session_id
        window_index
        anomaly_score
        prediction
        is_anomaly

Important:
    - Only behavioral features are passed to the model.
    - Metadata is NOT passed to the model.
    - The same RobustScaler fitted during training is used.
    - Higher anomaly_score = more anomalous.
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from .feature_config import MODEL_FEATURES
from .train import prepare_features, transform_features


# ---------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------

MODEL_PATH = Path(
    "ml/models/isolation_forest.joblib"
)

SCALER_PATH = Path(
    "ml/models/behavior_scaler.joblib"
)


# ---------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------

def load_model():
    """
    Load the trained Isolation Forest and RobustScaler.

    Returns:
        model: trained Isolation Forest
        scaler: RobustScaler fitted on training data
    """

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Isolation Forest model not found: {MODEL_PATH}"
        )

    if not SCALER_PATH.exists():
        raise FileNotFoundError(
            f"Behavior scaler not found: {SCALER_PATH}"
        )

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    return model, scaler


# ---------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------

def validate_input(df: pd.DataFrame) -> None:
    """
    Validate that the input DataFrame contains all required
    behavioral model features.
    """

    if df.empty:
        raise ValueError(
            "Input DataFrame is empty."
        )

    missing_features = [
        feature
        for feature in MODEL_FEATURES
        if feature not in df.columns
    ]

    if missing_features:
        raise ValueError(
            "Missing required model features:\n"
            + "\n".join(
                f"  - {feature}"
                for feature in missing_features
            )
        )


# ---------------------------------------------------------------------
# Window inference
# ---------------------------------------------------------------------

def predict_windows(
    df: pd.DataFrame,
    model=None,
    scaler=None,
) -> pd.DataFrame:
    """
    Run anomaly detection on behavioral ESP windows.

    Args:
        df:
            DataFrame containing one or more 1-second ESP windows.

        model:
            Optional pre-loaded Isolation Forest.

        scaler:
            Optional pre-loaded RobustScaler.

    Returns:
        DataFrame containing the original window identifiers plus:

            anomaly_score
            prediction
            is_anomaly

    Notes:
        sklearn Isolation Forest:
            prediction = 1   -> normal
            prediction = -1  -> anomaly

        anomaly_score is negated so:
            higher score -> more anomalous
    """

    validate_input(df)

    # Load model/scaler if not supplied.
    if model is None or scaler is None:
        model, scaler = load_model()

    # -------------------------------------------------------------
    # Prepare exactly the same features used during training.
    # -------------------------------------------------------------

    X = prepare_features(df)

    # -------------------------------------------------------------
    # Apply the scaler fitted during training.
    # -------------------------------------------------------------

    X_scaled = transform_features(
        scaler,
        X,
    )

    # -------------------------------------------------------------
    # Calculate anomaly score.
    #
    # sklearn:
    #     higher score_samples() = more normal
    #
    # We negate it:
    #     higher anomaly_score = more anomalous
    # -------------------------------------------------------------

    anomaly_scores = -model.score_samples(
        X_scaled
    )

    # -------------------------------------------------------------
    # Isolation Forest prediction.
    #
    #  1  = normal
    # -1  = anomaly
    # -------------------------------------------------------------

    predictions = model.predict(
        X_scaled
    )

    # -------------------------------------------------------------
    # Build result.
    # -------------------------------------------------------------

    result_columns = []

    for column in [
        "session_id",
        "window_index",
        "window_start",
        "window_end",
    ]:
        if column in df.columns:
            result_columns.append(column)

    result = df[
        result_columns
    ].copy()

    result["anomaly_score"] = anomaly_scores

    result["prediction"] = predictions

    result["is_anomaly"] = (
        predictions == -1
    )

    return result


# ---------------------------------------------------------------------
# Session-level inference
# ---------------------------------------------------------------------

def aggregate_session(
    window_results: pd.DataFrame,
) -> pd.DataFrame:
    """
    Aggregate window-level anomaly results into session-level results.

    The session retains multiple score statistics instead of reducing
    everything to one number.
    """

    if window_results.empty:
        raise ValueError(
            "Cannot aggregate an empty inference result."
        )

    if "session_id" not in window_results.columns:
        raise ValueError(
            "session_id is required for session aggregation."
        )

    grouped = (
        window_results
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
# Convenience function
# ---------------------------------------------------------------------

def analyze(
    df: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Run complete behavioral inference.

    Returns:
        window_results:
            One row per behavioral window.

        session_results:
            One row per session.
    """

    model, scaler = load_model()

    window_results = predict_windows(
        df,
        model=model,
        scaler=scaler,
    )

    session_results = aggregate_session(
        window_results
    )

    return (
        window_results,
        session_results,
    )


# ---------------------------------------------------------------------
# Command-line test
# ---------------------------------------------------------------------

def main():
    """
    Simple CLI test.

    Loads all behavioral Parquet files, runs inference, and prints
    the resulting statistics.
    """

    windows_dir = Path(
        "data/features/windows"
    )

    parquet_files = sorted(
        windows_dir.glob("*.parquet")
    )

    if not parquet_files:
        raise FileNotFoundError(
            f"No Parquet files found in: {windows_dir}"
        )

    print("=" * 70)
    print("ESP BEHAVIORAL INFERENCE")
    print("=" * 70)

    # -------------------------------------------------------------
    # Load all behavioral windows.
    # -------------------------------------------------------------

    frames = []

    for path in parquet_files:
        frame = pd.read_parquet(path)
        frames.append(frame)

    df = pd.concat(
        frames,
        ignore_index=True,
    )

    print(
        f"Loaded windows : {len(df)}"
    )

    print(
        f"Loaded sessions: "
        f"{df['session_id'].nunique()}"
    )

    # -------------------------------------------------------------
    # Run inference.
    # -------------------------------------------------------------

    window_results, session_results = analyze(
        df
    )

    # -------------------------------------------------------------
    # Print summary.
    # -------------------------------------------------------------

    anomaly_count = int(
        window_results["is_anomaly"].sum()
    )

    total_windows = len(
        window_results
    )

    anomaly_fraction = (
        anomaly_count / total_windows
        if total_windows
        else 0
    )

    print()
    print("=" * 70)
    print("RESULT")
    print("=" * 70)

    print(
        f"Windows           : {total_windows}"
    )

    print(
        f"Anomalous windows : {anomaly_count}"
    )

    print(
        f"Anomaly fraction  : "
        f"{anomaly_fraction:.2%}"
    )

    print(
        f"Mean score        : "
        f"{window_results['anomaly_score'].mean():.6f}"
    )

    print(
        f"Median score      : "
        f"{window_results['anomaly_score'].median():.6f}"
    )

    print(
        f"Max score         : "
        f"{window_results['anomaly_score'].max():.6f}"
    )

    # -------------------------------------------------------------
    # Print top anomalous windows.
    # -------------------------------------------------------------

    print()
    print("=" * 70)
    print("TOP 10 ANOMALOUS WINDOWS")
    print("=" * 70)

    top = (
        window_results
        .sort_values(
            "anomaly_score",
            ascending=False,
        )
        .head(10)
    )

    print(
        top.to_string(
            index=False
        )
    )

    # -------------------------------------------------------------
    # Print session summary.
    # -------------------------------------------------------------

    print()
    print("=" * 70)
    print("SESSION SUMMARY")
    print("=" * 70)

    print(
        session_results
        .sort_values(
            "mean_anomaly_score",
            ascending=False,
        )
        .head(20)
        .to_string(
            index=False
        )
    )


if __name__ == "__main__":
    main()