from pathlib import Path

import pandas as pd

from ml.feature_config import MODEL_FEATURES


SCORES_PATH = Path("ml/evaluation/window_scores.csv")
WINDOWS_DIR = Path("data/features/windows")


def section(title):
    print()
    print("=" * 90)
    print(title)
    print("=" * 90)


def load_behavioral_windows():
    """Load all extracted behavioral windows."""

    files = sorted(WINDOWS_DIR.glob("*.parquet"))

    if not files:
        raise FileNotFoundError(
            f"No Parquet files found in: {WINDOWS_DIR}"
        )

    frames = []

    for path in files:
        frame = pd.read_parquet(path)
        frames.append(frame)

    windows = pd.concat(
        frames,
        ignore_index=True,
    )

    return windows


def main():

    # ============================================================
    # 1. LOAD MODEL SCORES
    # ============================================================

    scores = pd.read_csv(SCORES_PATH)

    print(f"Score windows: {len(scores)}")
    print(
        f"Score sessions: "
        f"{scores['session_id'].nunique()}"
    )

    # ============================================================
    # 2. LOAD ORIGINAL BEHAVIORAL WINDOWS
    # ============================================================

    windows = load_behavioral_windows()

    print(
        f"Behavioral windows: "
        f"{len(windows)}"
    )

    print(
        f"Behavioral sessions: "
        f"{windows['session_id'].nunique()}"
    )

    # ============================================================
    # 3. CHECK REQUIRED JOIN COLUMNS
    # ============================================================

    required_columns = [
        "session_id",
        "window_index",
    ]

    for column in required_columns:

        if column not in scores.columns:
            raise RuntimeError(
                f"'{column}' missing from "
                f"{SCORES_PATH}"
            )

        if column not in windows.columns:
            raise RuntimeError(
                f"'{column}' missing from "
                f"behavioral Parquet files"
            )

    # ============================================================
    # 4. NORMALIZE JOIN KEYS
    # ============================================================
    #
    # IMPORTANT:
    # session_id MUST remain a string.
    #
    # Only window_index is converted to numeric.
    #

    scores["session_id"] = (
        scores["session_id"]
        .astype(str)
        .str.strip()
    )

    windows["session_id"] = (
        windows["session_id"]
        .astype(str)
        .str.strip()
    )

    scores["window_index"] = pd.to_numeric(
        scores["window_index"],
        errors="coerce",
    )

    windows["window_index"] = pd.to_numeric(
        windows["window_index"],
        errors="coerce",
    )

    # ============================================================
    # 5. REMOVE INVALID JOIN KEYS
    # ============================================================

    scores = scores.dropna(
        subset=[
            "session_id",
            "window_index",
        ]
    ).copy()

    windows = windows.dropna(
        subset=[
            "session_id",
            "window_index",
        ]
    ).copy()

    # ============================================================
    # 6. CHECK FOR DUPLICATE WINDOWS
    # ============================================================

    score_duplicates = scores.duplicated(
        subset=[
            "session_id",
            "window_index",
        ],
        keep=False,
    )

    window_duplicates = windows.duplicated(
        subset=[
            "session_id",
            "window_index",
        ],
        keep=False,
    )

    if score_duplicates.any():

        duplicates = scores.loc[
            score_duplicates,
            [
                "session_id",
                "window_index",
            ],
        ]

        print()
        print(
            "ERROR: Duplicate windows found "
            "in window_scores.csv:"
        )

        print(
            duplicates.head(20)
            .to_string(index=False)
        )

        raise RuntimeError(
            "window_scores.csv contains duplicate "
            "(session_id, window_index) pairs."
        )

    if window_duplicates.any():

        duplicates = windows.loc[
            window_duplicates,
            [
                "session_id",
                "window_index",
            ],
        ]

        print()
        print(
            "ERROR: Duplicate windows found "
            "in behavioral Parquet files:"
        )

        print(
            duplicates.head(20)
            .to_string(index=False)
        )

        raise RuntimeError(
            "Behavioral Parquet files contain duplicate "
            "(session_id, window_index) pairs."
        )

    # ============================================================
    # 7. JOIN SCORES WITH BEHAVIORAL FEATURES
    # ============================================================

    score_columns = [
        "session_id",
        "window_index",
        "anomaly_score",
        "is_anomaly",
    ]

    df = windows.merge(
        scores[score_columns],
        on=[
            "session_id",
            "window_index",
        ],
        how="inner",
        validate="one_to_one",
    )

    print(
        f"Joined windows: {len(df)}"
    )

    # ============================================================
    # 8. VERIFY COMPLETE JOIN
    # ============================================================

    if len(df) != len(scores):

        print()
        print(
            "WARNING: Not every scored window "
            "matched a behavioral window."
        )

        print(
            f"Score rows: {len(scores)}"
        )

        print(
            f"Joined rows: {len(df)}"
        )

        # Find missing score rows.
        missing_scores = scores.merge(
            windows[
                [
                    "session_id",
                    "window_index",
                ]
            ],
            on=[
                "session_id",
                "window_index",
            ],
            how="left",
            indicator=True,
        )

        missing_scores = missing_scores[
            missing_scores["_merge"] == "left_only"
        ]

        if not missing_scores.empty:

            print()
            print(
                "Example unmatched score rows:"
            )

            print(
                missing_scores[
                    [
                        "session_id",
                        "window_index",
                    ]
                ]
                .head(20)
                .to_string(index=False)
            )

        raise RuntimeError(
            "Some scored windows could not be "
            "matched with behavioral windows."
        )

    # ============================================================
    # 9. GET MODEL FEATURES
    # ============================================================

    FEATURES = [
        feature
        for feature in MODEL_FEATURES
        if feature in df.columns
    ]

    missing_features = [
        feature
        for feature in MODEL_FEATURES
        if feature not in df.columns
    ]

    print(
        f"Model features found: "
        f"{len(FEATURES)}"
    )

    if missing_features:

        print()
        print(
            "WARNING: Missing model features:"
        )

        for feature in missing_features:
            print(
                f"  - {feature}"
            )

    if not FEATURES:

        raise RuntimeError(
            "No model behavioral features "
            "were found."
        )

    # ============================================================
    # 10. RESTORE EVALUATION METADATA
    # ============================================================

    metadata_columns = [
        "traffic_class",
        "dh_group",
        "mode",
        "cipher_suite",
        "pfs",
    ]

    metadata_to_add = [
        column
        for column in metadata_columns
        if column in scores.columns
    ]

    for column in metadata_to_add:

        # If behavioral Parquet already contains the
        # column, don't create duplicate _x/_y columns.
        if column in df.columns:
            continue

        metadata = scores[
            [
                "session_id",
                "window_index",
                column,
            ]
        ]

        df = df.merge(
            metadata,
            on=[
                "session_id",
                "window_index",
            ],
            how="left",
            validate="one_to_one",
        )

    # ============================================================
    # 11. BASIC DATASET CHECK
    # ============================================================

    print()
    print(
        f"Final analysis rows: {len(df)}"
    )

    print(
        f"Final analysis sessions: "
        f"{df['session_id'].nunique()}"
    )

    # ============================================================
    # 12. FEATURE MEANS BY TRAFFIC CLASS
    # ============================================================

    section(
        "FEATURE MEANS BY TRAFFIC CLASS"
    )

    means = (
        df.groupby("traffic_class")[FEATURES]
        .mean()
        .T
    )

    print(
        means
        .round(4)
        .to_string()
    )

    # ============================================================
    # 13. FILE TRANSFER VS OTHER TRAFFIC
    # ============================================================

    section(
        "FILE TRANSFER vs OTHER TRAFFIC"
    )

    df["traffic_group"] = (
        df["traffic_class"]
        .eq("file_transfer")
        .map(
            {
                True: "file_transfer",
                False: "other_traffic",
            }
        )
    )

    comparison = (
        df.groupby("traffic_group")[FEATURES]
        .mean()
        .T
    )

    comparison["absolute_difference"] = (
        comparison["file_transfer"]
        - comparison["other_traffic"]
    ).abs()

    comparison = comparison.sort_values(
        "absolute_difference",
        ascending=False,
    )

    print(
        comparison
        .round(4)
        .to_string()
    )

    # ============================================================
    # 14. STANDARDIZED FEATURE DIFFERENCE
    # ============================================================

    section(
        "FEATURE SEPARATION: "
        "FILE TRANSFER vs OTHER"
    )

    file_df = df[
        df["traffic_group"]
        == "file_transfer"
    ]

    other_df = df[
        df["traffic_group"]
        == "other_traffic"
    ]

    rows = []

    for feature in FEATURES:

        file_mean = (
            file_df[feature]
            .mean()
        )

        other_mean = (
            other_df[feature]
            .mean()
        )

        file_std = (
            file_df[feature]
            .std()
        )

        other_std = (
            other_df[feature]
            .std()
        )

        pooled_std = (
            (
                file_std ** 2
                + other_std ** 2
            )
            / 2
        ) ** 0.5

        if pooled_std > 0:

            standardized_difference = (
                abs(
                    file_mean
                    - other_mean
                )
                / pooled_std
            )

        else:

            standardized_difference = 0.0

        rows.append(
            {
                "feature": feature,
                "file_mean": file_mean,
                "other_mean": other_mean,
                "standardized_difference":
                    standardized_difference,
            }
        )

    separation = (
        pd.DataFrame(rows)
        .sort_values(
            "standardized_difference",
            ascending=False,
        )
    )

    print(
        separation
        .round(4)
        .to_string(index=False)
    )

    # ============================================================
    # 15. ANOMALOUS VS NORMAL WINDOWS
    # ============================================================

    section(
        "ANOMALOUS vs NORMAL WINDOWS"
    )

    # Make sure is_anomaly is boolean.
    df["is_anomaly"] = (
        df["is_anomaly"]
        .astype(bool)
    )

    anomaly_comparison = (
        df.groupby("is_anomaly")[FEATURES]
        .mean()
        .T
    )

    # Explicitly handle boolean columns.
    if True in anomaly_comparison.columns:
        anomaly_comparison = (
            anomaly_comparison.rename(
                columns={
                    True: "anomalous"
                }
            )
        )

    if False in anomaly_comparison.columns:
        anomaly_comparison = (
            anomaly_comparison.rename(
                columns={
                    False: "normal"
                }
            )
        )

    if (
        "normal"
        in anomaly_comparison.columns
        and
        "anomalous"
        in anomaly_comparison.columns
    ):

        anomaly_comparison[
            "absolute_difference"
        ] = (
            anomaly_comparison[
                "anomalous"
            ]
            - anomaly_comparison[
                "normal"
            ]
        ).abs()

        anomaly_comparison = (
            anomaly_comparison
            .sort_values(
                "absolute_difference",
                ascending=False,
            )
        )

    print(
        anomaly_comparison
        .round(4)
        .to_string()
    )

    # ============================================================
    # 16. TOP 20 ANOMALOUS WINDOWS
    # ============================================================

    section(
        "TOP 20 ANOMALOUS WINDOWS — "
        "FEATURE VALUES"
    )

    top = (
        df.sort_values(
            "anomaly_score",
            ascending=False,
        )
        .head(20)
    )

    metadata = [
        "session_id",
        "traffic_class",
        "dh_group",
        "mode",
        "cipher_suite",
        "pfs",
        "window_index",
        "anomaly_score",
        "is_anomaly",
    ]

    available_metadata = [
        column
        for column in metadata
        if column in top.columns
    ]

    print(
        top[
            available_metadata
            + FEATURES
        ]
        .round(4)
        .to_string(index=False)
    )


if __name__ == "__main__":
    main()