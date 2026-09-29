"""
Diagnostic analysis for ESP behavioral window features.

Loads all window Parquet files and checks:
- Dataset size
- Missing values
- Constant / near-constant features
- Duplicate windows
- Highly correlated features
- Highly skewed features
- Extreme values
- Per-session behavioral variation
- Feature ranges

This script does NOT modify the dataset.
"""

from pathlib import Path
import glob

import numpy as np
import pandas as pd


WINDOW_DIR = Path("data/features/windows")

# Metadata columns that should never be used as ML features.
METADATA_COLUMNS = {
    "session_id",
    "window_index",
    "window_start",
    "window_end",
}

# We need enough variation to consider a feature useful for ML.
NEAR_CONSTANT_THRESHOLD = 0.995

# Correlation threshold for identifying redundant features.
HIGH_CORRELATION_THRESHOLD = 0.98


def load_windows() -> pd.DataFrame:
    """Load all window Parquet files."""
    files = sorted(WINDOW_DIR.glob("*.parquet"))

    if not files:
        raise FileNotFoundError(
            f"No Parquet files found in {WINDOW_DIR}"
        )

    print(f"[+] Found {len(files)} window files")

    frames = []

    for file in files:
        df = pd.read_parquet(file)

        # Preserve the source file so we can trace unusual rows.
        df["_source_file"] = file.name

        frames.append(df)

    combined = pd.concat(frames, ignore_index=True)

    return combined


def get_feature_columns(df: pd.DataFrame):
    """Return numeric behavioral features only."""
    excluded = METADATA_COLUMNS | {"_source_file"}

    columns = []

    for column in df.columns:
        if column in excluded:
            continue

        if pd.api.types.is_numeric_dtype(df[column]):
            columns.append(column)

    return columns


def check_missing(df: pd.DataFrame):
    print("\n" + "=" * 70)
    print("1. MISSING VALUES")
    print("=" * 70)

    missing = df.isna().sum()
    missing = missing[missing > 0]

    if missing.empty:
        print("[OK] No missing values")
    else:
        print(missing.to_string())


def check_constant_features(df: pd.DataFrame, features):
    print("\n" + "=" * 70)
    print("2. CONSTANT / NEAR-CONSTANT FEATURES")
    print("=" * 70)

    constant = []
    near_constant = []

    for feature in features:
        counts = df[feature].value_counts(dropna=False)

        if len(counts) <= 1:
            constant.append(feature)
            continue

        dominant_fraction = counts.iloc[0] / len(df)

        if dominant_fraction >= NEAR_CONSTANT_THRESHOLD:
            near_constant.append(
                (feature, dominant_fraction)
            )

    if not constant:
        print("[OK] No constant features")
    else:
        print("[WARNING] Constant features:")
        for feature in constant:
            print(f"  - {feature}")

    if not near_constant:
        print("[OK] No near-constant features")
    else:
        print("[WARNING] Near-constant features:")
        for feature, fraction in near_constant:
            print(f"  - {feature}: {fraction:.4%}")


def check_duplicates(df: pd.DataFrame, features):
    print("\n" + "=" * 70)
    print("3. DUPLICATE WINDOWS")
    print("=" * 70)

    duplicate_count = df.duplicated(
        subset=features,
        keep=False,
    ).sum()

    exact_duplicate_count = df.duplicated(
        subset=features,
        keep="first",
    ).sum()

    print(f"Rows with duplicate feature vectors : {duplicate_count}")
    print(f"Duplicate rows after first occurrence: {exact_duplicate_count}")

    if exact_duplicate_count == 0:
        print("[OK] No duplicate behavioral windows")
    else:
        print(
            "[INFO] Duplicate behavioral vectors exist. "
            "This is not necessarily an error, but we should inspect them."
        )


def check_correlations(df: pd.DataFrame, features):
    print("\n" + "=" * 70)
    print("4. HIGHLY CORRELATED FEATURES")
    print("=" * 70)

    correlation = df[features].corr().abs()

    pairs = []

    for i in range(len(features)):
        for j in range(i + 1, len(features)):
            value = correlation.iloc[i, j]

            if value >= HIGH_CORRELATION_THRESHOLD:
                pairs.append(
                    (
                        features[i],
                        features[j],
                        value,
                    )
                )

    pairs.sort(key=lambda x: x[2], reverse=True)

    if not pairs:
        print("[OK] No feature pairs above "
              f"{HIGH_CORRELATION_THRESHOLD:.2f} correlation")
    else:
        print(f"Found {len(pairs)} highly correlated pairs:")

        for feature_a, feature_b, value in pairs:
            print(
                f"  {feature_a:<25} "
                f"{feature_b:<25} "
                f"{value:.4f}"
            )


def check_skew(df: pd.DataFrame, features):
    print("\n" + "=" * 70)
    print("5. FEATURE SKEW")
    print("=" * 70)

    skew = df[features].skew().sort_values(
        key=lambda x: x.abs(),
        ascending=False,
    )

    print(
        f"{'Feature':<30} {'Skew':>12}"
    )
    print("-" * 45)

    for feature, value in skew.items():
        print(
            f"{feature:<30} {value:>12.4f}"
        )

    print(
        "\n[INFO] Large positive/negative skew is not automatically a problem "
        "for Isolation Forest."
    )


def check_extremes(df: pd.DataFrame, features):
    print("\n" + "=" * 70)
    print("6. EXTREME VALUES")
    print("=" * 70)

    for feature in features:
        series = df[feature]

        q1 = series.quantile(0.25)
        q3 = series.quantile(0.75)
        iqr = q3 - q1

        if iqr == 0:
            continue

        lower = q1 - 3 * iqr
        upper = q3 + 3 * iqr

        extreme_count = (
            (series < lower) |
            (series > upper)
        ).sum()

        if extreme_count > 0:
            print(
                f"{feature:<30} "
                f"{extreme_count:>5} extreme rows "
                f"(lower={lower:.4g}, upper={upper:.4g})"
            )


def check_session_variation(df: pd.DataFrame, features):
    print("\n" + "=" * 70)
    print("7. WITHIN-SESSION BEHAVIORAL VARIATION")
    print("=" * 70)

    session_count = df["session_id"].nunique()

    print(f"Unique sessions: {session_count}")

    variation_records = []

    for feature in features:
        grouped = df.groupby("session_id")[feature]

        session_ranges = grouped.max() - grouped.min()

        sessions_with_variation = (
            session_ranges > 0
        ).sum()

        fraction = (
            sessions_with_variation / session_count
        )

        variation_records.append(
            (
                feature,
                sessions_with_variation,
                fraction,
                session_ranges.mean(),
            )
        )

    variation_records.sort(
        key=lambda x: x[2],
        reverse=True,
    )

    print(
        f"{'Feature':<30} "
        f"{'Sessions varying':>17} "
        f"{'Fraction':>12} "
        f"{'Mean range':>15}"
    )

    print("-" * 80)

    for feature, count, fraction, mean_range in variation_records:
        print(
            f"{feature:<30} "
            f"{count:>17} "
            f"{fraction:>11.2%} "
            f"{mean_range:>15.4g}"
        )


def check_window_counts(df: pd.DataFrame):
    print("\n" + "=" * 70)
    print("8. WINDOWS PER SESSION")
    print("=" * 70)

    counts = df.groupby("session_id").size()

    print(counts.describe().to_string())

    print("\nDistribution:")

    distribution = counts.value_counts().sort_index()

    for windows, count in distribution.items():
        print(
            f"  {windows} windows: {count} sessions"
        )


def print_feature_ranges(df: pd.DataFrame, features):
    print("\n" + "=" * 70)
    print("9. FEATURE RANGES")
    print("=" * 70)

    summary = df[features].describe().T

    print(
        summary[
            ["min", "25%", "50%", "75%", "max"]
        ].to_string()
    )


def check_metadata(df: pd.DataFrame):
    print("\n" + "=" * 70)
    print("10. METADATA")
    print("=" * 70)

    print(f"Total rows       : {len(df)}")
    print(f"Unique sessions  : {df['session_id'].nunique()}")
    print(f"Source files     : {df['_source_file'].nunique()}")

    print(
        "\nMetadata columns excluded from ML:"
    )

    for column in sorted(METADATA_COLUMNS):
        if column in df.columns:
            print(f"  - {column}")


def main():
    print("=" * 70)
    print("ESP WINDOW DATASET DIAGNOSTICS")
    print("=" * 70)

    df = load_windows()

    features = get_feature_columns(df)

    print(f"\nTotal rows: {len(df)}")
    print(f"Behavioral features: {len(features)}")

    check_metadata(df)
    check_missing(df)
    check_constant_features(df, features)
    check_duplicates(df, features)
    check_correlations(df, features)
    check_skew(df, features)
    check_extremes(df, features)
    check_session_variation(df, features)
    check_window_counts(df)
    print_feature_ranges(df, features)

    print("\n" + "=" * 70)
    print("DIAGNOSTICS COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()