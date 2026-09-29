"""
Train the ESP behavioral Isolation Forest.

Important:
- Splitting is performed at SESSION level.
- Windows from the same PCAP never cross train/test boundaries.
- Preprocessing is fitted only on the training set.
- The trained model and metadata are saved for inference.
"""

from pathlib import Path
import json
import logging

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from .feature_config import (
    MODEL_FEATURES,
    validate_feature_columns,
)


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

WINDOW_DIR = Path("data/features/windows")
MODEL_DIR = Path("ml/models")

MODEL_PATH = MODEL_DIR / "isolation_forest.joblib"
SCALER_PATH = MODEL_DIR / "behavior_scaler.joblib"
METADATA_PATH = MODEL_DIR / "training_metadata.json"

# Session-level split.
TRAIN_RATIO = 0.70
VALIDATION_RATIO = 0.15
TEST_RATIO = 0.15

# Reproducibility.
RANDOM_STATE = 42

# Isolation Forest configuration.
N_ESTIMATORS = 300
CONTAMINATION = 0.05
MAX_SAMPLES = "auto"

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------

def load_window_dataset():
    """
    Load all ESP behavioral windows.

    Returns:
        DataFrame containing all windows.
    """

    files = sorted(WINDOW_DIR.glob("*.parquet"))

    if not files:
        raise FileNotFoundError(
            f"No window Parquet files found in {WINDOW_DIR}"
        )

    logger.info("Found %d window files", len(files))

    frames = []

    for file in files:
        df = pd.read_parquet(file)

        if "session_id" not in df.columns:
            raise ValueError(
                f"{file.name} does not contain session_id"
            )

        df["_source_file"] = file.name

        frames.append(df)

    dataset = pd.concat(
        frames,
        ignore_index=True,
    )

    validate_feature_columns(dataset.columns)

    logger.info(
        "Loaded %d windows from %d sessions",
        len(dataset),
        dataset["session_id"].nunique(),
    )

    return dataset


# ---------------------------------------------------------------------
# Session-level split
# ---------------------------------------------------------------------

def split_by_session(df):
    """
    Split the dataset by session.

    This prevents windows from the same PCAP appearing in multiple
    dataset splits.
    """

    sessions = (
        df["session_id"]
        .drop_duplicates()
        .to_numpy()
    )

    rng = np.random.default_rng(RANDOM_STATE)

    rng.shuffle(sessions)

    total_sessions = len(sessions)

    train_end = int(
        total_sessions * TRAIN_RATIO
    )

    validation_end = train_end + int(
        total_sessions * VALIDATION_RATIO
    )

    train_sessions = sessions[:train_end]

    validation_sessions = sessions[
        train_end:validation_end
    ]

    test_sessions = sessions[
        validation_end:
    ]

    train_df = df[
        df["session_id"].isin(train_sessions)
    ].copy()

    validation_df = df[
        df["session_id"].isin(validation_sessions)
    ].copy()

    test_df = df[
        df["session_id"].isin(test_sessions)
    ].copy()

    return (
        train_df,
        validation_df,
        test_df,
    )


# ---------------------------------------------------------------------
# Feature preparation
# ---------------------------------------------------------------------

def prepare_features(df):
    """
    Extract the frozen behavioral feature vector.
    """

    X = df[MODEL_FEATURES].copy()

    # Make sure all values are numeric.
    X = X.apply(
        pd.to_numeric,
        errors="coerce",
    )

    if X.isna().any().any():
        bad_columns = X.columns[
            X.isna().any()
        ].tolist()

        raise ValueError(
            "NaN values found in model features: "
            + ", ".join(bad_columns)
        )

    # Guard against infinities.
    if not np.isfinite(X.to_numpy()).all():
        raise ValueError(
            "Infinite values found in model features."
        )

    return X


# ---------------------------------------------------------------------
# Scaling
# ---------------------------------------------------------------------

def fit_scaler(X_train):
    """
    Fit RobustScaler using TRAINING data only.

    RobustScaler is less affected by the heavy tails present in
    byte_ratio, packet rates, and similar behavioral features.
    """

    scaler = RobustScaler()

    X_train_scaled = scaler.fit_transform(
        X_train
    )

    return scaler, X_train_scaled


def transform_features(scaler, X):
    """
    Transform features using the already-fitted scaler.
    """

    return scaler.transform(X)


# ---------------------------------------------------------------------
# Isolation Forest
# ---------------------------------------------------------------------

def train_isolation_forest(X_train):
    """
    Train the Isolation Forest.
    """

    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=CONTAMINATION,
        max_samples=MAX_SAMPLES,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    model.fit(X_train)

    return model


# ---------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------

def calculate_scores(model, X):
    """
    Calculate anomaly scores.

    sklearn's score_samples():
        higher = more normal

    We negate it so:
        higher = more anomalous
    """

    return -model.score_samples(X)


def calculate_predictions(model, X):
    """
    Return sklearn predictions.

    1  = normal
    -1 = anomaly
    """

    return model.predict(X)


def print_score_summary(name, scores, predictions):
    """
    Print scoring statistics.
    """

    anomaly_count = int(
        np.sum(predictions == -1)
    )

    total = len(predictions)

    anomaly_fraction = (
        anomaly_count / total
        if total
        else 0
    )

    print()
    print("=" * 70)
    print(f"{name.upper()} SCORES")
    print("=" * 70)

    print(f"Windows           : {total}")
    print(f"Anomalies         : {anomaly_count}")
    print(
        f"Anomaly fraction  : "
        f"{anomaly_fraction:.2%}"
    )

    print(
        f"Score min         : "
        f"{scores.min():.6f}"
    )

    print(
        f"Score median      : "
        f"{np.median(scores):.6f}"
    )

    print(
        f"Score mean        : "
        f"{scores.mean():.6f}"
    )

    print(
        f"Score max         : "
        f"{scores.max():.6f}"
    )


# ---------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------

def save_metadata(
    train_df,
    validation_df,
    test_df,
):
    """
    Save training configuration and dataset information.
    """

    metadata = {
        "model_type": "IsolationForest",

        "random_state": RANDOM_STATE,

        "n_estimators": N_ESTIMATORS,

        "contamination": CONTAMINATION,

        "max_samples": MAX_SAMPLES,

        "split": {
            "method": "session_level",
            "train_ratio": TRAIN_RATIO,
            "validation_ratio": VALIDATION_RATIO,
            "test_ratio": TEST_RATIO,
        },

        "dataset": {
            "total_windows": (
                len(train_df)
                + len(validation_df)
                + len(test_df)
            ),

            "total_sessions": (
                train_df["session_id"].nunique()
                + validation_df["session_id"].nunique()
                + test_df["session_id"].nunique()
            ),
        },

        "train": {
            "windows": len(train_df),
            "sessions": train_df["session_id"].nunique(),
        },

        "validation": {
            "windows": len(validation_df),
            "sessions": validation_df["session_id"].nunique(),
        },

        "test": {
            "windows": len(test_df),
            "sessions": test_df["session_id"].nunique(),
        },

        "features": MODEL_FEATURES,
    }

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        METADATA_PATH,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            metadata,
            file,
            indent=2,
        )


# ---------------------------------------------------------------------
# Main training pipeline
# ---------------------------------------------------------------------

def main():

    print("=" * 70)
    print("ESP BEHAVIORAL ISOLATION FOREST TRAINING")
    print("=" * 70)

    # ---------------------------------------------------------------
    # Load
    # ---------------------------------------------------------------

    df = load_window_dataset()

    # ---------------------------------------------------------------
    # Split by SESSION
    # ---------------------------------------------------------------

    (
        train_df,
        validation_df,
        test_df,
    ) = split_by_session(df)

    print()
    print("=" * 70)
    print("SESSION-LEVEL DATASET SPLIT")
    print("=" * 70)

    print(
        f"Train      : "
        f"{train_df['session_id'].nunique()} sessions / "
        f"{len(train_df)} windows"
    )

    print(
        f"Validation : "
        f"{validation_df['session_id'].nunique()} sessions / "
        f"{len(validation_df)} windows"
    )

    print(
        f"Test       : "
        f"{test_df['session_id'].nunique()} sessions / "
        f"{len(test_df)} windows"
    )

    # ---------------------------------------------------------------
    # Verify there is no session leakage
    # ---------------------------------------------------------------

    train_sessions = set(
        train_df["session_id"]
    )

    validation_sessions = set(
        validation_df["session_id"]
    )

    test_sessions = set(
        test_df["session_id"]
    )

    if train_sessions & validation_sessions:
        raise RuntimeError(
            "SESSION LEAKAGE: train/validation overlap"
        )

    if train_sessions & test_sessions:
        raise RuntimeError(
            "SESSION LEAKAGE: train/test overlap"
        )

    if validation_sessions & test_sessions:
        raise RuntimeError(
            "SESSION LEAKAGE: validation/test overlap"
        )

    print()
    print("[OK] No session leakage detected")

    # ---------------------------------------------------------------
    # Prepare features
    # ---------------------------------------------------------------

    X_train = prepare_features(train_df)
    X_validation = prepare_features(validation_df)
    X_test = prepare_features(test_df)

    print()
    print(
        f"[OK] Using {len(MODEL_FEATURES)} behavioral features"
    )

    # ---------------------------------------------------------------
    # Fit scaler ONLY on training data
    # ---------------------------------------------------------------

    scaler, X_train_scaled = fit_scaler(
        X_train
    )

    X_validation_scaled = transform_features(
        scaler,
        X_validation,
    )

    X_test_scaled = transform_features(
        scaler,
        X_test,
    )

    print("[OK] RobustScaler fitted on training data only")

    # ---------------------------------------------------------------
    # Train Isolation Forest
    # ---------------------------------------------------------------

    model = train_isolation_forest(
        X_train_scaled
    )

    print(
        f"[OK] Isolation Forest trained "
        f"with {N_ESTIMATORS} trees"
    )

    # ---------------------------------------------------------------
    # Score datasets
    # ---------------------------------------------------------------

    train_scores = calculate_scores(
        model,
        X_train_scaled,
    )

    validation_scores = calculate_scores(
        model,
        X_validation_scaled,
    )

    test_scores = calculate_scores(
        model,
        X_test_scaled,
    )

    train_predictions = calculate_predictions(
        model,
        X_train_scaled,
    )

    validation_predictions = calculate_predictions(
        model,
        X_validation_scaled,
    )

    test_predictions = calculate_predictions(
        model,
        X_test_scaled,
    )

    # ---------------------------------------------------------------
    # Print results
    # ---------------------------------------------------------------

    print_score_summary(
        "Training",
        train_scores,
        train_predictions,
    )

    print_score_summary(
        "Validation",
        validation_scores,
        validation_predictions,
    )

    print_score_summary(
        "Test",
        test_scores,
        test_predictions,
    )

    # ---------------------------------------------------------------
    # Save model
    # ---------------------------------------------------------------

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(
        model,
        MODEL_PATH,
    )

    joblib.dump(
        scaler,
        SCALER_PATH,
    )

    save_metadata(
        train_df,
        validation_df,
        test_df,
    )

    print()
    print("=" * 70)
    print("MODEL ARTIFACTS")
    print("=" * 70)

    print(f"Model    : {MODEL_PATH}")
    print(f"Scaler   : {SCALER_PATH}")
    print(f"Metadata : {METADATA_PATH}")

    print()
    print("[+] Training complete.")


if __name__ == "__main__":
    main()