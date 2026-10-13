"""
ml/train.py — single entry point that trains all three models.

    python ml/train.py --skip-optuna          # fast: default hyperparameters
    python ml/train.py --optuna-trials 20     # tune the traffic model with Optuna

Inputs
    data/features/*.parquet   one IPsecFeatureRow per session (features/pipeline.py)
    data/labels/*.json        ground truth per session (data/make_labels.py)
                              — or label_config / label_traffic columns in the parquet

Outputs (in --output-dir, default ml/)
    protocol_model.joblib     XGBClassifier  IKE features (9)  → combined config label
    traffic_model.joblib      XGBClassifier  ESP features (18) → traffic class
    anomaly_model.joblib      IsolationForest on ESP features of benign sessions
    encoder.joblib            {"protocol_encoder": LabelEncoder, "traffic_encoder": LabelEncoder}
    optuna_study_traffic.pkl  Optuna study (only when tuning ran)
    split.json                session ids per train / val / test split (used by evaluate.py)
    training_metadata.json    dataset counts, hyperparameters and validation/test scores
"""

from __future__ import annotations

import argparse
import json
import logging
import pickle
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from features.schema import IPsecFeatureRow, ProtocolModelTarget, TrafficClass  # noqa: E402
from ml.scorer import score_session  # noqa: E402

IKE_FEATURES = list(IPsecFeatureRow.IKE_FEATURE_NAMES)
ESP_FEATURES = list(IPsecFeatureRow.ESP_FEATURE_NAMES)

DEFAULT_FEATURES_DIR = ROOT / "data" / "features"
DEFAULT_LABELS_DIR = ROOT / "data" / "labels"
DEFAULT_OUTPUT_DIR = ROOT / "ml"

PROTOCOL_PARAMS = {"n_estimators": 100, "max_depth": 4, "learning_rate": 0.1}
TRAFFIC_PARAMS = {"n_estimators": 200, "max_depth": 6, "learning_rate": 0.1, "subsample": 0.8}
ANOMALY_PARAMS = {"n_estimators": 200, "contamination": 0.05}
BENIGN_SCORE_MIN = 80.0       # Isolation Forest trains on well-configured sessions only
MIN_BENIGN_ROWS = 20          # ...unless there are too few of them

log = logging.getLogger("train")


# ── Data loading (shared with evaluate.py) ───────────────────────────────────

def _read_label_file(labels_dir: Path, session_id: str) -> Optional[dict]:
    path = labels_dir / f"{session_id}.json"
    if not path.is_file():
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def load_dataset(features_dir: Path, labels_dir: Path) -> pd.DataFrame:
    """
    Load every parquet row and attach two targets:
      target_config  — ProtocolModelTarget label, e.g. 'tunnel__aes256_gcm__group19__pfs'
      target_traffic — traffic class
    Rows without ground truth are dropped (with a warning).
    """
    files = sorted(Path(features_dir).glob("*.parquet"))
    if not files:
        raise FileNotFoundError(f"No parquet files in {features_dir}")
    df = pd.concat([pd.read_parquet(f) for f in files], ignore_index=True)
    df = df.drop_duplicates(subset="session_id", keep="last").reset_index(drop=True)

    configs, traffics = [], []
    for _, row in df.iterrows():
        label = _read_label_file(Path(labels_dir), str(row["session_id"]))
        config = traffic = None
        if label:
            try:
                config = ProtocolModelTarget.config_label(
                    label["mode"], label["cipher_suite"], label["dh_group"], bool(label["pfs_enabled"])
                )
            except KeyError:
                config = None
            traffic = label.get("traffic_class")
        if config is None:
            value = row.get("label_config")
            if isinstance(value, str) and value.count("__") == 3:
                config = value
        if traffic is None:
            value = row.get("label_traffic")
            if isinstance(value, str) and value:
                traffic = value
        configs.append(config)
        traffics.append(traffic)

    df["target_config"] = configs
    df["target_traffic"] = traffics
    unlabeled = df["target_config"].isna() | df["target_traffic"].isna()
    if unlabeled.any():
        log.warning(
            "Dropping %d rows without ground-truth labels (run data/make_labels.py): %s",
            int(unlabeled.sum()), ", ".join(df.loc[unlabeled, "session_id"].astype(str).head(5)),
        )
    df = df[~unlabeled].reset_index(drop=True)
    unknown = set(df["target_traffic"]) - set(TrafficClass.ALL)
    if unknown:
        raise ValueError(f"Unknown traffic classes in labels: {sorted(unknown)}")
    if df.empty:
        raise ValueError("No labelled rows to train on")
    return df


def matrix(df: pd.DataFrame, columns: list[str]) -> np.ndarray:
    """Feature matrix built with exactly the conversion inference uses (None/NaN → 0)."""
    from ml.explainability import feature_vector

    if df.empty:
        return np.empty((0, len(columns)))
    rows = [feature_vector(record, columns)[0] for record in df[columns].to_dict("records")]
    out = np.vstack(rows)
    return np.nan_to_num(out, nan=0.0)


# ── Splitting ────────────────────────────────────────────────────────────────

def split_indices(y: np.ndarray, seed: int) -> dict[str, np.ndarray]:
    """70 / 15 / 15 split, stratified by traffic class when every class allows it."""
    from sklearn.model_selection import train_test_split

    idx = np.arange(len(y))

    def _split(indices, labels, test_size):
        try:
            return train_test_split(indices, test_size=test_size, random_state=seed, stratify=labels)
        except ValueError:
            log.warning("Too few samples per class to stratify — using a random split")
            return train_test_split(indices, test_size=test_size, random_state=seed)

    if len(idx) < 7:
        raise ValueError(f"Need at least 7 labelled sessions to split, got {len(idx)}")
    train_idx, rest_idx = _split(idx, y, 0.30)
    val_idx, test_idx = _split(rest_idx, y[rest_idx], 0.50)
    return {"train": np.sort(train_idx), "val": np.sort(val_idx), "test": np.sort(test_idx)}


# ── Model helpers ────────────────────────────────────────────────────────────

def _pad_missing_classes(x: np.ndarray, y: np.ndarray, weights: np.ndarray, n_classes: int):
    """
    XGBoost's sklearn API requires every class 0..n-1 to appear in y. Classes that
    only exist in val/test get one placeholder row with weight 0, which keeps the
    output layer the right size without influencing any tree.
    """
    missing = sorted(set(range(n_classes)) - set(int(v) for v in y))
    if not missing:
        return x, y, weights
    filler = np.tile(x.mean(axis=0), (len(missing), 1))
    return (
        np.vstack([x, filler]),
        np.concatenate([y, np.array(missing, dtype=y.dtype)]),
        np.concatenate([weights, np.zeros(len(missing))]),
    )


def fit_xgb(x, y, n_classes: int, params: dict, seed: int, balanced: bool):
    from sklearn.utils.class_weight import compute_sample_weight
    from xgboost import XGBClassifier

    weights = compute_sample_weight("balanced", y) if balanced else np.ones(len(y))
    x_fit, y_fit, w_fit = _pad_missing_classes(x, y, weights, n_classes)
    model = XGBClassifier(
        objective="multi:softprob",
        eval_metric="mlogloss",
        random_state=seed,
        n_jobs=-1,
        verbosity=0,
        **params,
    )
    model.fit(x_fit, y_fit, sample_weight=w_fit)
    return model


def macro_f1(model, x, y) -> float:
    from sklearn.metrics import f1_score

    if len(y) == 0:
        return float("nan")
    return float(f1_score(y, model.predict(x), average="macro", zero_division=0))


def tune_traffic(x_tr, y_tr, x_val, y_val, n_classes, trials, seed):
    import optuna

    optuna.logging.set_verbosity(optuna.logging.WARNING)

    def objective(trial):
        params = {
            "n_estimators": trial.suggest_int("n_estimators", 100, 500, step=50),
            "max_depth": trial.suggest_int("max_depth", 3, 10),
            "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.3),
            "min_child_weight": trial.suggest_int("min_child_weight", 1, 10),
            "subsample": trial.suggest_float("subsample", 0.6, 1.0),
            "colsample_bytree": trial.suggest_float("colsample_bytree", 0.6, 1.0),
        }
        model = fit_xgb(x_tr, y_tr, n_classes, params, seed, balanced=True)
        score = macro_f1(model, x_val, y_val)
        log.info("Optuna trial %d | val macro-F1=%.4f | %s", trial.number, score, params)
        return score

    study = optuna.create_study(
        study_name="traffic_classification",
        direction="maximize",
        sampler=optuna.samplers.TPESampler(seed=seed),
    )
    study.optimize(objective, n_trials=trials)
    return study


# ── Main pipeline ────────────────────────────────────────────────────────────

def train(
    features_dir: Path = DEFAULT_FEATURES_DIR,
    labels_dir: Path = DEFAULT_LABELS_DIR,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    optuna_trials: int = 20,
    skip_optuna: bool = False,
    seed: int = 42,
) -> dict[str, Any]:
    import joblib
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import LabelEncoder

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    df = load_dataset(Path(features_dir), Path(labels_dir))
    log.info("Loaded %d labelled sessions", len(df))

    protocol_encoder = LabelEncoder().fit(df["target_config"])
    traffic_encoder = LabelEncoder().fit(df["target_traffic"])
    y_config = protocol_encoder.transform(df["target_config"])
    y_traffic = traffic_encoder.transform(df["target_traffic"])
    x_ike = matrix(df, IKE_FEATURES)
    x_esp = matrix(df, ESP_FEATURES)

    splits = split_indices(y_traffic, seed)
    tr, va, te = splits["train"], splits["val"], splits["test"]
    log.info("Split sizes | train=%d val=%d test=%d", len(tr), len(va), len(te))

    # Model 1 — protocol identification
    n_config = len(protocol_encoder.classes_)
    protocol_model = fit_xgb(x_ike[tr], y_config[tr], n_config, PROTOCOL_PARAMS, seed, balanced=False)
    protocol_scores = {
        "val_macro_f1": macro_f1(protocol_model, x_ike[va], y_config[va]),
        "test_macro_f1": macro_f1(protocol_model, x_ike[te], y_config[te]),
    }
    log.info("Protocol model | classes=%d | %s", n_config, protocol_scores)

    # Model 2 — traffic classification (optionally tuned)
    n_traffic = len(traffic_encoder.classes_)
    traffic_params = dict(TRAFFIC_PARAMS)
    study = None
    if not skip_optuna and optuna_trials > 0:
        study = tune_traffic(x_esp[tr], y_traffic[tr], x_esp[va], y_traffic[va], n_traffic, optuna_trials, seed)
        traffic_params = dict(study.best_params)
        log.info("Optuna best val macro-F1=%.4f | %s", study.best_value, traffic_params)
    traffic_model = fit_xgb(x_esp[tr], y_traffic[tr], n_traffic, traffic_params, seed, balanced=True)
    traffic_scores = {
        "val_macro_f1": macro_f1(traffic_model, x_esp[va], y_traffic[va]),
        "test_macro_f1": macro_f1(traffic_model, x_esp[te], y_traffic[te]),
    }
    log.info("Traffic model | classes=%s | %s", list(traffic_encoder.classes_), traffic_scores)

    # Model 3 — Isolation Forest on benign (well-configured) training sessions
    train_df = df.iloc[tr]
    gt_rows = train_df.assign(
        mode=[c.split("__")[0] for c in train_df["target_config"]],
        cipher_suite=[c.split("__")[1] for c in train_df["target_config"]],
        dh_group=[c.split("__")[2] for c in train_df["target_config"]],
        pfs_enabled=[c.split("__")[3] == "pfs" for c in train_df["target_config"]],
    )
    scores = np.array([score_session(r)["security_score"] for r in gt_rows.to_dict("records")])
    benign = tr[scores >= BENIGN_SCORE_MIN]
    anomaly_rows = benign if len(benign) >= MIN_BENIGN_ROWS else tr
    if len(benign) < MIN_BENIGN_ROWS:
        log.warning(
            "Only %d benign training sessions (score >= %.0f) — training IsolationForest on all %d",
            len(benign), BENIGN_SCORE_MIN, len(tr),
        )
    anomaly_model = IsolationForest(random_state=seed, n_jobs=-1, **ANOMALY_PARAMS)
    anomaly_model.fit(x_esp[anomaly_rows])
    anomaly_scores = -anomaly_model.score_samples(x_esp)
    anomaly_summary = {
        "trained_on": int(len(anomaly_rows)),
        "mean": float(anomaly_scores.mean()),
        "std": float(anomaly_scores.std()),
        "max": float(anomaly_scores.max()),
        "threshold": float(-anomaly_model.offset_),
    }
    log.info("Anomaly model | %s", anomaly_summary)

    # Persist
    joblib.dump(protocol_model, output_dir / "protocol_model.joblib")
    joblib.dump(traffic_model, output_dir / "traffic_model.joblib")
    joblib.dump(anomaly_model, output_dir / "anomaly_model.joblib")
    joblib.dump(
        {"protocol_encoder": protocol_encoder, "traffic_encoder": traffic_encoder},
        output_dir / "encoder.joblib",
    )
    if study is not None:
        with open(output_dir / "optuna_study_traffic.pkl", "wb") as fh:
            pickle.dump(study, fh)
    session_ids = df["session_id"].astype(str).to_numpy()
    with open(output_dir / "split.json", "w", encoding="utf-8") as fh:
        json.dump({name: session_ids[ix].tolist() for name, ix in splits.items()}, fh, indent=2)

    metadata = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "seed": seed,
        "sessions": int(len(df)),
        "split_sizes": {k: int(len(v)) for k, v in splits.items()},
        "protocol": {"classes": n_config, "params": PROTOCOL_PARAMS, **protocol_scores},
        "traffic": {
            "classes": list(traffic_encoder.classes_),
            "params": traffic_params,
            "optuna_trials": 0 if study is None else len(study.trials),
            **traffic_scores,
        },
        "anomaly": {"params": ANOMALY_PARAMS, **anomaly_summary},
    }
    with open(output_dir / "training_metadata.json", "w", encoding="utf-8") as fh:
        json.dump(metadata, fh, indent=2, default=str)
    log.info("Artefacts written to %s", output_dir)
    return metadata


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Train protocol, traffic and anomaly models")
    parser.add_argument("--features-dir", type=Path, default=DEFAULT_FEATURES_DIR)
    parser.add_argument("--labels-dir", type=Path, default=DEFAULT_LABELS_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--optuna-trials", type=int, default=20)
    parser.add_argument("--skip-optuna", action="store_true", help="Use default traffic hyperparameters")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)

    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] train | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        level=logging.INFO,
        stream=sys.stdout,
    )
    try:
        train(
            features_dir=args.features_dir,
            labels_dir=args.labels_dir,
            output_dir=args.output_dir,
            optuna_trials=args.optuna_trials,
            skip_optuna=args.skip_optuna,
            seed=args.seed,
        )
    except (FileNotFoundError, ValueError) as exc:
        log.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
