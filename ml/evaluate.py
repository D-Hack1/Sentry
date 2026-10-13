"""
ml/evaluate.py — standalone evaluation of the trained classifiers.

    python ml/evaluate.py [--model-dir ml] [--features-dir data/features] [--labels-dir data/labels]

Evaluates on the held-out test split recorded by train.py (split.json). If no
split file exists (e.g. models trained elsewhere), it falls back to every
labelled row and says so — those numbers then include training data.

Writes to --output-dir (default: the model dir):
    protocol_classification_report.txt   traffic_classification_report.txt
    protocol_confusion_matrix.png        traffic_confusion_matrix.png
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Optional

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ml.inference import load_models  # noqa: E402
from ml.train import (  # noqa: E402
    DEFAULT_FEATURES_DIR,
    DEFAULT_LABELS_DIR,
    ESP_FEATURES,
    IKE_FEATURES,
    load_dataset,
    matrix,
)

log = logging.getLogger("evaluate")


def _select_test_rows(df, model_dir: Path):
    split_path = model_dir / "split.json"
    if split_path.is_file():
        with open(split_path, encoding="utf-8") as fh:
            test_ids = set(json.load(fh).get("test", []))
        subset = df[df["session_id"].astype(str).isin(test_ids)]
        if not subset.empty:
            return subset.reset_index(drop=True), f"held-out test split ({len(subset)} sessions)"
        log.warning("split.json test ids not found in the dataset — evaluating on all rows")
    else:
        log.warning("No split.json next to the models — evaluating on ALL labelled rows "
                    "(includes training data, so scores are optimistic)")
    return df.reset_index(drop=True), f"all labelled rows ({len(df)} sessions)"


def _report(name: str, y_true, y_pred, encoder, out_dir: Path, scope: str) -> float:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from sklearn.metrics import ConfusionMatrixDisplay, classification_report, confusion_matrix, f1_score

    present = np.unique(np.concatenate([y_true, y_pred]))
    names = [str(n) for n in encoder.inverse_transform(present)]
    report = classification_report(
        y_true, y_pred, labels=present, target_names=names, zero_division=0, digits=4
    )
    f1 = float(f1_score(y_true, y_pred, labels=present, average="macro", zero_division=0))
    text = f"{name} model — evaluated on {scope}\nmacro-F1: {f1:.4f}\n\n{report}"
    (out_dir / f"{name}_classification_report.txt").write_text(text, encoding="utf-8")

    cm = confusion_matrix(y_true, y_pred, labels=present)
    size = max(6.0, 0.35 * len(present) + 3)
    fig, ax = plt.subplots(figsize=(size, size))
    ConfusionMatrixDisplay(cm, display_labels=names).plot(
        ax=ax, cmap="Blues", colorbar=False, xticks_rotation="vertical", values_format="d"
    )
    ax.set_title(f"{name} model — {scope}")
    fig.tight_layout()
    fig.savefig(out_dir / f"{name}_confusion_matrix.png", dpi=120)
    plt.close(fig)
    log.info("%s model | macro-F1=%.4f | %s", name, f1, scope)
    return f1


def evaluate(
    model_dir: Path,
    features_dir: Path = DEFAULT_FEATURES_DIR,
    labels_dir: Path = DEFAULT_LABELS_DIR,
    output_dir: Optional[Path] = None,
) -> dict:
    model_dir = Path(model_dir)
    out_dir = Path(output_dir) if output_dir else model_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    models = load_models(model_dir)
    df = load_dataset(Path(features_dir), Path(labels_dir))
    test_df, scope = _select_test_rows(df, model_dir)

    proto_enc = models.encoder["protocol_encoder"]
    traffic_enc = models.encoder["traffic_encoder"]

    known_cfg = test_df["target_config"].isin(proto_enc.classes_)
    if not known_cfg.all():
        log.warning("%d rows have config labels the protocol model never saw — skipped for that model",
                    int((~known_cfg).sum()))
    cfg_df = test_df[known_cfg]
    results = {}
    if not cfg_df.empty:
        y_true = proto_enc.transform(cfg_df["target_config"])
        y_pred = models.protocol_model.predict(matrix(cfg_df, IKE_FEATURES)).astype(int)
        results["protocol_macro_f1"] = _report("protocol", y_true, y_pred, proto_enc, out_dir, scope)

    y_true = traffic_enc.transform(test_df["target_traffic"])
    y_pred = models.traffic_model.predict(matrix(test_df, ESP_FEATURES)).astype(int)
    results["traffic_macro_f1"] = _report("traffic", y_true, y_pred, traffic_enc, out_dir, scope)
    return results


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate trained models")
    parser.add_argument("--model-dir", type=Path, default=ROOT / "ml")
    parser.add_argument("--features-dir", type=Path, default=DEFAULT_FEATURES_DIR)
    parser.add_argument("--labels-dir", type=Path, default=DEFAULT_LABELS_DIR)
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args(argv)
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] evaluate | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        level=logging.INFO,
        stream=sys.stdout,
    )
    try:
        evaluate(args.model_dir, args.features_dir, args.labels_dir, args.output_dir)
    except (FileNotFoundError, ValueError) as exc:
        log.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
