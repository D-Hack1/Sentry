import json

import pytest

from ml import evaluate, train
from ml.inference import analyze_dict, load_models
from ml.tests.synthetic import make_dataset


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    base = tmp_path_factory.mktemp("train")
    features, labels, out = base / "features", base / "labels", base / "models"
    make_dataset(features, labels)
    metadata = train.train(features, labels, out, optuna_trials=3, skip_optuna=False, seed=1)
    return base, features, labels, out, metadata


def test_train_writes_all_artefacts(trained):
    _, _, _, out, metadata = trained
    for name in ("protocol_model.joblib", "traffic_model.joblib", "anomaly_model.joblib",
                 "encoder.joblib", "optuna_study_traffic.pkl", "split.json", "training_metadata.json"):
        assert (out / name).is_file(), name
    split = json.loads((out / "split.json").read_text())
    assert sum(len(v) for v in split.values()) == metadata["sessions"] == 60
    assert not set(split["train"]) & set(split["test"])


def test_traffic_model_learns_separable_classes(trained):
    assert trained[4]["traffic"]["test_macro_f1"] > 0.9


def test_trained_models_load_and_analyze(trained):
    _, features, _, out, _ = trained
    import pandas as pd

    models = load_models(out)
    row = pd.read_parquet(next(features.glob("*icmp_000.parquet"))).iloc[0].to_dict()
    result = analyze_dict(row, models)
    assert result["traffic_class"] == "icmp"
    assert result["mode"] in ("tunnel", "transport")      # filled by the protocol model
    assert result["config_source"]["mode"] == "model"
    assert result["config_source"]["cipher_suite"] == "parser"
    assert result["evidence"]


def test_evaluate_writes_reports(trained):
    _, features, labels, out, _ = trained
    results = evaluate.evaluate(out, features, labels)
    assert results["traffic_macro_f1"] > 0.9
    for name in ("protocol_classification_report.txt", "traffic_classification_report.txt",
                 "protocol_confusion_matrix.png", "traffic_confusion_matrix.png"):
        assert (out / name).stat().st_size > 0
    assert "held-out test split" in (out / "traffic_classification_report.txt").read_text()


def test_rows_without_labels_are_dropped(tmp_path):
    features, labels = tmp_path / "f", tmp_path / "l"
    ids = make_dataset(features, labels, per_class=3)
    (labels / f"{ids[0]}.json").unlink()
    df = train.load_dataset(features, labels)
    assert len(df) == len(ids) - 1


def test_missing_features_dir_fails_cleanly(tmp_path):
    assert train.main(["--features-dir", str(tmp_path / "nope"), "--output-dir", str(tmp_path)]) == 1
