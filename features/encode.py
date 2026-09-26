from __future__ import annotations

from pathlib import Path
from typing import Mapping

import joblib
import pandas as pd


ENCODED_COLUMNS = ("cipher_suite", "dh_group", "auth_algo", "mode")
DEFAULT_ENCODER_PATH = Path(__file__).resolve().parents[1] / "ml" / "frequency_encoder.joblib"


def fit_frequency_encoder(training_data: pd.DataFrame) -> dict[str, dict[object, float]]:
    _validate_columns(training_data)
    return {
        column: training_data[column].value_counts(normalize=True, dropna=False).to_dict()
        for column in ENCODED_COLUMNS
    }


def transform_frequency_encoder(
    data: pd.DataFrame,
    mappings: Mapping[str, Mapping[object, float]],
) -> pd.DataFrame:
    _validate_columns(data)
    encoded = data.copy()
    for column in ENCODED_COLUMNS:
        if column not in mappings:
            raise ValueError(f"Missing frequency mapping for {column}")
        encoded[column] = encoded[column].map(mappings[column]).fillna(0.0)
    return encoded


def fit_transform_frequency_encoder(
    training_data: pd.DataFrame,
    encoder_path: str | Path = DEFAULT_ENCODER_PATH,
) -> pd.DataFrame:
    mappings = fit_frequency_encoder(training_data)
    save_frequency_encoder(mappings, encoder_path)
    return transform_frequency_encoder(training_data, mappings)


def save_frequency_encoder(
    mappings: Mapping[str, Mapping[object, float]],
    encoder_path: str | Path = DEFAULT_ENCODER_PATH,
) -> Path:
    path = Path(encoder_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(dict(mappings), path)
    return path


def load_frequency_encoder(
    encoder_path: str | Path = DEFAULT_ENCODER_PATH,
) -> dict[str, dict[object, float]]:
    return joblib.load(encoder_path)


def transform_for_inference(
    data: pd.DataFrame,
    encoder_path: str | Path = DEFAULT_ENCODER_PATH,
) -> pd.DataFrame:
    return transform_frequency_encoder(data, load_frequency_encoder(encoder_path))


def _validate_columns(data: pd.DataFrame) -> None:
    missing_columns = [column for column in ENCODED_COLUMNS if column not in data.columns]
    if missing_columns:
        raise ValueError(f"Missing columns for frequency encoding: {', '.join(missing_columns)}")
