# Inference Output Schema

`ml/inference.py` is the single entry point the API uses.

```python
from ml.inference import load_models, infer, analyze_dict

models = load_models()                  # ml/*.joblib — raises FileNotFoundError listing anything missing
raw    = infer(feature_row, models)     # the three ML models only
result = analyze_dict(feature_row, models)  # models + config resolution + scorer + SHAP
```

`feature_row` is an `IPsecFeatureRow` dict (sections 1–4 of `features/schema.py`).
Missing / `None` numeric features are treated as `0.0`.

## Model artefacts

| File | Contents |
|---|---|
| `protocol_model.joblib` | `XGBClassifier` — 9 IKE features → combined config label (`tunnel__aes256_gcm__group19__pfs`) |
| `traffic_model.joblib` | `XGBClassifier` — 18 ESP features → traffic class |
| `anomaly_model.joblib` | `IsolationForest` — 18 ESP features |
| `encoder.joblib` | `{"protocol_encoder": LabelEncoder, "traffic_encoder": LabelEncoder}` |
| `optuna_study_traffic.pkl` | Optuna study from traffic-model tuning |

Feature order is frozen in `IPsecFeatureRow.IKE_FEATURE_NAMES` / `ESP_FEATURE_NAMES`.

## `infer()` output

| Key | Type | Meaning |
|---|---|---|
| `predicted_config_label` | str | Protocol model's top class, e.g. `tunnel__aes256_gcm__group19__pfs` |
| `predicted_config` | dict | The label decoded: `mode`, `cipher_suite`, `dh_group`, `pfs_enabled` |
| `config_index` / `config_confidence` | int / float | Top class index and its probability |
| `traffic_class` | str | `web` \| `voip` \| `video_stream` \| `file_transfer` \| `icmp` |
| `traffic_index` / `traffic_confidence` | int / float | Top class index and its probability |
| `anomaly_score` | float | `-IsolationForest.score_samples(x)` — higher = more anomalous (≈0.5 is typical) |
| `anomaly_label` | str | `normal` \| `slightly_unusual` \| `anomalous` (see below) |
| `ai_confidence` | float | `sqrt(config_confidence × traffic_confidence)` |

## `analyze_dict()` output (what `POST /analyze` returns, plus API fields)

| Key | Type | Notes |
|---|---|---|
| `session_id`, `ike_version` | | passed through |
| `mode`, `cipher_suite`, `dh_group`, `pfs_enabled` | | **resolved config** — see below |
| `auth_algo`, `key_lifetime_sec` | | passed through |
| `traffic_class`, `traffic_confidence` | str, float [0,1] | traffic model |
| `anomaly_score`, `anomaly_label` | float ≥ 0, str | IsolationForest |
| `ai_confidence` | float [0,1] | geometric mean of both model confidences |
| `security_score`, `severity` | float [0,100], str | `ml/scorer.py` (deterministic) |
| `risk_flags`, `recommendations` | list[str] | highest penalty first; `[]` when none |
| `evidence` | list[str], ≥ 1 | top-5 SHAP reasons for the traffic class |
| `config_evidence` | list[str], ≥ 1 | top-5 SHAP reasons for the predicted config |
| `predicted_config`, `config_confidence` | str, float | raw protocol-model output |
| `config_source` | dict | per config field: `"parser"` or `"model"` |

### Config resolution

IKE is plaintext, so values the parser extracted from the capture are ground truth and are
**never** replaced by a model guess. The protocol model only fills fields the parser could
not observe (`None`) — typically `mode` and `pfs_enabled`, which live in the encrypted
IKE_AUTH / CREATE_CHILD_SA exchanges. `config_source` records which one was used.
The security score is computed on the resolved config.

### Anomaly labels

Calibrated on the trained model rather than fixed constants. Let
`t = -anomaly_model.offset_` (the score above which IsolationForest itself flags an outlier,
set by `contamination=0.05` during training; ≈0.579 for the current model):

| anomaly_score | label |
|---|---|
| `≥ t` | `anomalous` |
| `t − 0.04 ≤ score < t` | `slightly_unusual` |
| `< t − 0.04` | `normal` |

### Evidence strings

`"<High|Low> <feature description> (<value>) — consistent with <traffic class>"`.
Only features whose SHAP value pushes towards the predicted class are listed. If no feature
does, the single most influential one is reported. "High" and "Low" compare the value with the
cover-weighted median split threshold the model uses for that feature.

### Severity thresholds

`critical` < 40 · `high` < 60 · `medium` < 75 · `low` < 90 · `info` ≥ 90
