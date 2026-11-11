"""Training pipeline for Network Model (LightGBM).

Trains an LGBMClassifier strictly on network telemetry features.
Crucially preserves unsupported PCAP features as NaN to leverage LightGBM's native
missing value branching without artificial zero imputation.
"""

from __future__ import annotations

import argparse
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd
from lightgbm import LGBMClassifier

from models.common import (
    SMALL_DATASET_WARNING,
    compute_binary_metrics,
    get_git_commit,
    get_package_version,
    stratified_split_dataset,
)
from models.network.model import PERMITTED_NETWORK_FEATURES, NetworkModel
from preprocessing.pipeline import PCAP_NULL_FIELDS

logger = logging.getLogger("train_network")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def _prepare_network_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Add is_missing_* indicator flags while preserving genuine NaNs for PCAP fields."""
    df_out = df.copy()
    for field in sorted(PCAP_NULL_FIELDS):
        sentinel_col = f"is_missing_{field}"
        if field in df_out.columns:
            df_out[sentinel_col] = df_out[field].isna().astype(int)
        else:
            df_out[sentinel_col] = 1
    return df_out


def train_network_model(
    dataset_path: str | Path = "data/processed/unified/unified_dataset.jsonl",
    output_dir: str | Path = "models/artifacts/network",
    eval_dir: str | Path = "evaluation/binary",
    random_state: int = 42,
) -> dict[str, Any]:
    """Train, validate, and evaluate the Network LightGBM binary classifier.

    Args:
        dataset_path: Path to unified dataset JSONL or CSV.
        output_dir: Directory where model weights and artifacts are saved.
        eval_dir: Directory where evaluation JSON report is saved.
        random_state: RNG seed for reproducible splitting and training.

    Returns:
        Dictionary containing evaluation metrics and training metadata.
    """
    data_file = Path(dataset_path)
    out_path = Path(output_dir)
    eval_path = Path(eval_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    eval_path.mkdir(parents=True, exist_ok=True)

    if not data_file.exists():
        raise FileNotFoundError(f"Unified dataset not found at {data_file}")

    if data_file.suffix == ".jsonl":
        rows = [
            json.loads(line)
            for line in data_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        df = pd.DataFrame(rows)
    else:
        df = pd.read_csv(data_file)

    logger.info("Loaded %d total samples from %s", len(df), data_file)

    # Prepare network features: generate missing sentinels, keep genuine NaNs
    df = _prepare_network_dataframe(df)
    active_features = [f for f in PERMITTED_NETWORK_FEATURES if f in df.columns]

    # Stratified 70/15/15 train/val/test splitting
    df_train, df_val, df_test = stratified_split_dataset(
        df,
        target_col="binary_label",
        test_size=0.15,
        val_size=0.15,
        random_state=random_state,
    )

    y_train = df_train["binary_label"].astype(int).values
    y_val = df_val["binary_label"].astype(int).values
    y_test = df_test["binary_label"].astype(int).values

    # Convert to float matrices preserving NaNs for LightGBM's native missing value handling
    X_train = df_train[active_features].values.astype(float)
    X_val = df_val[active_features].values.astype(float)

    # Conservative hyperparameters for tiny dataset
    hyperparams = {
        "n_estimators": 100,
        "max_depth": 3,
        "num_leaves": 7,
        "learning_rate": 0.05,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "min_child_samples": 3,  # Necessary for tiny dataset
        "random_state": random_state,
        "verbosity": -1,
    }

    lgbm_clf = LGBMClassifier(**hyperparams)
    lgbm_clf.fit(
        X_train,
        y_train,
        eval_set=[(X_val, y_val)],
    )

    # Wrap in NetworkModel
    network_model = NetworkModel(
        classifier=lgbm_clf,
        feature_names=active_features,
    )

    # Evaluate on test set (and validation set for reference)
    val_probs = network_model.predict_proba(df_val)
    val_metrics = compute_binary_metrics(y_val, val_probs)

    test_probs = network_model.predict_proba(df_test)
    test_metrics = compute_binary_metrics(y_test, test_probs)

    logger.info("Test Metrics for Network Model (LightGBM): %s", test_metrics)

    # Metadata specification
    metadata: dict[str, Any] = {
        "model_type": "lightgbm",
        "modality": "network",
        "dataset_source": str(data_file.resolve()),
        "train_sample_count": len(df_train),
        "validation_sample_count": len(df_val),
        "test_sample_count": len(df_test),
        "train_class_distribution": {
            "benign": int(sum(y_train == 0)),
            "malware": int(sum(y_train == 1)),
        },
        "validation_class_distribution": {
            "benign": int(sum(y_val == 0)),
            "malware": int(sum(y_val == 1)),
        },
        "test_class_distribution": {
            "benign": int(sum(y_test == 0)),
            "malware": int(sum(y_test == 1)),
        },
        "feature_names": active_features,
        "pcap_missing_features_preserved": sorted(PCAP_NULL_FIELDS),
        "random_seed": random_state,
        "hyperparameters": hyperparams,
        "training_timestamp": datetime.now(tz=UTC).isoformat(),
        "software_versions": {
            "lightgbm": get_package_version("lightgbm"),
            "scikit-learn": get_package_version("scikit-learn"),
            "pandas": get_package_version("pandas"),
        },
        "git_commit": get_git_commit(),
        "small_dataset_warning": SMALL_DATASET_WARNING,
    }

    # Save model artifacts
    network_model.save(out_path)
    (out_path / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    # Save evaluation report
    eval_report = {
        "model": "NetworkModel (LightGBM)",
        "modality": "network",
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics,
        "metadata": metadata,
    }
    eval_file = eval_path / "network_evaluation.json"
    eval_file.write_text(json.dumps(eval_report, indent=2), encoding="utf-8")

    logger.info("Network model artifacts saved to %s", out_path)
    logger.info("Network evaluation report saved to %s", eval_file)

    return eval_report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Network LightGBM Model")
    parser.add_argument("--dataset", default="data/processed/unified/unified_dataset.jsonl")
    parser.add_argument("--output-dir", default="models/artifacts/network")
    parser.add_argument("--eval-dir", default="evaluation/binary")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    train_network_model(
        dataset_path=args.dataset,
        output_dir=args.output_dir,
        eval_dir=args.eval_dir,
        random_state=args.seed,
    )
