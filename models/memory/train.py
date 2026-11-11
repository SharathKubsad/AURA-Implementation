"""Training pipeline for Memory Model (CatBoost).

Trains a CatBoostClassifier strictly on memory forensic telemetry features.
Preserves genuine nulls for memory entropy using CatBoost's native nan_mode="Min".
"""

from __future__ import annotations

import argparse
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd
from catboost import CatBoostClassifier

from models.common import (
    SMALL_DATASET_WARNING,
    compute_binary_metrics,
    get_git_commit,
    get_package_version,
    stratified_split_dataset,
)
from models.memory.model import PERMITTED_MEMORY_FEATURES, MemoryModel

logger = logging.getLogger("train_memory")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def _engineer_memory_features(df: pd.DataFrame) -> pd.DataFrame:
    """Compute permitted memory-modality engineered features."""
    df_out = df.copy()
    if "rwx_page_count" in df_out.columns:
        rwx = df_out["rwx_page_count"].fillna(0.0)
        inj = (
            df_out["injected_code_regions"].fillna(0.0)
            if "injected_code_regions" in df_out.columns
            else 0.0
        )
        vad = (
            df_out["vad_protection_anomaly_count"].fillna(0.0)
            if "vad_protection_anomaly_count" in df_out.columns
            else 0.0
        )
        df_out["memory_injection_score"] = rwx * 2.0 + inj * 3.0 + vad * 1.5
    return df_out


def train_memory_model(
    dataset_path: str | Path = "data/processed/unified/unified_dataset.jsonl",
    output_dir: str | Path = "models/artifacts/memory",
    eval_dir: str | Path = "evaluation/binary",
    random_state: int = 42,
) -> dict[str, Any]:
    """Train, validate, and evaluate the Memory CatBoost binary classifier.

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

    # Modality isolation: engineer features strictly within memory scope
    df = _engineer_memory_features(df)
    active_features = [f for f in PERMITTED_MEMORY_FEATURES if f in df.columns]

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

    X_train = df_train[active_features].values.astype(float)
    X_val = df_val[active_features].values.astype(float)

    hyperparams = {
        "iterations": 100,
        "depth": 3,
        "learning_rate": 0.05,
        "random_seed": random_state,
        "nan_mode": "Min",
        "verbose": False,
    }

    cat_clf = CatBoostClassifier(**hyperparams)
    cat_clf.fit(
        X_train,
        y_train,
        eval_set=(X_val, y_val),
        early_stopping_rounds=20,
    )

    # Wrap in MemoryModel
    memory_model = MemoryModel(
        classifier=cat_clf,
        feature_names=active_features,
    )

    # Evaluate on test set (and validation set for reference)
    val_probs = memory_model.predict_proba(df_val)
    val_metrics = compute_binary_metrics(y_val, val_probs)

    test_probs = memory_model.predict_proba(df_test)
    test_metrics = compute_binary_metrics(y_test, test_probs)

    logger.info("Test Metrics for Memory Model (CatBoost): %s", test_metrics)

    # Metadata specification
    metadata: dict[str, Any] = {
        "model_type": "catboost",
        "modality": "memory",
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
        "random_seed": random_state,
        "hyperparameters": hyperparams,
        "training_timestamp": datetime.now(tz=UTC).isoformat(),
        "software_versions": {
            "catboost": get_package_version("catboost"),
            "scikit-learn": get_package_version("scikit-learn"),
            "pandas": get_package_version("pandas"),
        },
        "git_commit": get_git_commit(),
        "small_dataset_warning": SMALL_DATASET_WARNING,
    }

    # Save model artifacts
    memory_model.save(out_path)
    (out_path / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    # Save evaluation report
    eval_report = {
        "model": "MemoryModel (CatBoost)",
        "modality": "memory",
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics,
        "metadata": metadata,
    }
    eval_file = eval_path / "memory_evaluation.json"
    eval_file.write_text(json.dumps(eval_report, indent=2), encoding="utf-8")

    logger.info("Memory model artifacts saved to %s", out_path)
    logger.info("Memory evaluation report saved to %s", eval_file)

    return eval_report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Memory CatBoost Model")
    parser.add_argument("--dataset", default="data/processed/unified/unified_dataset.jsonl")
    parser.add_argument("--output-dir", default="models/artifacts/memory")
    parser.add_argument("--eval-dir", default="evaluation/binary")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    train_memory_model(
        dataset_path=args.dataset,
        output_dir=args.output_dir,
        eval_dir=args.eval_dir,
        random_state=args.seed,
    )
