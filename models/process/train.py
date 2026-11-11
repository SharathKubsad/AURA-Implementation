"""Training pipeline for Process Model (XGBoost).

Trains an XGBClassifier strictly on process telemetry features using deterministic
stratified splitting (70/15/15) and zero-leakage preprocessing.
"""

from __future__ import annotations

import argparse
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from models.common import (
    SMALL_DATASET_WARNING,
    compute_binary_metrics,
    get_git_commit,
    get_package_version,
    stratified_split_dataset,
)
from models.process.model import PERMITTED_PROCESS_FEATURES, ProcessModel

logger = logging.getLogger("train_process")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def _engineer_process_features(df: pd.DataFrame) -> pd.DataFrame:
    """Compute permitted process-modality engineered features."""
    df_out = df.copy()
    if "avg_threads_per_process" in df_out.columns and "total_process_count" in df_out.columns:
        df_out["thread_to_process_ratio"] = df_out["avg_threads_per_process"] / (
            df_out["total_process_count"].replace(0, 1.0)
        )
    return df_out


def train_process_model(
    dataset_path: str | Path = "data/processed/unified/unified_dataset.jsonl",
    output_dir: str | Path = "models/artifacts/process",
    eval_dir: str | Path = "evaluation/binary",
    random_state: int = 42,
) -> dict[str, Any]:
    """Train, validate, and evaluate the Process XGBoost binary classifier.

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

    # Load data
    if data_file.suffix == ".jsonl":
        import json

        rows = [
            json.loads(line)
            for line in data_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        df = pd.DataFrame(rows)
    else:
        df = pd.read_csv(data_file)

    logger.info("Loaded %d total samples from %s", len(df), data_file)

    # Modality isolation: engineer features strictly within process scope
    df = _engineer_process_features(df)
    active_features = [f for f in PERMITTED_PROCESS_FEATURES if f in df.columns]

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

    # Preprocessing: Fit scaler ONLY on train
    scaler = StandardScaler()
    X_train_raw = df_train[active_features].values.astype(float)
    X_train = scaler.fit_transform(X_train_raw)

    X_val_raw = df_val[active_features].values.astype(float)
    X_val = scaler.transform(X_val_raw)

    # Conservative hyperparameters for tiny dataset (prevent overfitting)
    hyperparams = {
        "n_estimators": 100,
        "max_depth": 3,
        "learning_rate": 0.05,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "random_state": random_state,
        "eval_metric": "logloss",
    }

    xgb_clf = XGBClassifier(**hyperparams)
    xgb_clf.fit(
        X_train,
        y_train,
        eval_set=[(X_val, y_val)],
        verbose=False,
    )

    # Wrap in ProcessModel
    process_model = ProcessModel(
        classifier=xgb_clf,
        feature_names=active_features,
        scaler=scaler,
    )

    # Evaluate on test set (and validation set for reference)
    val_probs = process_model.predict_proba(df_val)
    val_metrics = compute_binary_metrics(y_val, val_probs)

    test_probs = process_model.predict_proba(df_test)
    test_metrics = compute_binary_metrics(y_test, test_probs)

    logger.info("Test Metrics for Process Model (XGBoost): %s", test_metrics)

    # Metadata specification
    metadata: dict[str, Any] = {
        "model_type": "xgboost",
        "modality": "process",
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
            "xgboost": get_package_version("xgboost"),
            "scikit-learn": get_package_version("scikit-learn"),
            "pandas": get_package_version("pandas"),
        },
        "git_commit": get_git_commit(),
        "small_dataset_warning": SMALL_DATASET_WARNING,
    }

    # Save model artifacts
    process_model.save(out_path)
    (out_path / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    # Save evaluation report
    eval_report = {
        "model": "ProcessModel (XGBoost)",
        "modality": "process",
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics,
        "metadata": metadata,
    }
    eval_file = eval_path / "process_evaluation.json"
    eval_file.write_text(json.dumps(eval_report, indent=2), encoding="utf-8")

    logger.info("Process model artifacts saved to %s", out_path)
    logger.info("Process evaluation report saved to %s", eval_file)

    return eval_report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Process XGBoost Model")
    parser.add_argument("--dataset", default="data/processed/unified/unified_dataset.jsonl")
    parser.add_argument("--output-dir", default="models/artifacts/process")
    parser.add_argument("--eval-dir", default="evaluation/binary")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    train_process_model(
        dataset_path=args.dataset,
        output_dir=args.output_dir,
        eval_dir=args.eval_dir,
        random_state=args.seed,
    )
