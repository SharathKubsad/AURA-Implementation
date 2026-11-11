"""Benchmark Training Pipeline for CIC-MalMem-2022 (Process & Memory Models).

Trains:
1. Process Model: XGBoost on shared compatible process features
2. Memory Model: CatBoost on shared compatible memory features

Features are strictly limited to those classified as DIRECTLY_COMPARABLE or
COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION in data/processed/public/cross_dataset_compatibility.json.
Features classified as NOT_COMPARABLE are strictly excluded.
"""

from __future__ import annotations

import argparse
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from catboost import CatBoostClassifier
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from models.common import compute_binary_metrics, get_git_commit, get_package_version

logger = logging.getLogger("train_malmem")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

REPO_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Strict Feature Definitions based on Cross-Dataset Compatibility Audit
# ---------------------------------------------------------------------------

PROCESS_FEATURES_USED: list[str] = [
    "total_process_count",
    "hidden_process_count",
    "avg_threads_per_process",
    "total_handle_count",
    "malfind_process_count",
    "unlinked_dll_count",
]

PROCESS_FEATURES_EXCLUDED: dict[str, str] = {
    "anomalous_ppid_count": "NOT_COMPARABLE. 100% missing in MalMem. Parent-child lineage rules not run.",
    "max_threads_in_single_process": "NOT_COMPARABLE. 100% missing in MalMem. Only dataset average was recorded.",
    "suspicious_dll_count": "NOT_COMPARABLE. 100% missing in MalMem. Path-based DLL staging audit not run.",
    "elevated_privilege_count": "NOT_COMPARABLE. 100% missing in MalMem. Windows privileges plugin not run.",
}

MEMORY_FEATURES_USED: list[str] = [
    "rwx_page_count",
    "injected_code_regions",
    "unmapped_executable_pages",
    "ldrmodules_inconsistencies",
]

MEMORY_FEATURES_EXCLUDED: dict[str, str] = {
    "vad_protection_anomaly_count": (
        "MALMEM_SPECIFIC_PROXY. Incompatible semantic definitions. "
        "Custom feature detects true VirtualProtect state modification (InitProtection != Protection); "
        "MalMem proxies commit charge on injected pages (commitCharge > 0). "
        "Strictly excluded from zero-shot cross-domain evaluation."
    ),
    "yara_shellcode_matches": "NOT_COMPARABLE. 100% missing in MalMem. YARA shellcode scans not run.",
    "mean_memory_entropy": "NOT_COMPARABLE. 100% missing in MalMem. Raw memory bytes not preserved.",
    "max_memory_entropy": "NOT_COMPARABLE. 100% missing in MalMem. Raw memory bytes not preserved.",
}

RAW_DATASET_CHECKSUM = "624ecb6c9229cf62bd3b8f65d23a2b132760e6bada458aa46eee134a313840c4"
ADAPTER_VERSION = "1.0.0"


def load_malmem_dataset(samples_path: Path) -> pd.DataFrame:
    """Load pre-validated interim MalMem samples into a unified DataFrame.

    Args:
        samples_path: Path to data/interim/public/cic_malmem_2022/samples.jsonl

    Returns:
        pd.DataFrame containing sample_id, binary_label, family, and flattened features.
    """
    if not samples_path.is_file():
        raise FileNotFoundError(f"Interim samples file not found: {samples_path}")

    records: list[dict[str, Any]] = []
    with open(samples_path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
            row: dict[str, Any] = {
                "sample_id": rec["sample_id"],
                "binary_label": int(rec["binary_label"]),
                "family": rec.get("family", "unknown"),
                "category": rec.get("category", "unknown"),
            }
            # Flatten process features
            proc = rec.get("process") or {}
            for k in PROCESS_FEATURES_USED:
                row[k] = proc.get(k)

            # Flatten memory features
            mem = rec.get("memory") or {}
            for k in MEMORY_FEATURES_USED:
                row[k] = mem.get(k)

            records.append(row)

    df = pd.DataFrame(records)
    logger.info(f"Loaded {len(df):,} MalMem samples from {samples_path}")
    return df


def split_malmem_dataset(
    df: pd.DataFrame,
    test_size: float = 0.15,
    val_size: float = 0.15,
    random_state: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, dict[str, Any]]:
    """Perform deterministic stratified train/validation/test split with temporal leakage analysis.

    Args:
        df: Input DataFrame.
        test_size: Fraction for test partition.
        val_size: Fraction for validation partition.
        random_state: Seed for reproducibility.

    Returns:
        Tuple of (train_df, val_df, test_df, split_metadata).
    """
    # 1. Investigate grouping identifiers for temporal leakage control
    # Check if a session, VM, or timestamp column exists in the dataset
    grouping_possible = False
    grouping_limitation_doc = (
        "CIC-MalMem-2022 contains 29,298 benign memory snapshots taken at 5-second intervals "
        "from the same running VM sessions. However, the published dataset does NOT provide "
        "session IDs, VM instance IDs, timestamps, or operator identifiers. Grouping by family "
        "is impossible for benign samples because all 29,298 share a single 'benign' label. "
        "Therefore, ordinary stratified random splitting is applied, but with this explicitly documented "
        "limitation: test set metrics reflect in-distribution evaluation and cannot guarantee independence "
        "from temporal autocorrelation in the benign class."
    )

    y = df["binary_label"].values

    # Step 1: Split into train_val and test
    sss_test = StratifiedShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    train_val_idx, test_idx = next(sss_test.split(df, y))

    df_train_val = df.iloc[train_val_idx].copy().reset_index(drop=True)
    df_test = df.iloc[test_idx].copy().reset_index(drop=True)

    # Step 2: Split train_val into train and val
    val_ratio_of_train_val = val_size / (1.0 - test_size)
    sss_val = StratifiedShuffleSplit(
        n_splits=1, test_size=val_ratio_of_train_val, random_state=random_state
    )
    y_train_val = df_train_val["binary_label"].values
    train_idx, val_idx = next(sss_val.split(df_train_val, y_train_val))

    df_train = df_train_val.iloc[train_idx].copy().reset_index(drop=True)
    df_val = df_train_val.iloc[val_idx].copy().reset_index(drop=True)

    split_meta = {
        "random_state": random_state,
        "split_ratios": {"train": 1.0 - test_size - val_size, "val": val_size, "test": test_size},
        "sample_counts": {
            "total": len(df),
            "train": len(df_train),
            "val": len(df_val),
            "test": len(df_test),
        },
        "class_distribution": {
            "train": {
                "benign": int((df_train["binary_label"] == 0).sum()),
                "malware": int((df_train["binary_label"] == 1).sum()),
            },
            "val": {
                "benign": int((df_val["binary_label"] == 0).sum()),
                "malware": int((df_val["binary_label"] == 1).sum()),
            },
            "test": {
                "benign": int((df_test["binary_label"] == 0).sum()),
                "malware": int((df_test["binary_label"] == 1).sum()),
            },
        },
        "grouping_possible": grouping_possible,
        "temporal_limitation_warning": grouping_limitation_doc,
    }

    logger.info(
        f"Splits created: Train={len(df_train):,} ({split_meta['class_distribution']['train']}), "
        f"Val={len(df_val):,} ({split_meta['class_distribution']['val']}), "
        f"Test={len(df_test):,} ({split_meta['class_distribution']['test']})"
    )
    return df_train, df_val, df_test, split_meta


def train_process_xgboost(
    df_train: pd.DataFrame,
    df_val: pd.DataFrame,
    df_test: pd.DataFrame,
    split_meta: dict[str, Any],
    artifacts_dir: Path,
    eval_dir: Path,
    random_state: int = 42,
) -> dict[str, Any]:
    """Train XGBoost model on CIC-MalMem-2022 process features."""
    logger.info("--- Training Process Model (XGBoost) on CIC-MalMem-2022 ---")
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    eval_dir.mkdir(parents=True, exist_ok=True)

    X_train_raw = df_train[PROCESS_FEATURES_USED].values.astype(float)
    y_train = df_train["binary_label"].values.astype(int)

    X_val_raw = df_val[PROCESS_FEATURES_USED].values.astype(float)
    y_val = df_val["binary_label"].values.astype(int)

    X_test_raw = df_test[PROCESS_FEATURES_USED].values.astype(float)
    y_test = df_test["binary_label"].values.astype(int)

    # Fit scaler strictly on training partition
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_val = scaler.transform(X_val_raw)
    X_test = scaler.transform(X_test_raw)

    hyperparams = {
        "n_estimators": 100,
        "max_depth": 5,
        "learning_rate": 0.05,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "eval_metric": "logloss",
        "random_state": random_state,
        "tree_method": "hist",
    }

    model = XGBClassifier(**hyperparams)
    model.fit(
        X_train,
        y_train,
        eval_set=[(X_val, y_val)],
        verbose=False,
    )

    # Evaluation
    val_probs = model.predict_proba(X_val)[:, 1]
    test_probs = model.predict_proba(X_test)[:, 1]

    val_metrics = compute_binary_metrics(y_val, val_probs)
    test_metrics = compute_binary_metrics(y_test, test_probs)

    logger.info(
        f"Process Model Test Results: Acc={test_metrics['accuracy']:.4f}, "
        f"F1={test_metrics['f1']:.4f}, ROC-AUC={test_metrics['roc_auc']:.4f}, "
        f"FPR={test_metrics['fpr']:.4f}, FNR={test_metrics['fnr']:.4f}"
    )

    # Save artifacts
    model_path = artifacts_dir / "xgboost_model.json"
    model.save_model(str(model_path))

    scaler_path = artifacts_dir / "scaler.joblib"
    joblib.dump(scaler, scaler_path)

    features_path = artifacts_dir / "features_used.json"
    with open(features_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "features_used": PROCESS_FEATURES_USED,
                "features_excluded": PROCESS_FEATURES_EXCLUDED,
            },
            f,
            indent=2,
        )

    meta_payload = {
        "model_name": "public_cic_malmem_process_xgboost",
        "architecture": "XGBoost",
        "dataset_name": "CIC-MalMem-2022",
        "dataset_checksum": RAW_DATASET_CHECKSUM,
        "adapter_version": ADAPTER_VERSION,
        "trained_at": datetime.now(UTC).isoformat(),
        "git_commit": get_git_commit(),
        "xgboost_version": get_package_version("xgboost"),
        "features_used": PROCESS_FEATURES_USED,
        "features_excluded": PROCESS_FEATURES_EXCLUDED,
        "hyperparameters": hyperparams,
        "split_metadata": split_meta,
    }
    with open(artifacts_dir / "training_metadata.json", "w", encoding="utf-8") as f:
        json.dump(meta_payload, f, indent=2)

    eval_report = {
        **meta_payload,
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics,
    }
    with open(eval_dir / "process_evaluation.json", "w", encoding="utf-8") as f:
        json.dump(eval_report, f, indent=2)

    return eval_report


def train_memory_catboost(
    df_train: pd.DataFrame,
    df_val: pd.DataFrame,
    df_test: pd.DataFrame,
    split_meta: dict[str, Any],
    artifacts_dir: Path,
    eval_dir: Path,
    random_state: int = 42,
) -> dict[str, Any]:
    """Train CatBoost model on CIC-MalMem-2022 memory features."""
    logger.info("--- Training Memory Model (CatBoost) on CIC-MalMem-2022 ---")
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    eval_dir.mkdir(parents=True, exist_ok=True)

    X_train = df_train[MEMORY_FEATURES_USED].values.astype(float)
    y_train = df_train["binary_label"].values.astype(int)

    X_val = df_val[MEMORY_FEATURES_USED].values.astype(float)
    y_val = df_val["binary_label"].values.astype(int)

    X_test = df_test[MEMORY_FEATURES_USED].values.astype(float)
    y_test = df_test["binary_label"].values.astype(int)

    hyperparams = {
        "iterations": 150,
        "depth": 5,
        "learning_rate": 0.05,
        "loss_function": "Logloss",
        "eval_metric": "Logloss",
        "random_seed": random_state,
        "verbose": 0,
    }

    model = CatBoostClassifier(**hyperparams)
    model.fit(
        X_train,
        y_train,
        eval_set=(X_val, y_val),
        early_stopping_rounds=20,
        verbose=False,
    )

    # Evaluation
    val_probs = model.predict_proba(X_val)[:, 1]
    test_probs = model.predict_proba(X_test)[:, 1]

    val_metrics = compute_binary_metrics(y_val, val_probs)
    test_metrics = compute_binary_metrics(y_test, test_probs)

    logger.info(
        f"Memory Model Test Results: Acc={test_metrics['accuracy']:.4f}, "
        f"F1={test_metrics['f1']:.4f}, ROC-AUC={test_metrics['roc_auc']:.4f}, "
        f"FPR={test_metrics['fpr']:.4f}, FNR={test_metrics['fnr']:.4f}"
    )

    # Save artifacts
    model_path = artifacts_dir / "catboost_model.cbm"
    model.save_model(str(model_path))

    features_path = artifacts_dir / "features_used.json"
    with open(features_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "features_used": MEMORY_FEATURES_USED,
                "features_excluded": MEMORY_FEATURES_EXCLUDED,
            },
            f,
            indent=2,
        )

    meta_payload = {
        "model_name": "public_cic_malmem_memory_catboost",
        "architecture": "CatBoost",
        "dataset_name": "CIC-MalMem-2022",
        "dataset_checksum": RAW_DATASET_CHECKSUM,
        "adapter_version": ADAPTER_VERSION,
        "trained_at": datetime.now(UTC).isoformat(),
        "git_commit": get_git_commit(),
        "catboost_version": get_package_version("catboost"),
        "features_used": MEMORY_FEATURES_USED,
        "features_excluded": MEMORY_FEATURES_EXCLUDED,
        "hyperparameters": hyperparams,
        "split_metadata": split_meta,
    }
    with open(artifacts_dir / "training_metadata.json", "w", encoding="utf-8") as f:
        json.dump(meta_payload, f, indent=2)

    eval_report = {
        **meta_payload,
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics,
    }
    with open(eval_dir / "memory_evaluation.json", "w", encoding="utf-8") as f:
        json.dump(eval_report, f, indent=2)

    return eval_report


def run_benchmark_training(
    interim_samples: Path = REPO_ROOT
    / "data"
    / "interim"
    / "public"
    / "cic_malmem_2022"
    / "samples.jsonl",
    process_artifacts: Path = REPO_ROOT / "models" / "artifacts" / "public_cic_malmem" / "process",
    memory_artifacts: Path = REPO_ROOT / "models" / "artifacts" / "public_cic_malmem" / "memory",
    eval_dir: Path = REPO_ROOT / "evaluation" / "public_cic_malmem",
    random_state: int = 42,
) -> dict[str, Any]:
    """Orchestrate training of both CIC-MalMem benchmark models."""
    df = load_malmem_dataset(interim_samples)
    df_train, df_val, df_test, split_meta = split_malmem_dataset(
        df, test_size=0.15, val_size=0.15, random_state=random_state
    )

    proc_eval = train_process_xgboost(
        df_train, df_val, df_test, split_meta, process_artifacts, eval_dir, random_state
    )
    mem_eval = train_memory_catboost(
        df_train, df_val, df_test, split_meta, memory_artifacts, eval_dir, random_state
    )

    consolidated = {
        "dataset_name": "CIC-MalMem-2022",
        "benchmark_strategy": "Strategy C (Separate Domain-Specific Benchmark Models)",
        "generated_at": datetime.now(UTC).isoformat(),
        "models": {
            "process": {
                "algorithm": "XGBoost",
                "features_count": len(PROCESS_FEATURES_USED),
                "features_used": PROCESS_FEATURES_USED,
                "test_metrics": proc_eval["test_metrics"],
            },
            "memory": {
                "algorithm": "CatBoost",
                "features_count": len(MEMORY_FEATURES_USED),
                "features_used": MEMORY_FEATURES_USED,
                "test_metrics": mem_eval["test_metrics"],
            },
        },
        "temporal_grouping_limitation": split_meta["temporal_limitation_warning"],
    }

    consolidated_path = eval_dir / "consolidated_report.json"
    with open(consolidated_path, "w", encoding="utf-8") as f:
        json.dump(consolidated, f, indent=2)

    logger.info(f"Consolidated benchmark report saved to {consolidated_path}")
    return consolidated


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description="Train CIC-MalMem Benchmark Models")
    parser.add_argument("--seed", type=int, default=42, help="Random state seed")
    args = parser.parse_args()

    run_benchmark_training(random_state=args.seed)


if __name__ == "__main__":
    main()
