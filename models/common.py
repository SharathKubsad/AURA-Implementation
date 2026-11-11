"""Common utilities for fileless malware binary model training and evaluation.

Provides:
- Strict binary evaluation metric computation (accuracy, precision, recall, f1, ROC-AUC, confusion matrix, FPR, FNR)
- Deterministic stratified splitting ensuring both classes exist in train, validation, and test
- Git commit extraction and metadata helpers
- Common prediction interface protocols
"""

from __future__ import annotations

import subprocess
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedShuffleSplit

SMALL_DATASET_WARNING: str = (
    "WARNING: This model was trained on an extremely small custom dataset (45 samples). "
    "Metrics are intended solely for pipeline and architecture validation. "
    "Do NOT treat these results as production-grade or statistically conclusive without benchmark dataset merging."
)


def compute_binary_metrics(
    y_true: np.ndarray | list[int] | pd.Series,
    y_prob: np.ndarray | list[float] | pd.Series,
    threshold: float = 0.5,
) -> dict[str, Any]:
    """Compute binary classification metrics with zero fabrication and strict bounds.

    Args:
        y_true: Ground-truth binary labels (0 or 1).
        y_prob: Predicted malware probabilities in [0.0, 1.0], shape (N,).
        threshold: Decision threshold for positive classification (default: 0.5).

    Returns:
        Dictionary containing accuracy, precision, recall, f1, roc_auc (or null),
        confusion_matrix [[TN, FP], [FN, TP]], fpr, fnr, and sample counts.
    """
    y_true_arr = np.asarray(y_true, dtype=int).ravel()
    y_prob_arr = np.asarray(y_prob, dtype=float).ravel()

    if len(y_true_arr) != len(y_prob_arr):
        raise ValueError(
            f"Length mismatch: y_true has {len(y_true_arr)} elements, y_prob has {len(y_prob_arr)}"
        )

    # Threshold probability to produce binary prediction
    y_pred_arr = (y_prob_arr >= threshold).astype(int)

    acc = float(accuracy_score(y_true_arr, y_pred_arr)) if len(y_true_arr) > 0 else 0.0
    prec = float(precision_score(y_true_arr, y_pred_arr, zero_division=0))
    rec = float(recall_score(y_true_arr, y_pred_arr, zero_division=0))
    f1 = float(f1_score(y_true_arr, y_pred_arr, zero_division=0))

    # ROC-AUC is mathematically undefined if only one class is present in y_true
    unique_classes = np.unique(y_true_arr)
    if len(unique_classes) > 1:
        try:
            auc: float | None = round(float(roc_auc_score(y_true_arr, y_prob_arr)), 4)
        except Exception:
            auc = None
    else:
        auc = None

    # Confusion matrix formatted as [[TN, FP], [FN, TP]]
    cm = confusion_matrix(y_true_arr, y_pred_arr, labels=[0, 1])
    tn, fp = int(cm[0, 0]), int(cm[0, 1])
    fn, tp = int(cm[1, 0]), int(cm[1, 1])

    # FPR = FP / (FP + TN), FNR = FN / (FN + TP)
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "roc_auc": auc,
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "fpr": round(fpr, 4),
        "fnr": round(fnr, 4),
        "threshold": threshold,
        "total_samples": len(y_true_arr),
        "true_benign_count": int(np.sum(y_true_arr == 0)),
        "true_malware_count": int(np.sum(y_true_arr == 1)),
    }


def stratified_split_dataset(
    df: pd.DataFrame,
    target_col: str = "binary_label",
    test_size: float = 0.15,
    val_size: float = 0.15,
    random_state: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Perform deterministic stratified 70/15/15 train/val/test splitting.

    Validates that each partition contains at least one sample of each binary class.

    Args:
        df: Input DataFrame containing target_col.
        target_col: Column containing binary target (0 or 1).
        test_size: Fraction of samples for test partition (default: 0.15).
        val_size: Fraction of samples for validation partition (default: 0.15).
        random_state: Seed for reproducible splitting.

    Returns:
        Tuple of (df_train, df_val, df_test).

    Raises:
        ValueError: If splitting fails to preserve both classes in all partitions.
    """
    if target_col not in df.columns:
        raise KeyError(f"Target column '{target_col}' not in DataFrame columns")

    y = df[target_col].astype(int).values
    if len(np.unique(y)) < 2:
        raise ValueError("Cannot perform stratified split with fewer than 2 target classes.")

    # 1. Carve test set from full dataset
    sss_test = StratifiedShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    train_val_idx, test_idx = next(sss_test.split(df, y))

    df_train_val = df.iloc[train_val_idx].reset_index(drop=True)
    df_test = df.iloc[test_idx].reset_index(drop=True)

    # 2. Carve validation set from train_val partition
    # Relative validation size: val_size / (1.0 - test_size)
    relative_val_size = val_size / (1.0 - test_size)
    y_tv = df_train_val[target_col].astype(int).values

    sss_val = StratifiedShuffleSplit(
        n_splits=1, test_size=relative_val_size, random_state=random_state
    )
    train_idx, val_idx = next(sss_val.split(df_train_val, y_tv))

    df_train = df_train_val.iloc[train_idx].reset_index(drop=True)
    df_val = df_train_val.iloc[val_idx].reset_index(drop=True)

    # 3. Enforce class presence invariant across all three sets
    for split_name, split_df in [("train", df_train), ("validation", df_val), ("test", df_test)]:
        split_classes = set(split_df[target_col].unique())
        if not {0, 1}.issubset(split_classes):
            raise ValueError(
                f"Stratified split failed: {split_name} partition missing required binary classes. "
                f"Found classes: {split_classes}"
            )

    return df_train, df_val, df_test


def get_git_commit() -> str | None:
    """Retrieve current Git commit hash if running in a Git repository."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        return res.stdout.strip()
    except Exception:
        return None


def get_package_version(package_name: str) -> str:
    """Safely return installed package version."""
    try:
        import importlib.metadata

        return importlib.metadata.version(package_name)
    except Exception:
        return "unknown"
