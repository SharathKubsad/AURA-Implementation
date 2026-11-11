"""Orchestrator for training all 4 fileless malware binary detection models.

Trains:
1. Process Model -> XGBoost (Process telemetry)
2. Command Model -> DistilBERT (Raw command strings)
3. Network Model -> LightGBM (Network telemetry, native NaN preservation)
4. Memory Model  -> CatBoost (Volatile memory forensics, nan_mode='Min')

Verifies dependencies, checks dataset integrity, trains models without data leakage,
saves artifacts to models/artifacts/, evaluates against test partitions, and produces
a consolidated report in evaluation/binary/consolidated_report.json.
"""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Ensure repo root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from models.command.train import train_command_model
from models.common import SMALL_DATASET_WARNING, get_git_commit
from models.memory.train import train_memory_model
from models.network.train import train_network_model
from models.process.train import train_process_model
from tools.audit_unified_dataset import audit_unified_dataset

logger = logging.getLogger("train_all_models")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

REQUIRED_DEPENDENCIES = {
    "xgboost": "xgboost",
    "lightgbm": "lightgbm",
    "catboost": "catboost",
    "torch": "torch",
    "transformers": "transformers",
    "sklearn": "scikit-learn",
}


def check_dependencies() -> dict[str, bool]:
    """Verify presence of all required ML and deep learning libraries."""
    status = {}
    for module_name in REQUIRED_DEPENDENCIES:
        try:
            __import__(module_name)
            status[module_name] = True
        except ImportError:
            status[module_name] = False
    return status


def verify_dataset(unified_dir: Path) -> dict[str, Any]:
    """Verify that unified dataset exists and passes the audit."""
    jsonl_file = unified_dir / "unified_dataset.jsonl"
    if not jsonl_file.exists():
        raise FileNotFoundError(
            f"Unified dataset not found at {jsonl_file}. Run tools/build_unified_dataset.py first."
        )

    audit_result = audit_unified_dataset(unified_dir)
    invalid_count = audit_result["summary"]["status_counts"].get("invalid", 0)
    if invalid_count > 0:
        raise ValueError(
            f"Unified dataset failed audit: {invalid_count} invalid samples detected. "
            "Resolve dataset integrity issues before training."
        )

    return audit_result


def train_all_models(
    unified_dir: str | Path = "data/processed/unified",
    artifacts_root: str | Path = "models/artifacts",
    eval_dir: str | Path = "evaluation/binary",
    random_state: int = 42,
) -> dict[str, Any]:
    """Execute training for all four binary detection models.

    Args:
        unified_dir: Directory containing unified_dataset.jsonl.
        artifacts_root: Base directory for model artifacts.
        eval_dir: Directory for evaluation reports.
        random_state: RNG seed for reproducible splitting and model initialization.

    Returns:
        Consolidated evaluation and training report.
    """
    u_path = Path(unified_dir)
    art_path = Path(artifacts_root)
    ev_path = Path(eval_dir)
    ev_path.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 65)
    print("  FILELESS MALWARE DETECTION — BINARY MODEL TRAINING PIPELINE")
    print("=" * 65)

    # 1. Check dependencies
    print("\n[*] Checking required ML dependencies...")
    dep_status = check_dependencies()
    missing_deps = [m for m, ok in dep_status.items() if not ok]
    for mod, ok in dep_status.items():
        print(f"    - {REQUIRED_DEPENDENCIES[mod]:<15}: {'AVAILABLE' if ok else 'MISSING'}")

    if missing_deps:
        err_msg = (
            f"Missing required dependencies: {missing_deps}. "
            f"Please run: py -3 -m pip install {' '.join(REQUIRED_DEPENDENCIES[m] for m in missing_deps)}"
        )
        logger.error(err_msg)
        raise RuntimeError(err_msg)

    # 2. Verify dataset integrity
    print("\n[*] Verifying unified dataset integrity...")
    audit_report = verify_dataset(u_path)
    total_samples = audit_report["summary"]["total_samples"]
    label_dist = audit_report["summary"]["label_distribution"]
    print(f"    - Total validated samples: {total_samples}")
    print(f"    - Class distribution:      {label_dist}")
    print("    - Dataset audit status:    ALL SAMPLES VALID (0 invalid)")

    dataset_jsonl = u_path / "unified_dataset.jsonl"
    model_reports: dict[str, Any] = {}
    failures: dict[str, str] = {}

    # 3. Train Process Model (XGBoost)
    print("\n" + "-" * 65)
    print("  [1/4] Training Process Model (XGBoost)")
    print("-" * 65)
    try:
        proc_eval = train_process_model(
            dataset_path=dataset_jsonl,
            output_dir=art_path / "process",
            eval_dir=ev_path,
            random_state=random_state,
        )
        model_reports["process"] = proc_eval
        print(
            f"    => Process Model Test F1: {proc_eval['test_metrics']['f1']:.4f} (Accuracy: {proc_eval['test_metrics']['accuracy']:.4f})"
        )
    except Exception as exc:
        logger.error("Process model training failed: %s", exc)
        failures["process"] = str(exc)

    # 4. Train Command Model (DistilBERT)
    print("\n" + "-" * 65)
    print("  [2/4] Training Command Model (DistilBERT)")
    print("-" * 65)
    try:
        cmd_eval = train_command_model(
            dataset_path=dataset_jsonl,
            output_dir=art_path / "command",
            eval_dir=ev_path,
            epochs=3,
            random_state=random_state,
        )
        model_reports["command"] = cmd_eval
        print(
            f"    => Command Model Test F1: {cmd_eval['test_metrics']['f1']:.4f} (Accuracy: {cmd_eval['test_metrics']['accuracy']:.4f})"
        )
    except Exception as exc:
        logger.error("Command model training failed: %s", exc)
        failures["command"] = str(exc)

    # 5. Train Network Model (LightGBM)
    print("\n" + "-" * 65)
    print("  [3/4] Training Network Model (LightGBM)")
    print("-" * 65)
    try:
        net_eval = train_network_model(
            dataset_path=dataset_jsonl,
            output_dir=art_path / "network",
            eval_dir=ev_path,
            random_state=random_state,
        )
        model_reports["network"] = net_eval
        print(
            f"    => Network Model Test F1: {net_eval['test_metrics']['f1']:.4f} (Accuracy: {net_eval['test_metrics']['accuracy']:.4f})"
        )
    except Exception as exc:
        logger.error("Network model training failed: %s", exc)
        failures["network"] = str(exc)

    # 6. Train Memory Model (CatBoost)
    print("\n" + "-" * 65)
    print("  [4/4] Training Memory Model (CatBoost)")
    print("-" * 65)
    try:
        mem_eval = train_memory_model(
            dataset_path=dataset_jsonl,
            output_dir=art_path / "memory",
            eval_dir=ev_path,
            random_state=random_state,
        )
        model_reports["memory"] = mem_eval
        print(
            f"    => Memory Model Test F1: {mem_eval['test_metrics']['f1']:.4f} (Accuracy: {mem_eval['test_metrics']['accuracy']:.4f})"
        )
    except Exception as exc:
        logger.error("Memory model training failed: %s", exc)
        failures["memory"] = str(exc)

    # 7. Consolidated Summary
    comparison_table = []
    for mod, rep in model_reports.items():
        tm = rep["test_metrics"]
        comparison_table.append(
            {
                "modality": mod,
                "architecture": rep["model"],
                "accuracy": tm["accuracy"],
                "precision": tm["precision"],
                "recall": tm["recall"],
                "f1": tm["f1"],
                "roc_auc": tm["roc_auc"],
                "fpr": tm["fpr"],
                "fnr": tm["fnr"],
                "confusion_matrix": tm["confusion_matrix"],
            }
        )

    consolidated = {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "git_commit": get_git_commit(),
        "small_dataset_warning": SMALL_DATASET_WARNING,
        "dataset_summary": {
            "total_samples": total_samples,
            "label_distribution": label_dist,
            "split_ratios": {"train": 0.70, "validation": 0.15, "test": 0.15},
        },
        "models_trained": list(model_reports.keys()),
        "failures": failures,
        "comparison_table": comparison_table,
        "individual_reports": {k: str(ev_path / f"{k}_evaluation.json") for k in model_reports},
        "artifact_directories": {k: str(art_path / k) for k in model_reports},
    }

    report_file = ev_path / "consolidated_report.json"
    report_file.write_text(json.dumps(consolidated, indent=2), encoding="utf-8")
    print("\n" + "=" * 65)
    print("  TRAINING COMPLETE — CONSOLIDATED EVALUATION REPORT")
    print("=" * 65)
    print(f"Report saved: {report_file}")
    print(
        "\n"
        + f"{'Modality':<10} {'Architecture':<25} {'Accuracy':<10} {'F1':<8} {'ROC-AUC':<10} {'FPR':<8} {'FNR':<8}"
    )
    print("-" * 79)
    for row in comparison_table:
        auc_str = f"{row['roc_auc']:.4f}" if row["roc_auc"] is not None else "N/A"
        print(
            f"{row['modality']:<10} {row['architecture']:<25} {row['accuracy']:<10.4f} "
            f"{row['f1']:<8.4f} {auc_str:<10} {row['fpr']:<8.4f} {row['fnr']:<8.4f}"
        )
    print("=" * 79)
    print(f"\n[!] Note: {SMALL_DATASET_WARNING}\n")

    return consolidated


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train all 4 fileless malware binary detection models"
    )
    parser.add_argument("--unified-dir", default="data/processed/unified")
    parser.add_argument("--artifacts-root", default="models/artifacts")
    parser.add_argument("--eval-dir", default="evaluation/binary")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    train_all_models(
        unified_dir=args.unified_dir,
        artifacts_root=args.artifacts_root,
        eval_dir=args.eval_dir,
        random_state=args.seed,
    )
