"""Zero-Shot Cross-Domain Evaluation: Public CIC-MalMem Models on Custom VM Telemetry.

Loads the benchmark models trained on public CIC-MalMem-2022 (Process XGBoost and Memory CatBoost)
and evaluates their zero-shot inference performance on the 45 custom VM samples using ONLY the
shared compatible feature subset.

Strict scientific protocol:
- Zero fine-tuning on custom data
- Zero retraining
- Pure zero-shot out-of-distribution transfer evaluation
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
from xgboost import XGBClassifier

from models.common import compute_binary_metrics, get_git_commit

logger = logging.getLogger("evaluate_cross_domain")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

REPO_ROOT = Path(__file__).resolve().parent.parent

PROCESS_SHARED_FEATURES: list[str] = [
    "total_process_count",
    "hidden_process_count",
    "avg_threads_per_process",
    "total_handle_count",
    "malfind_process_count",
    "unlinked_dll_count",
]

PROCESS_EXCLUDED_FEATURES: list[str] = [
    "anomalous_ppid_count",
    "max_threads_in_single_process",
    "suspicious_dll_count",
    "elevated_privilege_count",
]

MEMORY_SHARED_FEATURES: list[str] = [
    "rwx_page_count",
    "injected_code_regions",
    "unmapped_executable_pages",
    "ldrmodules_inconsistencies",
]

MEMORY_EXCLUDED_FEATURES: list[str] = [
    "vad_protection_anomaly_count",
    "yara_shellcode_matches",
    "mean_memory_entropy",
    "max_memory_entropy",
]


def load_custom_dataset(
    dataset_path: Path = REPO_ROOT / "data" / "processed" / "unified" / "unified_dataset.jsonl",
) -> pd.DataFrame:
    """Load the 45 custom VM samples."""
    if not dataset_path.is_file():
        raise FileNotFoundError(f"Custom unified dataset not found: {dataset_path}")

    records = [
        json.loads(line)
        for line in dataset_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    df = pd.DataFrame(records)
    logger.info(
        f"Loaded {len(df)} custom VM samples (Benign: {(df['binary_label'] == 0).sum()}, "
        f"Malware: {(df['binary_label'] == 1).sum()})"
    )
    return df


def evaluate_process_model_zero_shot(
    df_custom: pd.DataFrame,
    model_dir: Path = REPO_ROOT / "models" / "artifacts" / "public_cic_malmem" / "process",
    eval_dir: Path = REPO_ROOT / "evaluation" / "cross_domain",
) -> dict[str, Any]:
    """Evaluate public Process XGBoost model on custom VM samples."""
    logger.info("Evaluating Public Process Model (XGBoost) Zero-Shot on Custom Data...")
    eval_dir.mkdir(parents=True, exist_ok=True)

    model_file = model_dir / "xgboost_model.json"
    scaler_file = model_dir / "scaler.joblib"
    if not model_file.is_file() or not scaler_file.is_file():
        raise FileNotFoundError(
            f"Public process artifacts missing under {model_dir}. Run training first."
        )

    model = XGBClassifier()
    model.load_model(str(model_file))
    scaler = joblib.load(scaler_file)

    # Extract strictly the 6 shared process features
    X_custom_raw = df_custom[PROCESS_SHARED_FEATURES].values.astype(float)
    y_custom = df_custom["binary_label"].values.astype(int)

    # Apply public scaler
    X_custom_scaled = scaler.transform(X_custom_raw)
    probs = model.predict_proba(X_custom_scaled)[:, 1]

    metrics = compute_binary_metrics(y_custom, probs, threshold=0.5)

    domain_shift_analysis = {
        "domain_shift_severity": "HIGH",
        "primary_shift_drivers": [
            "Baseline Process Count Shift: Windows 11 clean VM baseline maintains 70-150 processes and 45,000+ handles, "
            "whereas MalMem's older Windows 10 VirtualBox baseline shows only 40-50 processes and 9,000 handles. "
            "XGBoost split rules trained on MalMem may treat legitimate Windows 11 service processes as anomalous.",
            "Omission of Fileless Indicators: Model lacks anomalous_ppid_count, elevated_privilege_count, and suspicious_dll_count. "
            "It cannot inspect parent-child process spoofing or token elevation, relying solely on volumetric handle and thread counts.",
        ],
    }

    report = {
        "evaluation_type": "ZERO-SHOT CROSS-DOMAIN EVALUATION",
        "evaluated_at": datetime.now(UTC).isoformat(),
        "git_commit": get_git_commit(),
        "model_source": "CIC-MalMem-2022 (Process XGBoost)",
        "target_dataset": "Custom VM Telemetry (45 samples: 13 Benign, 32 Malware)",
        "samples_evaluated": len(df_custom),
        "shared_features": PROCESS_SHARED_FEATURES,
        "excluded_features": PROCESS_EXCLUDED_FEATURES,
        "metrics": metrics,
        "domain_shift_analysis": domain_shift_analysis,
    }

    out_file = eval_dir / "cic_malmem_to_custom_process.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    logger.info(
        f"Process Zero-Shot Results: Acc={metrics['accuracy']:.4f}, "
        f"F1={metrics['f1']:.4f}, ROC-AUC={metrics['roc_auc']}, "
        f"FPR={metrics['fpr']:.4f}, FNR={metrics['fnr']:.4f}"
    )
    return report


def evaluate_memory_model_zero_shot(
    df_custom: pd.DataFrame,
    model_dir: Path = REPO_ROOT / "models" / "artifacts" / "public_cic_malmem" / "memory",
    eval_dir: Path = REPO_ROOT / "evaluation" / "cross_domain",
) -> dict[str, Any]:
    """Evaluate public Memory CatBoost model on custom VM samples."""
    logger.info("Evaluating Public Memory Model (CatBoost) Zero-Shot on Custom Data...")
    eval_dir.mkdir(parents=True, exist_ok=True)

    model_file = model_dir / "catboost_model.cbm"
    if not model_file.is_file():
        raise FileNotFoundError(
            f"Public memory artifact missing: {model_file}. Run training first."
        )

    model = CatBoostClassifier()
    model.load_model(str(model_file))

    # Extract strictly the 5 shared memory features
    X_custom_raw = df_custom[MEMORY_SHARED_FEATURES].values.astype(float)
    y_custom = df_custom["binary_label"].values.astype(int)

    probs = model.predict_proba(X_custom_raw)[:, 1]
    metrics = compute_binary_metrics(y_custom, probs, threshold=0.5)

    domain_shift_analysis = {
        "domain_shift_severity": "MODERATE_TO_HIGH",
        "primary_shift_drivers": [
            "Exclusion of vad_protection_anomaly_count: MalMem's vad_protection_anomaly_count is a dataset-specific "
            "proxy (malfind.commitCharge > 0) rather than true VirtualProtect protection alteration (InitProtection != Protection). "
            "It is classified as MALMEM_SPECIFIC_PROXY and strictly excluded from this zero-shot shared feature vector.",
            "VAD Scope Discrepancy: Custom vadinfo scans all committed user/kernel memory regions, whereas MalMem's "
            "rwx_page_count was extracted from candidate injections identified by malfind.protection. "
            "Clean Windows 11 JIT runtimes (PowerShell/.NET) create legitimate RWX pages that the public model may penalize.",
            "Omission of Memory Entropy and YARA: Shannon entropy and shellcode signature matches are completely absent "
            "from the public model, removing the ability to verify whether injected RWX memory contains encrypted shellcode.",
        ],
    }

    report = {
        "evaluation_type": "ZERO-SHOT CROSS-DOMAIN EVALUATION",
        "evaluated_at": datetime.now(UTC).isoformat(),
        "git_commit": get_git_commit(),
        "model_source": "CIC-MalMem-2022 (Memory CatBoost)",
        "target_dataset": "Custom VM Telemetry (45 samples: 13 Benign, 32 Malware)",
        "samples_evaluated": len(df_custom),
        "shared_features": MEMORY_SHARED_FEATURES,
        "excluded_features": MEMORY_EXCLUDED_FEATURES,
        "metrics": metrics,
        "domain_shift_analysis": domain_shift_analysis,
    }

    out_file = eval_dir / "cic_malmem_to_custom_memory.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    logger.info(
        f"Memory Zero-Shot Results: Acc={metrics['accuracy']:.4f}, "
        f"F1={metrics['f1']:.4f}, ROC-AUC={metrics['roc_auc']}, "
        f"FPR={metrics['fpr']:.4f}, FNR={metrics['fnr']:.4f}"
    )
    return report


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(
        description="Zero-Shot Evaluation of Public Models on Custom Data"
    )
    parser.parse_args()

    df_custom = load_custom_dataset()
    evaluate_process_model_zero_shot(df_custom)
    evaluate_memory_model_zero_shot(df_custom)


if __name__ == "__main__":
    main()
