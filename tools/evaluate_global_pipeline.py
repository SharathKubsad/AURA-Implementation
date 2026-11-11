"""Authoritative End-to-End Global Evaluation of the Two-Stage Hybrid Fusion Pipeline.

Executes all 45 authentic benchmark samples through:
1. Process XGBoost Model (P_proc)
2. Command DistilBERT Model (P_cmd)
3. Network LightGBM Model (P_net)
4. Stage 1 Behavioral Fusion: S1 = 0.35 * P_proc + 0.40 * P_cmd + 0.25 * P_net
5. Suspicion Trigger Gate: S1 >= 0.50 (or individual safety override)
6. Memory CatBoost Model (P_mem, or 0.05 baseline if not triggered)
7. Stage 2 Global Fusion: S_final = 0.50 * S1 + 0.50 * P_mem
8. Final Classification Threshold: S_final >= 0.60 => Malware, else Benign.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

# Ensure repository root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

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

from forensics.schemas import (
    CommandFeatures,
    MemoryFeatures,
    NetworkFeatures,
    ProcessFeatures,
)
from framework.detection_service import DetectionService

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("evaluation.global")


def run_global_evaluation(
    dataset_path: str = "data/processed/unified/unified_dataset.jsonl",
    output_dir: str = "evaluation/global",
) -> dict[str, Any]:
    """Evaluate all samples through the live detection pipeline and save verified metrics."""
    data_file = Path(dataset_path)
    if not data_file.exists():
        raise FileNotFoundError(f"Unified dataset not found at {dataset_path}")

    records = [
        json.loads(line)
        for line in data_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    total_samples = len(records)
    benign_count = sum(1 for r in records if r.get("binary_label") == 0)
    malware_count = sum(1 for r in records if r.get("binary_label") == 1)

    logger.info("Dataset loaded: %d total samples (%d Benign, %d Malware)", total_samples, benign_count, malware_count)

    # Initialize detection service
    service = DetectionService()

    y_true: list[int] = []
    y_pred: list[int] = []
    y_scores: list[float] = []
    y_stage1: list[float] = []
    sample_evaluations: list[dict[str, Any]] = []

    for r in records:
        sid = str(r["sample_id"])
        true_label = int(r["binary_label"])
        y_true.append(true_label)

        # Build schema objects
        proc = ProcessFeatures(
            sample_id=sid,
            total_process_count=int(r.get("total_process_count", 140)),
            hidden_process_count=int(r.get("hidden_process_count", 0)),
            anomalous_ppid_count=int(r.get("anomalous_ppid_count", 0)),
            avg_threads_per_process=float(r.get("avg_threads_per_process", 12.0)),
            max_threads_in_single_process=int(r.get("max_threads_in_single_process", 80)),
            total_handle_count=int(r.get("total_handle_count", 50000)),
            suspicious_dll_count=int(r.get("suspicious_dll_count", 0)),
            malfind_process_count=int(r.get("malfind_process_count", 0)),
            elevated_privilege_count=int(r.get("elevated_privilege_count", 0)),
            unlinked_dll_count=int(r.get("unlinked_dll_count", 0)),
        )

        cmd_text = str(r.get("raw_command_text") or "")
        cmd = CommandFeatures(
            sample_id=sid,
            raw_command_text=cmd_text,
            command_length=len(cmd_text),
            shannon_entropy=float(r.get("shannon_entropy") or 4.0),
            is_base64_encoded=int(r.get("is_base64_encoded", 0)),
            has_download_cradle=int(r.get("has_download_cradle", 0)),
            has_bypass_execution_policy=int(r.get("has_bypass_execution_policy", 0)),
            has_hidden_window=int(r.get("has_hidden_window", 0)),
            uses_lolbins=int(r.get("uses_lolbins", 0)),
            registry_persistence_count=int(r.get("registry_persistence_count", 0)),
        )

        net = NetworkFeatures(
            sample_id=sid,
            active_connection_count=int(r.get("active_connection_count", 0)),
            listening_port_count=int(r.get("listening_port_count", 0)),
            outbound_connection_count=int(r.get("outbound_connection_count", 0)),
            dns_query_count=int(r.get("dns_query_count") or 0),
            unique_remote_ips=int(r.get("unique_remote_ips", 0)),
            avg_interpacket_interval_ms=float(r.get("avg_interpacket_interval_ms") or 0.0),
            beacon_regularity_score=float(r.get("beacon_regularity_score") or 0.0),
            total_bytes_sent=int(r.get("total_bytes_sent") or 0),
            total_bytes_received=int(r.get("total_bytes_received") or 0),
            suspicious_port_usage=int(r.get("suspicious_port_usage", 0)),
        )

        mem = MemoryFeatures(
            sample_id=sid,
            rwx_page_count=int(r.get("rwx_page_count", 0)),
            injected_code_regions=int(r.get("injected_code_regions", 0)),
            unmapped_executable_pages=int(r.get("unmapped_executable_pages", 0)),
            vad_protection_anomaly_count=int(r.get("vad_protection_anomaly_count", 0)),
            ldrmodules_inconsistencies=int(r.get("ldrmodules_inconsistencies", 0)),
            yara_shellcode_matches=int(r.get("yara_shellcode_matches", 0)),
            mean_memory_entropy=float(r.get("mean_memory_entropy") or 0.0),
            max_memory_entropy=float(r.get("max_memory_entropy") or 0.0),
        )

        # Run pipeline
        res = service.detect(proc=proc, cmd=cmd, net=net, mem=mem)

        pred_label = 1 if res["verdict"].lower() == "malware" else 0
        final_conf = float(res["confidence"])
        stage1_conf = float(res.get("stage1_confidence", 0.0))

        y_pred.append(pred_label)
        y_scores.append(final_conf)
        y_stage1.append(stage1_conf)

        sample_evaluations.append({
            "sample_id": sid,
            "true_label": true_label,
            "true_label_name": "Malware" if true_label == 1 else "Benign",
            "predicted_label": pred_label,
            "verdict": res["verdict"],
            "is_correct": pred_label == true_label,
            "stage1_confidence": stage1_conf,
            "final_confidence": final_conf,
            "memory_triggered": res["memory_triggered"],
            "per_model": res["per_model"],
            "attributed_family": res.get("family"),
            "family_confidence": res.get("family_confidence"),
        })

    # Compute classification metrics
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    roc_auc = float(roc_auc_score(y_true, y_scores))

    logger.info("Evaluation Complete: Acc=%.4f (TP=%d, TN=%d, FP=%d, FN=%d), Rec=%.4f, Prec=%.4f, F1=%.4f, ROC-AUC=%.4f",
                acc, tp, tn, fp, fn, rec, prec, f1, roc_auc)

    output_payload = {
        "evaluation_timestamp": "2026-09-27T21:20:00Z",
        "dataset_path": dataset_path,
        "total_samples": total_samples,
        "benign_samples": benign_count,
        "malware_samples": malware_count,
        "metrics": {
            "tp": int(tp),
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "roc_auc": round(roc_auc, 4),
        },
        "configuration": {
            "stage1_weights": service.fusion_engine.stage1_weights,
            "stage2_weights": service.fusion_engine.stage2_weights,
            "behavioral_suspicion_threshold": service.fusion_engine.behavioral_suspicion_threshold,
            "decision_threshold": service.fusion_engine.threshold,
            "untriggered_memory_baseline": 0.05,
        },
        "per_sample_results": sample_evaluations,
    }

    out_p = Path(output_dir)
    out_p.mkdir(parents=True, exist_ok=True)
    out_json = out_p / "fusion_evaluation.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(output_payload, f, indent=2)

    logger.info("Saved authoritative global evaluation report to %s", out_json)
    return output_payload


if __name__ == "__main__":
    result = run_global_evaluation()
    print("\n" + "=" * 60)
    print("GLOBAL FUSION EVALUATION RESULT")
    print("=" * 60)
    print(f"Total Samples: {result['total_samples']} (Benign: {result['benign_samples']}, Malware: {result['malware_samples']})")
    print(f"TP: {result['metrics']['tp']} | TN: {result['metrics']['tn']} | FP: {result['metrics']['fp']} | FN: {result['metrics']['fn']}")
    print(f"Accuracy:  {result['metrics']['accuracy'] * 100:.2f}% ({result['metrics']['tp'] + result['metrics']['tn']}/{result['total_samples']})")
    print(f"Recall:    {result['metrics']['recall'] * 100:.2f}%")
    print(f"Precision: {result['metrics']['precision'] * 100:.2f}%")
    print(f"F1 Score:  {result['metrics']['f1']:.4f}")
    print(f"ROC-AUC:   {result['metrics']['roc_auc']:.4f}")
    print("=" * 60)
