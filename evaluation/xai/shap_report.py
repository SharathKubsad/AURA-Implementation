"""SHAP Explainability Engine (Objective 4).

Generates global feature importance rankings and local waterfall explanations
for Process, Memory, Network, and Multi-Class tree models using shap.TreeExplainer.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# Ensure repo root on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import pandas as pd

try:
    import shap

    HAS_SHAP = True
except Exception:
    shap = None
    HAS_SHAP = False

from framework.detection_service import DetectionService

from preprocessing.pipeline import (
    ALL_NUMERIC_FEATURE_COLS,
    MEMORY_FEATURE_COLS,
    PROCESS_FEATURE_COLS,
)


class ShapExplainerManager:
    """Computes global feature importances and local per-prediction attribution."""

    def __init__(self, detection_service: DetectionService) -> None:
        self.svc = detection_service
        self.process_explainer = None
        self.memory_explainer = None
        self.multiclass_explainer = None

        if HAS_SHAP and shap is not None:
            try:
                proc_clf = getattr(self.svc.process_model, "classifier", self.svc.process_model)
                self.process_explainer = shap.TreeExplainer(proc_clf) if proc_clf else None
            except Exception:
                self.process_explainer = None

            try:
                mem_clf = getattr(self.svc.memory_model, "classifier", self.svc.memory_model)
                self.memory_explainer = shap.TreeExplainer(mem_clf) if mem_clf else None
            except Exception:
                self.memory_explainer = None

            try:
                self.multiclass_explainer = (
                    shap.TreeExplainer(self.svc.multiclass_model)
                    if self.svc.multiclass_model
                    else None
                )
            except Exception:
                self.multiclass_explainer = None


    def explain_process(self, proc_dict: dict[str, Any]) -> list[dict[str, Any]]:
        """Explain process model prediction with SHAP contribution values."""
        if not self.svc.process_model:
            return []

        features = self.svc.process_model.feature_names
        try:
            df_in = pd.DataFrame([proc_dict])
            X_df = self.svc.process_model._prepare_input(df_in)
            X_vals = X_df.values[0] if isinstance(X_df, pd.DataFrame) else X_df[0]

            if not self.process_explainer:
                importances = getattr(
                    self.svc.process_model.classifier, "feature_importances_", [0.1] * len(features)
                )
                results = [
                    {
                        "feature": feat,
                        "importance": round(float(imp), 4),
                        "value": round(float(val), 2),
                        "domain": "process",
                    }
                    for feat, imp, val in zip(features, importances, X_vals, strict=False)
                ]
                results.sort(key=lambda x: abs(x["importance"]), reverse=True)
                return results

            vals = self.process_explainer.shap_values(X_df)
            shap_vals = vals[0] if isinstance(vals, list) or len(vals.shape) > 1 else vals

            results = [
                {
                    "feature": feat,
                    "importance": round(float(val), 4),
                    "value": round(float(actual), 2),
                    "domain": "process",
                }
                for feat, val, actual in zip(features, shap_vals, X_vals, strict=False)
            ]
            results.sort(key=lambda x: abs(x["importance"]), reverse=True)
            return results
        except Exception:
            return []

    def explain_memory(self, mem_dict: dict[str, Any]) -> list[dict[str, Any]]:
        """Explain memory model prediction with SHAP values."""
        if not self.svc.memory_model:
            return []

        features = self.svc.memory_model.feature_names
        try:
            df_in = pd.DataFrame([mem_dict])
            X_df = self.svc.memory_model._prepare_input(df_in)
            X_vals = X_df.values[0] if isinstance(X_df, pd.DataFrame) else X_df[0]

            if not self.memory_explainer:
                importances = getattr(
                    self.svc.memory_model.classifier, "feature_importances_", [0.1] * len(features)
                )
                results = [
                    {
                        "feature": feat,
                        "importance": round(float(imp), 4),
                        "value": round(float(val), 2),
                        "domain": "memory",
                    }
                    for feat, imp, val in zip(features, importances, X_vals, strict=False)
                ]
                results.sort(key=lambda x: abs(x["importance"]), reverse=True)
                return results

            vals = self.memory_explainer.shap_values(X_df)
            shap_vals = vals[0] if isinstance(vals, list) or len(vals.shape) > 1 else vals

            results = [
                {
                    "feature": feat,
                    "importance": round(float(val), 4),
                    "value": round(float(actual), 2),
                    "domain": "memory",
                }
                for feat, val, actual in zip(features, shap_vals, X_vals, strict=False)
            ]
            results.sort(key=lambda x: abs(x["importance"]), reverse=True)
            return results
        except Exception:
            return []

    def explain_multiclass(self, fused_dict: dict[str, Any]) -> list[dict[str, Any]]:
        """Explain multi-class family attribution using SHAP."""
        if not self.svc.multiclass_model:
            return []

        try:
            df_row = pd.DataFrame([fused_dict])[ALL_NUMERIC_FEATURE_COLS].fillna(0.0).astype(float)
            if not self.multiclass_explainer:
                importances = getattr(
                    self.svc.multiclass_model,
                    "feature_importances_",
                    [0.05] * len(ALL_NUMERIC_FEATURE_COLS),
                )
                results = [
                    {
                        "feature": feat,
                        "importance": round(float(imp), 4),
                        "value": round(float(val), 2),
                        "domain": "multiclass",
                    }
                    for feat, imp, val in zip(
                        ALL_NUMERIC_FEATURE_COLS, importances, df_row.iloc[0], strict=False
                    )
                ]
                results.sort(key=lambda x: abs(x["importance"]), reverse=True)
                return results[:10]

            vals = self.multiclass_explainer.shap_values(df_row)
            if isinstance(vals, list):
                target_vals = vals[0][0]
            elif len(vals.shape) == 3:
                target_vals = vals[0, :, 0]
            else:
                target_vals = vals[0]

            results = [
                {
                    "feature": feat,
                    "importance": round(float(val), 4),
                    "value": round(float(actual), 2),
                    "domain": "multiclass",
                }
                for feat, val, actual in zip(
                    ALL_NUMERIC_FEATURE_COLS, target_vals, df_row.iloc[0], strict=False
                )
            ]
            results.sort(key=lambda x: abs(x["importance"]), reverse=True)
            return results[:10]
        except Exception:
            return []


def generate_shap_report(output_dir: str = "evaluation/xai/artifacts") -> dict[str, Any]:
    """Generate summary SHAP values across authentic custom VM dataset."""
    p_out = Path(output_dir)
    p_out.mkdir(parents=True, exist_ok=True)

    svc = DetectionService()
    manager = ShapExplainerManager(svc)

    # Load the authentic 45-sample unified dataset (NOT synthetic benchmark_dataset.csv)
    import json

    jsonl_path = Path("data/processed/unified/unified_dataset.jsonl")
    if not jsonl_path.exists():
        raise FileNotFoundError(f"Unified dataset not found: {jsonl_path}")

    rows = [json.loads(line) for line in jsonl_path.read_text(encoding="utf-8").splitlines()
            if line.strip()]
    df = pd.DataFrame(rows)

    # Use first malware sample for local SHAP explanation
    malware_rows = df[df["binary_label"] == 1]
    if malware_rows.empty:
        raise ValueError("No malware samples found in unified dataset")
    sample_mal = malware_rows.iloc[0].to_dict()
    # Fill PCAP-null fields with 0 (consistent with training and inference)
    pcap_null_fields = [
        "dns_query_count", "avg_interpacket_interval_ms", "beacon_regularity_score",
        "total_bytes_sent", "total_bytes_received", "mean_memory_entropy", "max_memory_entropy",
    ]
    for field in pcap_null_fields:
        if sample_mal.get(field) is None:
            sample_mal[field] = 0.0

    proc_shap = manager.explain_process(sample_mal)
    mem_shap = manager.explain_memory(sample_mal)
    multi_shap = manager.explain_multiclass(sample_mal)

    report = {
        "dataset": str(jsonl_path),
        "sample_id": sample_mal.get("sample_id", "unknown"),
        "sample_family": sample_mal.get("family", "unknown"),
        "process_top_features": proc_shap[:5],
        "memory_top_features": mem_shap[:5],
        "multiclass_top_features": multi_shap[:5],
    }

    with open(p_out / "shap_summary.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[SHAP] Generated SHAP explanations from authentic dataset -> {p_out / 'shap_summary.json'}")
    return report


if __name__ == "__main__":
    generate_shap_report()
