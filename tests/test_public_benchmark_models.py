"""Unit tests for CIC-MalMem-2022 benchmark training and zero-shot cross-domain evaluation."""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

PUBLIC_PROCESS_ARTIFACTS = REPO_ROOT / "models" / "artifacts" / "public_cic_malmem" / "process"
PUBLIC_MEMORY_ARTIFACTS = REPO_ROOT / "models" / "artifacts" / "public_cic_malmem" / "memory"

CUSTOM_PROCESS_ARTIFACTS = REPO_ROOT / "models" / "artifacts" / "process"
CUSTOM_MEMORY_ARTIFACTS = REPO_ROOT / "models" / "artifacts" / "memory"

PUBLIC_EVAL_DIR = REPO_ROOT / "evaluation" / "public_cic_malmem"
CROSS_DOMAIN_DIR = REPO_ROOT / "evaluation" / "cross_domain"

EXPECTED_PROCESS_FEATURES = [
    "total_process_count",
    "hidden_process_count",
    "avg_threads_per_process",
    "total_handle_count",
    "malfind_process_count",
    "unlinked_dll_count",
]

EXPECTED_MEMORY_FEATURES = [
    "rwx_page_count",
    "injected_code_regions",
    "unmapped_executable_pages",
    "ldrmodules_inconsistencies",
]


def test_public_benchmark_artifacts_exist() -> None:
    """Verify that all public benchmark model artifacts exist in their dedicated namespace."""
    assert (PUBLIC_PROCESS_ARTIFACTS / "xgboost_model.json").is_file()
    assert (PUBLIC_PROCESS_ARTIFACTS / "scaler.joblib").is_file()
    assert (PUBLIC_PROCESS_ARTIFACTS / "features_used.json").is_file()
    assert (PUBLIC_PROCESS_ARTIFACTS / "training_metadata.json").is_file()

    assert (PUBLIC_MEMORY_ARTIFACTS / "catboost_model.cbm").is_file()
    assert (PUBLIC_MEMORY_ARTIFACTS / "features_used.json").is_file()
    assert (PUBLIC_MEMORY_ARTIFACTS / "training_metadata.json").is_file()


def test_custom_artifacts_untouched() -> None:
    """Verify that custom VM model artifacts exist and were not overwritten by public training."""
    assert (CUSTOM_PROCESS_ARTIFACTS / "model.json").is_file()
    assert (CUSTOM_MEMORY_ARTIFACTS / "model.cbm").is_file()

    # Verify custom metadata does not reference CIC-MalMem
    with open(CUSTOM_PROCESS_ARTIFACTS / "metadata.json", encoding="utf-8") as f:
        meta_proc = json.load(f)
    assert meta_proc.get("dataset_name") != "CIC-MalMem-2022"


def test_strict_feature_subsets_used() -> None:
    """Verify that models strictly use only approved features and exclude unmeasured features."""
    with open(PUBLIC_PROCESS_ARTIFACTS / "features_used.json", encoding="utf-8") as f:
        proc_data = json.load(f)
    assert proc_data["features_used"] == EXPECTED_PROCESS_FEATURES
    assert "anomalous_ppid_count" in proc_data["features_excluded"]
    assert "elevated_privilege_count" in proc_data["features_excluded"]

    with open(PUBLIC_MEMORY_ARTIFACTS / "features_used.json", encoding="utf-8") as f:
        mem_data = json.load(f)
    assert mem_data["features_used"] == EXPECTED_MEMORY_FEATURES
    assert "vad_protection_anomaly_count" in mem_data["features_excluded"]
    assert "MALMEM_SPECIFIC_PROXY" in mem_data["features_excluded"]["vad_protection_anomaly_count"]
    assert "mean_memory_entropy" in mem_data["features_excluded"]
    assert "yara_shellcode_matches" in mem_data["features_excluded"]


def test_public_evaluation_reports() -> None:
    """Verify that public benchmark evaluation outputs exist and contain required metrics."""
    proc_eval_file = PUBLIC_EVAL_DIR / "process_evaluation.json"
    mem_eval_file = PUBLIC_EVAL_DIR / "memory_evaluation.json"
    consolidated_file = PUBLIC_EVAL_DIR / "consolidated_report.json"

    assert proc_eval_file.is_file()
    assert mem_eval_file.is_file()
    assert consolidated_file.is_file()

    with open(proc_eval_file, encoding="utf-8") as f:
        proc_eval = json.load(f)
    assert "test_metrics" in proc_eval
    metrics_p = proc_eval["test_metrics"]
    for m in [
        "accuracy",
        "precision",
        "recall",
        "f1",
        "roc_auc",
        "fpr",
        "fnr",
        "confusion_matrix",
    ]:
        assert m in metrics_p
        assert metrics_p[m] is not None

    with open(mem_eval_file, encoding="utf-8") as f:
        mem_eval = json.load(f)
    assert "test_metrics" in mem_eval
    metrics_m = mem_eval["test_metrics"]
    for m in [
        "accuracy",
        "precision",
        "recall",
        "f1",
        "roc_auc",
        "fpr",
        "fnr",
        "confusion_matrix",
    ]:
        assert m in metrics_m
        assert metrics_m[m] is not None


def test_cross_domain_zero_shot_reports() -> None:
    """Verify that zero-shot evaluation reports exist and conform to reporting contract."""
    proc_cross_file = CROSS_DOMAIN_DIR / "cic_malmem_to_custom_process.json"
    mem_cross_file = CROSS_DOMAIN_DIR / "cic_malmem_to_custom_memory.json"

    assert proc_cross_file.is_file()
    assert mem_cross_file.is_file()

    with open(proc_cross_file, encoding="utf-8") as f:
        p_cross = json.load(f)
    assert p_cross["evaluation_type"] == "ZERO-SHOT CROSS-DOMAIN EVALUATION"
    assert p_cross["samples_evaluated"] == 45
    assert p_cross["shared_features"] == EXPECTED_PROCESS_FEATURES
    assert "domain_shift_analysis" in p_cross

    with open(mem_cross_file, encoding="utf-8") as f:
        m_cross = json.load(f)
    assert m_cross["evaluation_type"] == "ZERO-SHOT CROSS-DOMAIN EVALUATION"
    assert m_cross["samples_evaluated"] == 45
    assert m_cross["shared_features"] == EXPECTED_MEMORY_FEATURES
    assert "vad_protection_anomaly_count" not in m_cross["shared_features"]
    assert "vad_protection_anomaly_count" in m_cross["excluded_features"]
    assert "domain_shift_analysis" in m_cross


def test_vad_protection_anomaly_not_in_zero_shot() -> None:
    """Regression test: vad_protection_anomaly_count is explicitly excluded from zero-shot shared features."""
    mem_cross_file = CROSS_DOMAIN_DIR / "cic_malmem_to_custom_memory.json"
    with open(mem_cross_file, encoding="utf-8") as f:
        m_cross = json.load(f)

    assert "vad_protection_anomaly_count" not in m_cross["shared_features"]
    assert "vad_protection_anomaly_count" in m_cross["excluded_features"]

    # Check compatibility JSON explicitly labels it MALMEM_SPECIFIC_PROXY
    compat_json_file = (
        REPO_ROOT / "data" / "processed" / "public" / "cross_dataset_compatibility.json"
    )
    with open(compat_json_file, encoding="utf-8") as f:
        compat = json.load(f)

    vad_feat = compat["features"]["vad_protection_anomaly_count"]
    assert vad_feat["classification"] == "MALMEM_SPECIFIC_PROXY"
    assert vad_feat["comparable"] == "NO"


def test_custom_and_public_feature_semantics_isolated() -> None:
    """Regression test: Custom and public feature semantics remain explicitly separated."""
    # Custom memory extractor computes InitProtection != Protection
    from forensics.extraction.memory_extractor import extract_memory_features

    assert callable(extract_memory_features)

    # Public memory adapter explicitly documents MALMEM_SPECIFIC_PROXY
    from forensics.public.memory_adapter import MemoryAdapter

    doc = MemoryAdapter.from_malmem.__doc__ or ""
    assert "MALMEM_SPECIFIC_PROXY" in doc
    assert "InitProtection != Protection" in doc
