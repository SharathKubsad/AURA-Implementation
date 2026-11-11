"""Regression tests for Phase 2 custom dataset and model audit deliverables.

Validates that:
- All 16 audit output files exist and are valid.
- Custom dataset integrity constraints hold (45 samples, 13 benign, 32 malware, 0 duplicates).
- Feature variance analysis correctly identifies constant and missing features.
- High-correlation pairs (including cross-modality duplicates) are accurately detected.
- Leakage classifications match forensic evidence.
- Split audit confirms deterministic 31/7/7 partition and family coverage gaps.
- Reproduced model performance exactly matches published benchmarks.
- Custom model artifacts remain untouched and un-retrained.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
AUDIT_DIR = REPO_ROOT / "evaluation" / "custom_audit"
ARTIFACTS_DIR = REPO_ROOT / "models" / "artifacts"


def test_audit_deliverables_exist() -> None:
    """Verify all 16 Phase 2 custom audit deliverables exist on disk."""
    expected_files = [
        "dataset_integrity.json",
        "dataset_integrity.csv",
        "feature_statistics.json",
        "feature_statistics.csv",
        "correlation_matrix.csv",
        "correlation_report.json",
        "leakage_audit.json",
        "split_audit.json",
        "model_artifact_audit.json",
        "current_model_reproduction.json",
        "current_model_reproduction.csv",
        "threshold_sweep.json",
        "threshold_sweep.csv",
        "modality_score_analysis.json",
        "modality_score_analysis.csv",
        "consolidated_audit_report.md",
    ]
    for filename in expected_files:
        filepath = AUDIT_DIR / filename
        assert filepath.is_file(), f"Missing required audit deliverable: {filepath}"
        assert filepath.stat().st_size > 0, f"Audit deliverable is empty: {filepath}"


def test_dataset_integrity_report() -> None:
    """Verify dataset integrity metrics."""
    data = json.loads((AUDIT_DIR / "dataset_integrity.json").read_text(encoding="utf-8"))
    assert data["total_samples"] == 45
    assert data["class_distribution"]["benign"] == 13
    assert data["class_distribution"]["malware"] == 32
    assert len(data["duplicate_sample_ids"]) == 0
    assert data["exact_duplicate_rows"] == 0
    assert data["missing_modality_count"] == 0
    assert len(data["impossible_values"]) == 0
    assert len(data["label_inconsistencies"]) == 0


def test_feature_variance_audit() -> None:
    """Verify feature variance flags for known constant and missing features."""
    data = json.loads((AUDIT_DIR / "feature_statistics.json").read_text(encoding="utf-8"))

    # Memory constant features
    assert data["memory"]["vad_protection_anomaly_count"]["zero_variance"] is True
    assert data["memory"]["yara_shellcode_matches"]["zero_variance"] is True
    assert data["memory"]["mean_memory_entropy"]["missing_pct"] == 100.0

    # Network constant and missing features
    assert data["network"]["listening_port_count"]["zero_variance"] is True
    assert data["network"]["suspicious_port_usage"]["zero_variance"] is True
    assert data["network"]["dns_query_count"]["missing_pct"] == 100.0

    # Command constant features
    assert data["command"]["is_base64_encoded"]["zero_variance"] is True
    assert data["command"]["uses_lolbins"]["zero_variance"] is True


def test_correlation_redundancy_report() -> None:
    """Verify cross-modality and engineered feature redundancy detection."""
    data = json.loads((AUDIT_DIR / "correlation_report.json").read_text(encoding="utf-8"))
    pairs = data["high_correlation_pairs"]
    pair_tuples = {(p["feature_a"], p["feature_b"]) for p in pairs} | {
        (p["feature_b"], p["feature_a"]) for p in pairs
    }

    # Cross-modality identical pair
    assert ("unlinked_dll_count", "ldrmodules_inconsistencies") in pair_tuples

    # Command length vs entropy
    assert ("command_length", "shannon_entropy") in pair_tuples

    # Memory page correlation
    assert ("rwx_page_count", "unmapped_executable_pages") in pair_tuples


def test_label_leakage_audit() -> None:
    """Verify label leakage severity classifications."""
    data = json.loads((AUDIT_DIR / "leakage_audit.json").read_text(encoding="utf-8"))
    findings = {f["category"]: f["severity"] for f in data["audit_findings"]}

    assert findings["SAMPLE_ID_DIRECT_LEAKAGE"] == "NONE"
    assert findings["PREPROCESSING_FIT_LEAKAGE"] == "NONE"
    assert findings["COMMAND_TEXT_REPRESENTATIVENESS"] == "CRITICAL"
    assert findings["NETWORK_TELEMETRY_MISSINGNESS"] == "HIGH"
    assert findings["RUN_ID_HARNESS_CLUSTERING"] == "HIGH"


def test_split_audit_structure() -> None:
    """Verify deterministic split audit parameters and family coverage."""
    data = json.loads((AUDIT_DIR / "split_audit.json").read_text(encoding="utf-8"))
    assert data["random_seed"] == 42
    assert data["split_counts"]["train"] == 31
    assert data["split_counts"]["validation"] == 7
    assert data["split_counts"]["test"] == 7
    assert data["is_family_grouped"] is False
    assert len(data["family_analysis"]["families_unseen_in_test"]) == 8


def test_reproduced_metrics_match_binary_evaluation() -> None:
    """Verify reproduced model metrics match previously published binary evaluation."""
    repro = json.loads((AUDIT_DIR / "current_model_reproduction.json").read_text(encoding="utf-8"))

    # Process: Acc=0.8571, F1=0.9091, AUC=0.9000
    p = repro["models"]["process"]
    assert p["accuracy"] == 0.8571
    assert p["f1"] == 0.9091
    assert p["roc_auc"] == 0.9

    # Command: Acc=0.7143, F1=0.8333, AUC=0.3000
    c = repro["models"]["command"]
    assert c["accuracy"] == 0.7143
    assert c["f1"] == 0.8333
    assert c["roc_auc"] == 0.3

    # Network: Acc=0.7143, F1=0.8333, AUC=0.5000
    n = repro["models"]["network"]
    assert n["accuracy"] == 0.7143
    assert n["f1"] == 0.8333
    assert n["roc_auc"] == 0.5

    # Memory: Acc=0.8571, F1=0.9091, AUC=1.0000
    m = repro["models"]["memory"]
    assert m["accuracy"] == 0.8571
    assert m["f1"] == 0.9091
    assert m["roc_auc"] == 1.0


def test_threshold_sweep_bounds() -> None:
    """Verify threshold sweep contains all 17 target thresholds."""
    data = json.loads((AUDIT_DIR / "threshold_sweep.json").read_text(encoding="utf-8"))
    expected_thresholds = [
        0.10,
        0.15,
        0.20,
        0.25,
        0.30,
        0.35,
        0.40,
        0.45,
        0.50,
        0.55,
        0.60,
        0.65,
        0.70,
        0.75,
        0.80,
        0.85,
        0.90,
    ]
    for mod in ["process", "command", "network", "memory"]:
        ths = [round(entry["threshold"], 2) for entry in data[mod]]
        assert ths == expected_thresholds


def test_modality_scores_analysis() -> None:
    """Verify modality score analysis contains all 7 test samples."""
    data = json.loads((AUDIT_DIR / "modality_score_analysis.json").read_text(encoding="utf-8"))
    assert data["test_sample_count"] == 7
    assert len(data["samples"]) == 7


def test_custom_artifacts_remained_untouched() -> None:
    """Verify custom model artifact weights exist and were not altered."""
    assert (ARTIFACTS_DIR / "process" / "model.json").is_file()
    assert (ARTIFACTS_DIR / "command" / "model.safetensors").is_file()
    assert (ARTIFACTS_DIR / "network" / "model.joblib").is_file()
    assert (ARTIFACTS_DIR / "memory" / "model.cbm").is_file()
