"""Tests for cross-dataset feature compatibility audit."""

from __future__ import annotations

import json
from pathlib import Path

from preprocessing.pipeline import (
    COMMAND_FEATURE_COLS,
    MEMORY_FEATURE_COLS,
    NETWORK_FEATURE_COLS,
    PROCESS_FEATURE_COLS,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
COMPATIBILITY_JSON = (
    REPO_ROOT / "data" / "processed" / "public" / "cross_dataset_compatibility.json"
)
COMPATIBILITY_DOC = REPO_ROOT / "docs" / "cross_dataset_feature_compatibility.md"

REQUIRED_FEATURE_KEYS = {
    "feature_name",
    "modality",
    "our_definition",
    "public_dataset_definition",
    "source_field",
    "extraction_method",
    "units",
    "os_environment",
    "volatility_plugin_version",
    "comparable",
    "classification",
    "transformation_required",
    "distribution_shift_risk",
    "explanation",
}

VALID_CLASSIFICATIONS = {
    "DIRECTLY_COMPARABLE",
    "COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION",
    "NOT_COMPARABLE",
    "MALMEM_SPECIFIC_PROXY",
}

VALID_MODALITY_VERDICTS = {"YES", "CONDITIONAL", "NO"}


def test_compatibility_artifacts_exist() -> None:
    """Verify that both JSON and Markdown compatibility audit artifacts exist."""
    assert COMPATIBILITY_JSON.is_file(), f"Missing {COMPATIBILITY_JSON}"
    assert COMPATIBILITY_DOC.is_file(), f"Missing {COMPATIBILITY_DOC}"
    assert COMPATIBILITY_JSON.stat().st_size > 0
    assert COMPATIBILITY_DOC.stat().st_size > 0


def test_compatibility_json_structure() -> None:
    """Verify top-level keys and structure of cross_dataset_compatibility.json."""
    with open(COMPATIBILITY_JSON, encoding="utf-8") as f:
        data = json.load(f)

    assert "summary" in data
    assert "modality_breakdowns" in data
    assert "features" in data
    assert "training_strategy_evaluation" in data

    summary = data["summary"]
    assert summary["total_features_audited"] == len(data["features"])
    assert summary["recommended_strategy"] in {"A", "B", "C", "D"}

    # Modality verdicts check
    verdicts = summary["modality_verdicts"]
    for mod in ["PROCESS", "MEMORY", "COMMAND", "NETWORK"]:
        assert mod in verdicts
        assert verdicts[mod] in VALID_MODALITY_VERDICTS


def test_all_schema_features_audited() -> None:
    """Verify that every feature in the four modality feature lists is present in the audit."""
    with open(COMPATIBILITY_JSON, encoding="utf-8") as f:
        data = json.load(f)

    audited_features = set(data["features"].keys())

    # Check Process features
    for col in PROCESS_FEATURE_COLS:
        assert col in audited_features, f"Process feature {col} missing from audit"

    # Check Memory features
    for col in MEMORY_FEATURE_COLS:
        assert col in audited_features, f"Memory feature {col} missing from audit"

    # Check Command features
    for col in COMMAND_FEATURE_COLS:
        assert col in audited_features, f"Command feature {col} missing from audit"

    # Check Network features
    for col in NETWORK_FEATURE_COLS:
        assert col in audited_features, f"Network feature {col} missing from audit"


def test_feature_audit_record_completeness() -> None:
    """Verify that every audited feature has complete and non-empty required metadata."""
    with open(COMPATIBILITY_JSON, encoding="utf-8") as f:
        data = json.load(f)

    for feat_name, record in data["features"].items():
        missing_keys = REQUIRED_FEATURE_KEYS - set(record.keys())
        assert not missing_keys, f"Feature {feat_name} is missing keys: {missing_keys}"

        assert (
            record["classification"] in VALID_CLASSIFICATIONS
        ), f"Feature {feat_name} has invalid classification: {record['classification']}"

        assert record["our_definition"].strip(), f"Feature {feat_name} has empty our_definition"
        assert record[
            "public_dataset_definition"
        ].strip(), f"Feature {feat_name} has empty public_dataset_definition"
        assert record["source_field"].strip(), f"Feature {feat_name} has empty source_field"
        assert record[
            "extraction_method"
        ].strip(), f"Feature {feat_name} has empty extraction_method"
        assert record["units"].strip(), f"Feature {feat_name} has empty units"
        assert record[
            "distribution_shift_risk"
        ].strip(), f"Feature {feat_name} has empty distribution_shift_risk"
        assert record["explanation"].strip(), f"Feature {feat_name} has empty explanation"


def test_markdown_report_contents() -> None:
    """Verify that docs/cross_dataset_feature_compatibility.md contains key audit sections."""
    content = COMPATIBILITY_DOC.read_text(encoding="utf-8")

    assert "# Cross-Dataset Feature Compatibility Audit & Semantics Report" in content
    assert "Modality-Level Compatibility Verdicts" in content
    assert "Comprehensive Feature Compatibility Matrix" in content
    assert "Training Strategy Recommendation" in content
    assert "Strategy C: Separate domain-specific models" in content
    assert "Identified Risks & Mitigation Protocols" in content
