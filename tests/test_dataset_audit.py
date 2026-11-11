"""Unit and integration tests for tools/audit_custom_dataset.py."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from tools.audit_custom_dataset import (
    AuditStatus,
    audit_custom_dataset,
    audit_single_sample,
    find_all_sample_ids,
    main,
    print_terminal_summary,
    resolve_family_and_label,
    save_audit_reports,
)


@pytest.fixture
def mock_categories() -> dict:
    """Provide a standard mock categories.json dictionary."""
    return {
        "categories": [
            {
                "family": "benign",
                "binary_label": 0,
                "run_range": [1100, 1299],
            },
            {
                "family": "powershell_fileless",
                "binary_label": 1,
                "run_range": [2, 99],
            },
            {
                "family": "process_hollowing",
                "binary_label": 1,
                "run_range": [100, 199],
            },
        ],
        "run_conventions": {
            "RUN-001": {
                "sample_id": "EXEC_RUN-001",
                "family": "benign",
                "label": 0,
            }
        },
    }


def test_resolve_family_and_label(mock_categories: dict) -> None:
    """Test mapping of sample IDs to family names and binary labels."""
    # Special baseline
    fam, lbl = resolve_family_and_label("EXEC_RUN-001", mock_categories)
    assert fam == "benign"
    assert lbl == 0

    # Range [2, 99]
    fam, lbl = resolve_family_and_label("EXEC_RUN-002", mock_categories)
    assert fam == "powershell_fileless"
    assert lbl == 1

    # Range [100, 199]
    fam, lbl = resolve_family_and_label("EXEC_RUN-105", mock_categories)
    assert fam == "process_hollowing"
    assert lbl == 1

    # Range [1100, 1299]
    fam, lbl = resolve_family_and_label("EXEC_RUN-1105", mock_categories)
    assert fam == "benign"
    assert lbl == 0

    # Unmapped RUN
    fam, lbl = resolve_family_and_label("EXEC_RUN-9999", mock_categories)
    assert fam == "unknown"
    assert lbl is None

    # Invalid string without RUN number
    fam, lbl = resolve_family_and_label("INVALID_SAMPLE", mock_categories)
    assert fam == "unknown"
    assert lbl is None


def test_find_all_sample_ids(tmp_path: Path) -> None:
    """Test sample ID discovery and duplicate detection."""
    interim = tmp_path / "interim"
    (interim / "command").mkdir(parents=True)
    (interim / "network").mkdir(parents=True)

    (interim / "command" / "EXEC_RUN-001.json").write_text("{}", encoding="utf-8")
    (interim / "command" / "EXEC_RUN-002.json").write_text("{}", encoding="utf-8")
    (interim / "network" / "EXEC_RUN-002.json").write_text("{}", encoding="utf-8")
    (interim / "network" / "EXEC_RUN-003.json").write_text("{}", encoding="utf-8")

    sample_ids, duplicates = find_all_sample_ids(interim)
    assert sample_ids == ["EXEC_RUN-001", "EXEC_RUN-002", "EXEC_RUN-003"]
    assert len(duplicates) == 0


def test_audit_valid_complete_sample(tmp_path: Path, mock_categories: dict) -> None:
    """Test audit of a fully complete and valid 4-modality sample."""
    interim = tmp_path / "interim"
    for m in ("process", "memory", "command", "network"):
        (interim / m).mkdir(parents=True)

    sample_id = "EXEC_RUN-001"

    proc_data = {
        "sample_id": sample_id,
        "total_process_count": 10,
        "hidden_process_count": 0,
        "anomalous_ppid_count": 0,
        "avg_threads_per_process": 2.5,
        "max_threads_in_single_process": 5,
        "total_handle_count": 50,
        "suspicious_dll_count": 0,
        "malfind_process_count": 0,
        "elevated_privilege_count": 0,
        "unlinked_dll_count": 0,
    }
    mem_data = {
        "sample_id": sample_id,
        "rwx_page_count": 0,
        "injected_code_regions": 0,
        "unmapped_executable_pages": 0,
        "vad_protection_anomaly_count": 0,
        "ldrmodules_inconsistencies": 0,
        "yara_shellcode_matches": 0,
        "mean_memory_entropy": 4.5,
        "max_memory_entropy": 6.8,
    }
    cmd_data = {
        "sample_id": sample_id,
        "raw_command_text": "powershell.exe -NoProfile -Command Get-Process",
        "command_length": 46,
        "shannon_entropy": 4.2,
        "is_base64_encoded": 0,
        "has_download_cradle": 0,
        "has_bypass_execution_policy": 0,
        "has_hidden_window": 0,
        "uses_lolbins": 0,
        "registry_persistence_count": 0,
    }
    net_data = {
        "sample_id": sample_id,
        "active_connection_count": 1,
        "listening_port_count": 2,
        "outbound_connection_count": 1,
        "dns_query_count": None,
        "unique_remote_ips": 1,
        "avg_interpacket_interval_ms": None,
        "beacon_regularity_score": None,
        "total_bytes_sent": None,
        "total_bytes_received": None,
        "suspicious_port_usage": 0,
    }

    (interim / "process" / f"{sample_id}.json").write_text(json.dumps(proc_data), encoding="utf-8")
    (interim / "memory" / f"{sample_id}.json").write_text(json.dumps(mem_data), encoding="utf-8")
    (interim / "command" / f"{sample_id}.json").write_text(json.dumps(cmd_data), encoding="utf-8")
    (interim / "network" / f"{sample_id}.json").write_text(json.dumps(net_data), encoding="utf-8")

    res, parsed = audit_single_sample(sample_id, interim, mock_categories)
    assert res.status == AuditStatus.VALID
    assert res.family == "benign"
    assert res.binary_label == 0
    assert all(res.modalities_present.values())
    assert all(res.schema_valid.values())
    assert res.raw_command_len == 46
    assert res.network_null_count == 5
    assert len(res.issues) == 0


def test_audit_incomplete_sample(tmp_path: Path, mock_categories: dict) -> None:
    """Test audit of a sample with missing modalities (e.g. process and memory absent)."""
    interim = tmp_path / "interim"
    for m in ("command", "network"):
        (interim / m).mkdir(parents=True)

    sample_id = "EXEC_RUN-002"
    cmd_data = {
        "sample_id": sample_id,
        "raw_command_text": "powershell.exe -EncodedCommand AAAA",
        "command_length": 35,
        "shannon_entropy": 4.1,
        "is_base64_encoded": 1,
        "has_download_cradle": 0,
        "has_bypass_execution_policy": 0,
        "has_hidden_window": 0,
        "uses_lolbins": 0,
        "registry_persistence_count": 0,
    }
    net_data = {
        "sample_id": sample_id,
        "active_connection_count": 0,
        "listening_port_count": 0,
        "outbound_connection_count": 0,
        "dns_query_count": None,
        "unique_remote_ips": 0,
        "avg_interpacket_interval_ms": None,
        "beacon_regularity_score": None,
        "total_bytes_sent": None,
        "total_bytes_received": None,
        "suspicious_port_usage": 0,
    }
    (interim / "command" / f"{sample_id}.json").write_text(json.dumps(cmd_data), encoding="utf-8")
    (interim / "network" / f"{sample_id}.json").write_text(json.dumps(net_data), encoding="utf-8")

    res, _ = audit_single_sample(sample_id, interim, mock_categories)
    assert res.status == AuditStatus.INCOMPLETE
    assert res.family == "powershell_fileless"
    assert res.binary_label == 1
    assert not res.modalities_present["process"]
    assert not res.modalities_present["memory"]
    assert res.modalities_present["command"]
    assert res.modalities_present["network"]
    assert any("Missing modalities: process, memory" in iss for iss in res.issues)


def test_audit_invalid_schema_and_numeric_violations(tmp_path: Path, mock_categories: dict) -> None:
    """Test detection of invalid schemas, NaNs, and negative violations."""
    interim = tmp_path / "interim"
    (interim / "command").mkdir(parents=True)
    (interim / "network").mkdir(parents=True)

    # 1. Schema failure: missing required command_length
    sample_id_1 = "EXEC_RUN-002"
    bad_cmd = {
        "sample_id": sample_id_1,
        "raw_command_text": "whoami",
        # missing command_length, shannon_entropy, etc.
    }
    (interim / "command" / f"{sample_id_1}.json").write_text(json.dumps(bad_cmd), encoding="utf-8")
    res1, _ = audit_single_sample(sample_id_1, interim, mock_categories)
    assert res1.status == AuditStatus.INVALID
    assert not res1.schema_valid["command"]

    # 2. Impossible negative value
    sample_id_2 = "EXEC_RUN-003"
    neg_cmd = {
        "sample_id": sample_id_2,
        "raw_command_text": "whoami",
        "command_length": -5,  # Impossible negative length
        "shannon_entropy": 2.0,
        "is_base64_encoded": 0,
        "has_download_cradle": 0,
        "has_bypass_execution_policy": 0,
        "has_hidden_window": 0,
        "uses_lolbins": 0,
        "registry_persistence_count": 0,
    }
    (interim / "command" / f"{sample_id_2}.json").write_text(json.dumps(neg_cmd), encoding="utf-8")
    res2, _ = audit_single_sample(sample_id_2, interim, mock_categories)
    assert res2.status == AuditStatus.INVALID


def test_audit_review_flags(tmp_path: Path, mock_categories: dict) -> None:
    """Test flagging samples for review on ID mismatches and empty command text."""
    interim = tmp_path / "interim"
    (interim / "command").mkdir(parents=True)

    # Sample ID mismatch: file is EXEC_RUN-002 but content is EXEC_RUN-999
    sample_id = "EXEC_RUN-002"
    mismatched_cmd = {
        "sample_id": "EXEC_RUN-999",
        "raw_command_text": "powershell.exe",
        "command_length": 14,
        "shannon_entropy": 3.5,
        "is_base64_encoded": 0,
        "has_download_cradle": 0,
        "has_bypass_execution_policy": 0,
        "has_hidden_window": 0,
        "uses_lolbins": 0,
        "registry_persistence_count": 0,
    }
    (interim / "command" / f"{sample_id}.json").write_text(
        json.dumps(mismatched_cmd), encoding="utf-8"
    )
    res, _ = audit_single_sample(sample_id, interim, mock_categories)
    assert res.status == AuditStatus.REVIEW
    assert len(res.id_mismatches) > 0

    # Empty raw command text
    empty_cmd = {
        "sample_id": sample_id,
        "raw_command_text": "",
        "command_length": 0,
        "shannon_entropy": 0.0,
        "is_base64_encoded": 0,
        "has_download_cradle": 0,
        "has_bypass_execution_policy": 0,
        "has_hidden_window": 0,
        "uses_lolbins": 0,
        "registry_persistence_count": 0,
    }
    (interim / "command" / f"{sample_id}.json").write_text(json.dumps(empty_cmd), encoding="utf-8")
    res_empty, _ = audit_single_sample(sample_id, interim, mock_categories)
    assert res_empty.status == AuditStatus.REVIEW
    assert res_empty.raw_command_len == 0


def test_constant_features_detection(tmp_path: Path, mock_categories: dict) -> None:
    """Test detection of constant features with zero variance across samples."""
    interim = tmp_path / "interim"
    (interim / "command").mkdir(parents=True)

    for sid in ("EXEC_RUN-002", "EXEC_RUN-003"):
        cmd_data = {
            "sample_id": sid,
            "raw_command_text": "sample text",
            "command_length": 11,
            "shannon_entropy": 2.5,
            "is_base64_encoded": 0,
            "has_download_cradle": 0,
            "has_bypass_execution_policy": 0,
            "has_hidden_window": 0,
            "uses_lolbins": 0,
            "registry_persistence_count": 0,
        }
        (interim / "command" / f"{sid}.json").write_text(json.dumps(cmd_data), encoding="utf-8")

    cat_file = tmp_path / "categories.json"
    cat_file.write_text(json.dumps(mock_categories), encoding="utf-8")

    report = audit_custom_dataset(interim, cat_file)
    const_feats = report.summary["numeric_sanity"]["constant_features"]
    const_names = [f["feature"] for f in const_feats]

    assert "command_length" in const_names
    assert "uses_lolbins" in const_names


def test_report_generation_json_and_csv(tmp_path: Path, mock_categories: dict) -> None:
    """Test saving and verifying JSON and CSV report formats."""
    interim = tmp_path / "interim"
    (interim / "command").mkdir(parents=True)
    (interim / "network").mkdir(parents=True)

    sample_id = "EXEC_RUN-002"
    cmd_data = {
        "sample_id": sample_id,
        "raw_command_text": "netstat -ano",
        "command_length": 12,
        "shannon_entropy": 3.1,
        "is_base64_encoded": 0,
        "has_download_cradle": 0,
        "has_bypass_execution_policy": 0,
        "has_hidden_window": 0,
        "uses_lolbins": 0,
        "registry_persistence_count": 0,
    }
    net_data = {
        "sample_id": sample_id,
        "active_connection_count": 3,
        "listening_port_count": 5,
        "outbound_connection_count": 2,
        "dns_query_count": None,
        "unique_remote_ips": 2,
        "avg_interpacket_interval_ms": None,
        "beacon_regularity_score": None,
        "total_bytes_sent": None,
        "total_bytes_received": None,
        "suspicious_port_usage": 0,
    }
    (interim / "command" / f"{sample_id}.json").write_text(json.dumps(cmd_data), encoding="utf-8")
    (interim / "network" / f"{sample_id}.json").write_text(json.dumps(net_data), encoding="utf-8")

    cat_file = tmp_path / "categories.json"
    cat_file.write_text(json.dumps(mock_categories), encoding="utf-8")

    report = audit_custom_dataset(interim, cat_file)
    json_path = tmp_path / "report.json"
    csv_path = tmp_path / "report.csv"

    save_audit_reports(report, json_path, csv_path)

    assert json_path.is_file()
    assert csv_path.is_file()

    # Verify JSON content
    with json_path.open("r", encoding="utf-8") as f:
        jd = json.load(f)
    assert jd["summary"]["total_samples"] == 1
    assert jd["summary"]["status_counts"]["incomplete"] == 1

    # Verify CSV content
    with csv_path.open("r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))
    assert len(reader) == 1
    row = reader[0]
    assert row["sample_id"] == sample_id
    assert row["status"] == "incomplete"
    assert row["family"] == "powershell_fileless"
    assert row["binary_label"] == "1"
    assert row["has_command"] == "True"
    assert row["has_process"] == "False"


def test_cli_execution(tmp_path: Path, mock_categories: dict) -> None:
    """Test CLI main invocation with custom arguments."""
    interim = tmp_path / "interim"
    (interim / "command").mkdir(parents=True)
    sample_id = "EXEC_RUN-002"
    cmd_data = {
        "sample_id": sample_id,
        "raw_command_text": "calc.exe",
        "command_length": 8,
        "shannon_entropy": 2.5,
        "is_base64_encoded": 0,
        "has_download_cradle": 0,
        "has_bypass_execution_policy": 0,
        "has_hidden_window": 0,
        "uses_lolbins": 1,
        "registry_persistence_count": 0,
    }
    (interim / "command" / f"{sample_id}.json").write_text(json.dumps(cmd_data), encoding="utf-8")

    cat_file = tmp_path / "categories.json"
    cat_file.write_text(json.dumps(mock_categories), encoding="utf-8")
    json_out = tmp_path / "out.json"
    csv_out = tmp_path / "out.csv"

    argv = [
        "--interim-dir",
        str(interim),
        "--categories",
        str(cat_file),
        "--json-out",
        str(json_out),
        "--csv-out",
        str(csv_out),
    ]

    ret = main(argv)
    assert ret == 0
    assert json_out.is_file()
    assert csv_out.is_file()


def test_real_interim_dataset_audit() -> None:
    """Run audit against real data/interim in the repo and verify expectations."""
    interim_dir = Path("data/interim")
    categories_path = Path("data/raw/custom/categories.json")

    report = audit_custom_dataset(interim_dir, categories_path)

    # We expect 45 samples from the batch extraction
    assert report.summary["total_samples"] == 45
    assert report.summary["unique_sample_ids"] == 45
    assert len(report.summary["duplicate_sample_warnings"]) == 0

    # No corruption: 0 invalid, 0 review
    assert report.summary["status_counts"]["invalid"] == 0
    assert report.summary["status_counts"]["review"] == 0

    # All 45 samples now have all 4 modalities and are valid
    assert report.summary["status_counts"]["valid"] == 45
    assert report.summary["status_counts"]["incomplete"] == 0
    assert report.summary["modality_availability"]["process"]["count"] == 45
    assert report.summary["modality_availability"]["memory"]["count"] == 45
    assert report.summary["modality_availability"]["command"]["count"] == 45
    assert report.summary["modality_availability"]["network"]["count"] == 45
    assert report.summary["modality_availability"]["all_four"]["count"] == 45
    assert report.samples["EXEC_RUN-001"]["status"] == "valid"
    assert report.samples["EXEC_RUN-002"]["status"] == "valid"

    # Terminal summary smoke test
    print_terminal_summary(report)
