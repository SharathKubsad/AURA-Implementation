"""Unit and regression tests for CAPEv2 Sandbox dataset integration and benchmark models."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from forensics.public.cape_sandbox.command_adapter import CapeCommandAdapter
from forensics.public.cape_sandbox.memory_adapter import CapeMemoryAdapter
from forensics.public.cape_sandbox.network_adapter import CapeNetworkAdapter
from forensics.public.cape_sandbox.process_adapter import CapeProcessAdapter
from forensics.public.cape_sandbox.provenance import CapeProvenance

REPO_ROOT = Path(__file__).resolve().parent.parent

PUBLIC_CAPE_RAW = REPO_ROOT / "data" / "raw" / "public" / "cape_sandbox"
PUBLIC_CAPE_PROCESSED = REPO_ROOT / "data" / "processed" / "public" / "cape_sandbox"
PUBLIC_CAPE_ARTIFACTS = REPO_ROOT / "models" / "artifacts" / "public_cape_sandbox"
PUBLIC_CAPE_EVAL = REPO_ROOT / "evaluation" / "public_cape_sandbox"
CROSS_DOMAIN_DIR = REPO_ROOT / "evaluation" / "cross_domain"

CUSTOM_MODEL_DIR = REPO_ROOT / "models" / "artifacts"
MALMEM_MODEL_DIR = REPO_ROOT / "models" / "artifacts" / "public_cic_malmem"


def test_cape_provenance_and_verification() -> None:
    """Verify CAPEv2 raw dataset verification and provenance metadata."""
    verif_file = PUBLIC_CAPE_RAW / "verification.json"
    assert verif_file.is_file(), "CAPE verification.json must exist"

    with open(verif_file, encoding="utf-8") as f:
        verif = json.load(f)

    assert "CAPEv2" in verif["dataset_name"]
    assert "CC BY-SA 4.0" in verif["license"]
    assert verif["sample_count"] == 120

    prov = CapeProvenance(
        original_sample_id="test_001",
        original_dataset="CAPEv2",
        original_source="Avast-CTU",
        original_label="Malware",
        original_family="powershell_fileless",
        source_file="report.json",
        source_report_id="CAPE_001",
        transformation_version="1.0.0",
        adapter_version="1.0.0",
        source_checksum="abc123def",
        available_modalities=["process", "command", "network"],
    )
    assert prov.original_dataset == "CAPEv2"


def test_cape_decision_gate() -> None:
    """Verify that the decision gate strictly approves Command and Network and rejects Process and Memory."""
    decision_file = PUBLIC_CAPE_PROCESSED / "dataset_decision.json"
    assert decision_file.is_file()

    with open(decision_file, encoding="utf-8") as f:
        decision = json.load(f)

    assert "CAPEv2" in decision["dataset_name"]
    assert decision["decision"] == "APPROVED_FOR_BENCHMARK"
    assert "command" in decision["approved_modalities"]
    assert "network" in decision["approved_modalities"]
    assert "memory" in decision["excluded_modalities"]
    assert "process" in decision["excluded_modalities"]


def test_cape_memory_adapter_rejects_fabrication() -> None:
    """Verify that CapeMemoryAdapter raises NotImplementedError and never fabricates memory features."""
    with pytest.raises(NotImplementedError, match="Memory modality is NOT_COMPARABLE"):
        CapeMemoryAdapter.from_cape_report({}, sample_id="mock_01")


def test_cape_adapters_schema_conformance() -> None:
    """Verify that Cape adapters produce valid telemetry schemas."""
    mock_report = {
        "behavior": {
            "processes": [
                {
                    "process_id": 1234,
                    "process_name": "cmd.exe",
                    "command_line": "cmd.exe /c powershell -enc dGVzdA==",
                    "first_seen": "2026-01-01 00:00:00",
                    "calls": [{"api": "CreateProcessW"}, {"api": "VirtualAllocEx"}],
                }
            ],
            "command_lines": ["powershell -enc dGVzdA=="],
        },
        "network": {
            "hosts": ["192.168.1.50", "8.8.8.8"],
            "domains": [{"domain": "malicious.test"}],
            "http": [{"uri": "http://malicious.test/payload"}],
            "dns": [{"request": "malicious.test"}],
            "tcp": [{"src": "10.0.2.15", "dst": "8.8.8.8", "sport": 49152, "dport": 53}],
            "udp": [],
        },
    }

    cmd_feat = CapeCommandAdapter.from_cape_report(mock_report, sample_id="mock_01")
    assert cmd_feat.sample_id == "mock_01"
    assert "powershell -enc" in cmd_feat.raw_command_text

    net_feat = CapeNetworkAdapter.from_cape_report(mock_report, sample_id="mock_01")
    assert net_feat.sample_id == "mock_01"
    assert net_feat.dns_query_count == 1
    assert net_feat.outbound_connection_count == 1
    assert net_feat.avg_interpacket_interval_ms is None

    proc_feat = CapeProcessAdapter.from_cape_report(mock_report, sample_id="mock_01")
    assert proc_feat.sample_id == "mock_01"
    assert proc_feat.total_process_count == 1


def test_cape_custom_and_malmem_isolation() -> None:
    """Verify that custom VM artifacts and MalMem artifacts remain strictly isolated and untouched."""
    # Custom artifacts
    assert (CUSTOM_MODEL_DIR / "process" / "model.json").is_file()
    assert (CUSTOM_MODEL_DIR / "command" / "model.safetensors").is_file()
    assert (CUSTOM_MODEL_DIR / "network" / "model.joblib").is_file()
    assert (CUSTOM_MODEL_DIR / "memory" / "model.cbm").is_file()

    with open(CUSTOM_MODEL_DIR / "command" / "metadata.json", encoding="utf-8") as f:
        meta_cmd = json.load(f)
    assert meta_cmd.get("dataset_name") != "Avast-CTU CAPE Sandbox Behavioral Dataset"

    # MalMem artifacts
    assert (MALMEM_MODEL_DIR / "process" / "xgboost_model.json").is_file()
    assert (MALMEM_MODEL_DIR / "memory" / "catboost_model.cbm").is_file()


def test_public_cape_artifacts_exist_after_training() -> None:
    """Verify that public CAPEv2 model artifacts exist in models/artifacts/public_cape_sandbox/."""
    cmd_artifacts = PUBLIC_CAPE_ARTIFACTS / "command"
    net_artifacts = PUBLIC_CAPE_ARTIFACTS / "network"

    assert (cmd_artifacts / "model.safetensors").is_file() or (
        cmd_artifacts / "pytorch_model.bin"
    ).is_file()
    assert (cmd_artifacts / "config.json").is_file()
    assert (cmd_artifacts / "metadata.json").is_file()

    assert (net_artifacts / "model.joblib").is_file()
    assert (net_artifacts / "features.json").is_file()
    assert (net_artifacts / "metadata.json").is_file()


def test_public_cape_cross_domain_reports() -> None:
    """Verify that cross-domain zero-shot evaluation reports exist and have proper structure."""
    cmd_cross = CROSS_DOMAIN_DIR / "cape_to_custom_command.json"
    net_cross = CROSS_DOMAIN_DIR / "cape_to_custom_network.json"
    shift_file = CROSS_DOMAIN_DIR / "cape_domain_shift_analysis.json"

    assert cmd_cross.is_file()
    assert net_cross.is_file()
    assert shift_file.is_file()

    with open(cmd_cross, encoding="utf-8") as f:
        c_data = json.load(f)
    assert c_data["evaluation_type"] == "ZERO-SHOT CROSS-DOMAIN EVALUATION"
    assert c_data["metrics"]["total_samples"] == 45
    assert "domain_shift_analysis" in c_data or "probability_distribution" in c_data

    with open(net_cross, encoding="utf-8") as f:
        n_data = json.load(f)
    assert n_data["evaluation_type"] == "ZERO-SHOT CROSS-DOMAIN EVALUATION"
    assert n_data["metrics"]["total_samples"] == 45
    assert "avg_interpacket_interval_ms" in n_data["excluded_features"]
    assert "beacon_regularity_score" in n_data["excluded_features"]

    with open(shift_file, encoding="utf-8") as f:
        s_data = json.load(f)
    assert "features_analyzed" in s_data
    assert "outbound_connection_count" in s_data["features_analyzed"]
