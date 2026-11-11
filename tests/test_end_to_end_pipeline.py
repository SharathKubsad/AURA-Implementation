"""Comprehensive deterministic end-to-end pipeline test suite.

Verifies complete execution flow:
Raw telemetry -> Pydantic schemas -> Process model -> Command model -> Network model
-> Suspicion trigger -> Memory forensics trigger -> Fusion engine -> Binary verdict
-> Multiclass family attribution (if malware) -> XAI explanations.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from forensics.schemas import (
    CommandFeatures,
    MemoryFeatures,
    NetworkFeatures,
    ProcessFeatures,
)
from framework.detection_service import DetectionService
from evaluation.xai.lime_report import LimeExplainerManager
from evaluation.xai.shap_report import ShapExplainerManager


@pytest.fixture(scope="module")
def detection_service() -> DetectionService:
    """Initialize singleton DetectionService with real model artifacts."""
    return DetectionService()


@pytest.fixture(scope="module")
def authentic_samples() -> dict[str, dict]:
    """Load authentic custom VM samples for deterministic testing."""
    jsonl_path = Path("data/processed/unified/unified_dataset.jsonl")
    records = [json.loads(line) for line in jsonl_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    benign = next(r for r in records if r["sample_id"] == "EXEC_RUN-001")
    malware = next(r for r in records if r["sample_id"] == "EXEC_RUN-002")
    return {"benign": benign, "malware": malware}


def test_end_to_end_benign_pipeline(detection_service: DetectionService, authentic_samples: dict[str, dict]) -> None:
    """Test full pipeline on authentic benign execution (EXEC_RUN-001)."""
    b = authentic_samples["benign"]
    
    proc = ProcessFeatures(
        sample_id=b["sample_id"],
        total_process_count=b["total_process_count"],
        hidden_process_count=b["hidden_process_count"],
        anomalous_ppid_count=b["anomalous_ppid_count"],
        avg_threads_per_process=b["avg_threads_per_process"],
        max_threads_in_single_process=b["max_threads_in_single_process"],
        total_handle_count=b["total_handle_count"],
        suspicious_dll_count=b["suspicious_dll_count"],
        malfind_process_count=b["malfind_process_count"],
        elevated_privilege_count=b["elevated_privilege_count"],
        unlinked_dll_count=b["unlinked_dll_count"],
    )
    cmd = CommandFeatures(
        sample_id=b["sample_id"],
        raw_command_text=b["raw_command_text"],
        command_length=b["command_length"],
        shannon_entropy=b["shannon_entropy"],
        is_base64_encoded=b["is_base64_encoded"],
        has_download_cradle=b["has_download_cradle"],
        has_bypass_execution_policy=b["has_bypass_execution_policy"],
        has_hidden_window=b["has_hidden_window"],
        uses_lolbins=b["uses_lolbins"],
        registry_persistence_count=b["registry_persistence_count"],
    )
    net = NetworkFeatures(
        sample_id=b["sample_id"],
        active_connection_count=b["active_connection_count"],
        listening_port_count=b["listening_port_count"],
        outbound_connection_count=b["outbound_connection_count"],
        dns_query_count=b.get("dns_query_count") or 0,
        unique_remote_ips=b["unique_remote_ips"],
        avg_interpacket_interval_ms=b.get("avg_interpacket_interval_ms") or 0.0,
        beacon_regularity_score=b.get("beacon_regularity_score") or 0.0,
        total_bytes_sent=b.get("total_bytes_sent") or 0,
        total_bytes_received=b.get("total_bytes_received") or 0,
        suspicious_port_usage=b["suspicious_port_usage"],
    )
    mem = MemoryFeatures(
        sample_id=b["sample_id"],
        rwx_page_count=b["rwx_page_count"],
        injected_code_regions=b["injected_code_regions"],
        unmapped_executable_pages=b["unmapped_executable_pages"],
        vad_protection_anomaly_count=b["vad_protection_anomaly_count"],
        ldrmodules_inconsistencies=b["ldrmodules_inconsistencies"],
        yara_shellcode_matches=b["yara_shellcode_matches"],
        mean_memory_entropy=b.get("mean_memory_entropy") or 0.0,
        max_memory_entropy=b.get("max_memory_entropy") or 0.0,
    )

    # 1. Run detection
    res = detection_service.detect(proc=proc, cmd=cmd, net=net, mem=mem)

    # 2. Structural & Schema assertions
    assert "verdict" in res
    assert res["verdict"] in ("benign", "malware")
    assert "confidence" in res
    assert 0.0 <= res["confidence"] <= 1.0
    assert "is_malware" in res
    assert isinstance(res["is_malware"], bool)
    assert "per_model" in res
    for mod in ["process", "command", "network", "memory"]:
        assert mod in res["per_model"]
        assert 0.0 <= res["per_model"][mod] <= 1.0

    # 3. Benign specific assertions: verdict must be benign and family attribution should be None
    assert res["verdict"] == "benign"
    assert res["is_malware"] is False
    assert res["confidence"] < 0.60
    assert res["family"] is None


def test_end_to_end_malware_pipeline(detection_service: DetectionService, authentic_samples: dict[str, dict]) -> None:
    """Test full pipeline on authentic malware execution (EXEC_RUN-002: powershell_fileless)."""
    m = authentic_samples["malware"]
    
    proc = ProcessFeatures(
        sample_id=m["sample_id"],
        total_process_count=m["total_process_count"],
        hidden_process_count=m["hidden_process_count"],
        anomalous_ppid_count=m["anomalous_ppid_count"],
        avg_threads_per_process=m["avg_threads_per_process"],
        max_threads_in_single_process=m["max_threads_in_single_process"],
        total_handle_count=m["total_handle_count"],
        suspicious_dll_count=m["suspicious_dll_count"],
        malfind_process_count=m["malfind_process_count"],
        elevated_privilege_count=m["elevated_privilege_count"],
        unlinked_dll_count=m["unlinked_dll_count"],
    )
    cmd = CommandFeatures(
        sample_id=m["sample_id"],
        raw_command_text=m["raw_command_text"],
        command_length=m["command_length"],
        shannon_entropy=m["shannon_entropy"],
        is_base64_encoded=m["is_base64_encoded"],
        has_download_cradle=m["has_download_cradle"],
        has_bypass_execution_policy=m["has_bypass_execution_policy"],
        has_hidden_window=m["has_hidden_window"],
        uses_lolbins=m["uses_lolbins"],
        registry_persistence_count=m["registry_persistence_count"],
    )
    net = NetworkFeatures(
        sample_id=m["sample_id"],
        active_connection_count=m["active_connection_count"],
        listening_port_count=m["listening_port_count"],
        outbound_connection_count=m["outbound_connection_count"],
        dns_query_count=m.get("dns_query_count") or 0,
        unique_remote_ips=m["unique_remote_ips"],
        avg_interpacket_interval_ms=m.get("avg_interpacket_interval_ms") or 0.0,
        beacon_regularity_score=m.get("beacon_regularity_score") or 0.0,
        total_bytes_sent=m.get("total_bytes_sent") or 0,
        total_bytes_received=m.get("total_bytes_received") or 0,
        suspicious_port_usage=m["suspicious_port_usage"],
    )
    mem = MemoryFeatures(
        sample_id=m["sample_id"],
        rwx_page_count=m["rwx_page_count"],
        injected_code_regions=m["injected_code_regions"],
        unmapped_executable_pages=m["unmapped_executable_pages"],
        vad_protection_anomaly_count=m["vad_protection_anomaly_count"],
        ldrmodules_inconsistencies=m["ldrmodules_inconsistencies"],
        yara_shellcode_matches=m["yara_shellcode_matches"],
        mean_memory_entropy=m.get("mean_memory_entropy") or 0.0,
        max_memory_entropy=m.get("max_memory_entropy") or 0.0,
    )

    # 1. Run detection
    res = detection_service.detect(proc=proc, cmd=cmd, net=net, mem=mem)

    # 2. Assert malware detection and threshold
    assert res["verdict"] == "malware"
    assert res["is_malware"] is True
    assert res["confidence"] >= 0.60
    assert res["memory_triggered"] is True

    # 3. Post-verdict Multiclass Family Attribution
    assert res["family"] is not None
    assert isinstance(res["family"], str)
    assert res["family_confidence"] is not None
    assert 0.0 <= res["family_confidence"] <= 1.0
    assert isinstance(res["family_probabilities"], dict)
    assert len(res["family_probabilities"]) > 0

    # 4. Explainability (SHAP & LIME) Execution Verification
    shap_mgr = ShapExplainerManager(detection_service)
    proc_shap = shap_mgr.explain_process(proc.model_dump())
    mem_shap = shap_mgr.explain_memory(mem.model_dump())
    assert isinstance(proc_shap, list)
    assert isinstance(mem_shap, list)

    lime_mgr = LimeExplainerManager(detection_service)
    cmd_tokens = lime_mgr.explain_command_text(cmd.raw_command_text, num_features=4)
    assert isinstance(cmd_tokens, list)
    proc_weights = lime_mgr.explain_process_tabular(proc.model_dump(), num_features=4)
    assert isinstance(proc_weights, list)
