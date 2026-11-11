"""Comprehensive test suite for DetectionService model loading and scoring."""

from __future__ import annotations

import pytest

from forensics.schemas import (
    CommandFeatures,
    MemoryFeatures,
    NetworkFeatures,
    ProcessFeatures,
)
from framework.detection_service import DetectionService
from models.command.model import CommandModel
from models.memory.model import MemoryModel
from models.network.model import NetworkModel
from models.process.model import ProcessModel


@pytest.fixture(scope="module")
def detection_service() -> DetectionService:
    """Instantiate DetectionService with real model artifacts."""
    return DetectionService()


@pytest.fixture
def benign_telemetry() -> tuple[ProcessFeatures, CommandFeatures, NetworkFeatures, MemoryFeatures]:
    """Create benign telemetry schema instances."""
    proc = ProcessFeatures(
        sample_id="test_benign",
        total_process_count=45,
        hidden_process_count=0,
        anomalous_ppid_count=0,
        avg_threads_per_process=12.0,
        max_threads_in_single_process=50,
        total_handle_count=1200,
        suspicious_dll_count=0,
        malfind_process_count=0,
        elevated_privilege_count=0,
        unlinked_dll_count=0,
    )
    cmd = CommandFeatures(
        sample_id="test_benign",
        raw_command_text="Get-Process | Where-Object {$_.CPU -gt 10}",
        command_length=42,
        shannon_entropy=4.2,
        is_base64_encoded=0,
        has_download_cradle=0,
        has_bypass_execution_policy=0,
        has_hidden_window=0,
        uses_lolbins=0,
        registry_persistence_count=0,
    )
    net = NetworkFeatures(
        sample_id="test_benign",
        active_connection_count=4,
        listening_port_count=2,
        outbound_connection_count=2,
        dns_query_count=5,
        unique_remote_ips=2,
        avg_interpacket_interval_ms=120.0,
        beacon_regularity_score=0.1,
        total_bytes_sent=1500,
        total_bytes_received=4500,
        suspicious_port_usage=0,
    )
    mem = MemoryFeatures(
        sample_id="test_benign",
        rwx_page_count=0,
        injected_code_regions=0,
        unmapped_executable_pages=0,
        vad_protection_anomaly_count=0,
        ldrmodules_inconsistencies=0,
        yara_shellcode_matches=0,
        mean_memory_entropy=2.1,
        max_memory_entropy=3.5,
    )
    return proc, cmd, net, mem


@pytest.fixture
def malware_telemetry() -> tuple[ProcessFeatures, CommandFeatures, NetworkFeatures, MemoryFeatures]:
    """Create malware-like telemetry schema instances."""
    proc = ProcessFeatures(
        sample_id="test_malware",
        total_process_count=120,
        hidden_process_count=3,
        anomalous_ppid_count=2,
        avg_threads_per_process=28.0,
        max_threads_in_single_process=150,
        total_handle_count=8500,
        suspicious_dll_count=4,
        malfind_process_count=2,
        elevated_privilege_count=3,
        unlinked_dll_count=2,
    )
    cmd = CommandFeatures(
        sample_id="test_malware",
        raw_command_text="powershell.exe -nop -w hidden -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        command_length=76,
        shannon_entropy=5.8,
        is_base64_encoded=1,
        has_download_cradle=1,
        has_bypass_execution_policy=1,
        has_hidden_window=1,
        uses_lolbins=1,
        registry_persistence_count=1,
    )
    net = NetworkFeatures(
        sample_id="test_malware",
        active_connection_count=18,
        listening_port_count=6,
        outbound_connection_count=12,
        dns_query_count=45,
        unique_remote_ips=9,
        avg_interpacket_interval_ms=10.5,
        beacon_regularity_score=0.92,
        total_bytes_sent=85000,
        total_bytes_received=120000,
        suspicious_port_usage=1,
    )
    mem = MemoryFeatures(
        sample_id="test_malware",
        rwx_page_count=6,
        injected_code_regions=3,
        unmapped_executable_pages=4,
        vad_protection_anomaly_count=2,
        ldrmodules_inconsistencies=2,
        yara_shellcode_matches=1,
        mean_memory_entropy=6.8,
        max_memory_entropy=7.8,
    )
    return proc, cmd, net, mem


def test_models_loaded_correctly(detection_service: DetectionService) -> None:
    """Verify that all four binary models and the multiclass model are loaded."""
    assert detection_service.process_model is not None
    assert isinstance(detection_service.process_model, ProcessModel)

    assert detection_service.command_model is not None
    assert isinstance(detection_service.command_model, CommandModel)

    assert detection_service.network_model is not None
    assert isinstance(detection_service.network_model, NetworkModel)

    assert detection_service.memory_model is not None
    assert isinstance(detection_service.memory_model, MemoryModel)


def test_individual_modality_scoring(
    detection_service: DetectionService,
    benign_telemetry: tuple[ProcessFeatures, CommandFeatures, NetworkFeatures, MemoryFeatures],
    malware_telemetry: tuple[ProcessFeatures, CommandFeatures, NetworkFeatures, MemoryFeatures],
) -> None:
    """Verify score_* methods return float probabilities in [0.0, 1.0]."""
    b_proc, b_cmd, b_net, b_mem = benign_telemetry
    m_proc, m_cmd, m_net, m_mem = malware_telemetry

    for proc in [b_proc, m_proc]:
        score = detection_service.score_process(proc)
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0

    for cmd in [b_cmd, m_cmd]:
        score = detection_service.score_command(cmd)
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0

    for net in [b_net, m_net]:
        score = detection_service.score_network(net)
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0

    for mem in [b_mem, m_mem]:
        score = detection_service.score_memory(mem)
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0


def test_detect_pipeline_contract(
    detection_service: DetectionService,
    malware_telemetry: tuple[ProcessFeatures, CommandFeatures, NetworkFeatures, MemoryFeatures],
) -> None:
    """Verify detect() produces full contract with all expected keys."""
    proc, cmd, net, mem = malware_telemetry
    result = detection_service.detect(proc=proc, cmd=cmd, net=net, mem=mem)

    assert "verdict" in result
    assert result["verdict"] in ("benign", "malware")
    assert "confidence" in result
    assert 0.0 <= result["confidence"] <= 1.0
    assert "is_malware" in result
    assert isinstance(result["is_malware"], bool)
    assert "memory_triggered" in result
    assert "per_model" in result
    assert set(result["per_model"].keys()) == {"process", "command", "network", "memory"}
    assert "fusion_threshold" in result
    assert result["fusion_threshold"] == 0.60


def test_predict_proba_and_predict_interfaces(
    detection_service: DetectionService,
    benign_telemetry: tuple[ProcessFeatures, CommandFeatures, NetworkFeatures, MemoryFeatures],
) -> None:
    """Verify predict_proba() and predict() interfaces on DetectionService."""
    proc, cmd, net, mem = benign_telemetry
    prob = detection_service.predict_proba(proc=proc, cmd=cmd, net=net, mem=mem)
    assert isinstance(prob, float)
    assert 0.0 <= prob <= 1.0

    pred = detection_service.predict(proc=proc, cmd=cmd, net=net, mem=mem, threshold=0.60)
    assert pred in (0, 1)
    assert pred == int(prob >= 0.60)
