"""Unit tests for JSON Schemas and Pydantic feature contracts (Task J2)."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from forensics.schemas import (
    BinaryLabel,
    CommandFeatures,
    EnvironmentType,
    InitialFamilyLabel,
    MemoryFeatures,
    NetworkFeatures,
    OperatingSystem,
    ProcessFeatures,
    SampleMetadata,
    SourceType,
)


@pytest.fixture
def schemas_dir() -> Path:
    """Return path to data/schemas directory."""
    return Path(__file__).resolve().parent.parent / "data" / "schemas"


def test_schema_files_exist(schemas_dir: Path) -> None:
    """Verify all expected JSON schema files exist."""
    expected_schemas = [
        "schema_version.json",
        "labels.schema.json",
        "sample_metadata.schema.json",
        "process_features.schema.json",
        "command_features.schema.json",
        "network_features.schema.json",
        "memory_features.schema.json",
    ]
    for schema_file in expected_schemas:
        path = schemas_dir / schema_file
        assert path.is_file(), f"Missing schema file: {schema_file}"
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
            assert isinstance(data, dict), f"Schema {schema_file} is not a valid JSON object"
            assert "$schema" in data or "schema_version" in data


def test_sample_id_in_all_feature_schemas(schemas_dir: Path) -> None:
    """Verify that sample_id is present and required in all feature schemas."""
    feature_schemas = [
        "sample_metadata.schema.json",
        "process_features.schema.json",
        "command_features.schema.json",
        "network_features.schema.json",
        "memory_features.schema.json",
    ]
    for filename in feature_schemas:
        path = schemas_dir / filename
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
            props = data.get("properties", {})
            assert "sample_id" in props, f"sample_id missing in {filename} properties"
            required = data.get("required", [])
            assert "sample_id" in required, f"sample_id not required in {filename}"


def test_pydantic_sample_metadata_validation() -> None:
    """Test validation of SampleMetadata model."""
    valid_meta = SampleMetadata(
        sample_id="EXEC_20260913_001",
        source_type=SourceType.CUSTOM_SANDBOX,
        source_id="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        execution_id="RUN_WIN11_001",
        timestamp=datetime.now(UTC),
        operating_system=OperatingSystem.WINDOWS_11,
        environment=EnvironmentType.VMWARE_WORKSTATION,
        binary_label=BinaryLabel.MALWARE,
        family_label=InitialFamilyLabel.PROCESS_HOLLOWING,
        family_name="Process Hollowing",
        operator="Track A",
    )
    assert valid_meta.binary_label == 1
    assert valid_meta.family_label == 3

    # Invalid sample_id pattern
    with pytest.raises(ValidationError):
        SampleMetadata(
            sample_id="INVALID_PATTERN_XYZ",
            source_type=SourceType.CUSTOM_SANDBOX,
            source_id="123",
            execution_id="run1",
            timestamp=datetime.now(UTC),
            operating_system=OperatingSystem.WINDOWS_10,
            environment=EnvironmentType.VMWARE_WORKSTATION,
            binary_label=BinaryLabel.BENIGN,
            family_label=0,
            family_name="Benign",
        )


def test_pydantic_all_modalities_linkage() -> None:
    """Test linking all 4 modalities using the identical sample_id."""
    sample_id = "EXEC_20260913_TEST_01"

    proc = ProcessFeatures(
        sample_id=sample_id,
        total_process_count=130,
        hidden_process_count=0,
        anomalous_ppid_count=0,
        avg_threads_per_process=12.5,
        max_threads_in_single_process=45,
        total_handle_count=4500,
        suspicious_dll_count=0,
        malfind_process_count=0,
        elevated_privilege_count=1,
    )

    cmd = CommandFeatures(
        sample_id=sample_id,
        raw_command_text="powershell.exe -ExecutionPolicy Bypass -NoProfile -File script.ps1",
        command_length=64,
        shannon_entropy=4.12,
        is_base64_encoded=0,
        has_download_cradle=0,
        has_bypass_execution_policy=1,
        has_hidden_window=0,
        uses_lolbins=0,
    )

    net = NetworkFeatures(
        sample_id=sample_id,
        active_connection_count=5,
        listening_port_count=12,
        outbound_connection_count=2,
        dns_query_count=3,
        unique_remote_ips=2,
        avg_interpacket_interval_ms=150.0,
        beacon_regularity_score=0.1,
        total_bytes_sent=1024,
        total_bytes_received=2048,
        suspicious_port_usage=0,
    )

    mem = MemoryFeatures(
        sample_id=sample_id,
        rwx_page_count=0,
        injected_code_regions=0,
        unmapped_executable_pages=0,
        vad_protection_anomaly_count=0,
        ldrmodules_inconsistencies=0,
        yara_shellcode_matches=0,
        mean_memory_entropy=3.1,
        max_memory_entropy=4.5,
    )

    assert proc.sample_id == cmd.sample_id == net.sample_id == mem.sample_id == sample_id
    assert cmd.raw_command_text.startswith("powershell.exe")
