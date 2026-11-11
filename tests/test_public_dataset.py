"""Tests for public dataset adapters, provenance, and audit infrastructure."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from forensics.public.command_adapter import CommandAdapter
from forensics.public.memory_adapter import MemoryAdapter
from forensics.public.network_adapter import NetworkAdapter
from forensics.public.process_adapter import ProcessAdapter
from forensics.public.provenance import DatasetCompatibility, PublicProvenance
from forensics.schemas.command import CommandFeatures
from forensics.schemas.memory import MemoryFeatures
from forensics.schemas.network import NetworkFeatures
from forensics.schemas.process import ProcessFeatures
from tools.audit_public_dataset import PublicDatasetAuditor

_REPO_ROOT = Path(__file__).resolve().parent.parent


class TestPublicProvenance:
    """Tests for public provenance validation and tracking."""

    def test_valid_provenance(self) -> None:
        """Verify valid provenance model initialization."""
        prov = PublicProvenance(
            original_dataset="CIC-MalMem-2022",
            original_sample_id="SAMPLE_001",
            original_label="Malware",
            original_family="Spyware-Gator",
            source_reference="https://www.unb.ca/cic/datasets/malmem-2022.html",
            available_modalities=["process", "memory"],
            mapping_method="Volatility 2/3 outputs",
            checksum="abcdef123456",
        )
        assert prov.original_dataset == "CIC-MalMem-2022"
        assert prov.available_modalities == ["process", "memory"]

    def test_invalid_provenance_rejects_missing_fields(self) -> None:
        """Verify validation error when essential provenance fields are missing."""
        with pytest.raises(ValidationError):
            PublicProvenance(  # type: ignore[call-arg]
                original_dataset="CIC-MalMem-2022",
                # missing original_sample_id, original_label, etc.
            )


class TestProcessAdapter:
    """Tests for ProcessAdapter from public formats."""

    def test_process_adapter_from_malmem(self) -> None:
        """Verify conversion of MalMem Volatility features to ProcessFeatures."""
        malmem_raw = {
            "pslist.nproc": 45,
            "pslist.avg_threads": 12.4,
            "psxview.not_in_pslist": 1,
            "psxview.not_in_csrss_handles": 1,
            "handles.nhandles": 8500,
            "dlllist.ndlls": 1500,
            "ldrmodules.not_in_load": 3,
            "malfind.ninjections": 5,
        }
        feat = ProcessAdapter.from_malmem(malmem_raw, "PUB_PROC_001")
        assert isinstance(feat, ProcessFeatures)
        assert feat.sample_id == "PUB_PROC_001"
        assert feat.total_process_count == 45
        assert feat.hidden_process_count == 1
        assert feat.malfind_process_count == 5
        assert feat.unlinked_dll_count == 3

    def test_process_adapter_from_behavioral(self) -> None:
        """Verify conversion of behavioral execution summary to ProcessFeatures."""
        sandbox_raw = {
            "total_process_count": 6,
            "hidden_process_count": 0,
            "anomalous_ppid_count": 1,
            "avg_threads_per_process": 2.5,
            "total_handle_count": 320,
        }
        feat = ProcessAdapter.from_behavioral(sandbox_raw, "PUB_PROC_002")
        assert isinstance(feat, ProcessFeatures)
        assert feat.total_process_count == 6
        assert feat.anomalous_ppid_count == 1


class TestMemoryAdapter:
    """Tests for MemoryAdapter and genuine null preservation."""

    def test_memory_adapter_from_malmem_preserves_null_entropy(self) -> None:
        """Verify MalMem Volatility features preserve memory entropy as None."""
        malmem_raw = {
            "malfind.ninjections": 8,
            "malfind.uniqueInjections": 6,
            "malfind.commitCharge": 32,
            "ldrmodules.not_in_load": 4,
            "ldrmodules.not_in_init": 2,
            "ldrmodules.not_in_mem": 1,
        }
        feat = MemoryAdapter.from_malmem(malmem_raw, "PUB_MEM_001")
        assert isinstance(feat, MemoryFeatures)
        assert feat.sample_id == "PUB_MEM_001"
        assert feat.injected_code_regions == 8
        assert feat.unmapped_executable_pages == 6
        assert feat.ldrmodules_inconsistencies == 7
        # Strict requirement: entropy MUST NOT be fabricated
        assert feat.mean_memory_entropy is None
        assert feat.max_memory_entropy is None


class TestCommandAdapter:
    """Tests for CommandAdapter and non-fabrication constraints."""

    def test_command_adapter_from_raw_command(self) -> None:
        """Verify deterministic parsing of raw command strings."""
        cmd = "powershell.exe -w hidden -ep bypass -enc AAAA"
        feat = CommandAdapter.from_raw_command(cmd, "PUB_CMD_001")
        assert isinstance(feat, CommandFeatures)
        assert feat.sample_id == "PUB_CMD_001"
        assert feat.raw_command_text == cmd
        assert feat.has_hidden_window == 1
        assert feat.has_bypass_execution_policy == 1
        assert feat.command_length == len(cmd)
        assert feat.shannon_entropy > 0.0

    def test_command_adapter_rejects_none(self) -> None:
        """Verify CommandAdapter refuses to fabricate features from None."""
        with pytest.raises(ValueError, match="command telemetry cannot be fabricated"):
            CommandAdapter.from_raw_command(None, "PUB_CMD_002")  # type: ignore[arg-type]


class TestNetworkAdapter:
    """Tests for NetworkAdapter and native NaN handling."""

    def test_network_adapter_preserves_pcap_nulls(self) -> None:
        """Verify unsupported PCAP fields remain None rather than zero-filled."""
        net_raw = {
            "active_connection_count": 3,
            "listening_port_count": 1,
            "outbound_connection_count": 2,
            "unique_remote_ips": 2,
            "suspicious_port_usage": 1,
            # Notice: interpacket interval, beacon regularity, byte statistics are omitted
        }
        feat = NetworkAdapter.from_flow_or_sandbox(net_raw, "PUB_NET_001")
        assert isinstance(feat, NetworkFeatures)
        assert feat.active_connection_count == 3
        assert feat.suspicious_port_usage == 1
        assert feat.avg_interpacket_interval_ms is None
        assert feat.beacon_regularity_score is None
        assert feat.total_bytes_sent is None
        assert feat.total_bytes_received is None


class TestPublicAuditorAndIsolation:
    """Tests for PublicDatasetAuditor and isolation guarantees."""

    def test_audit_public_dataset_run(self) -> None:
        """Verify audit runs successfully on processed public directory."""
        auditor = PublicDatasetAuditor()
        report = auditor.run_audit()
        assert report["audit_passed"] is True
        assert report["total_public_samples"] == 10
        assert report["custom_dataset_isolation"]["status"] == "ISOLATED"
        assert len(report["duplicate_sample_ids"]) == 0
        assert report["schema_validation_status"]["failures_count"] == 0
        assert report["provenance_completeness"]["completeness_pct"] == 100.0

    def test_custom_dataset_zero_pollution(self) -> None:
        """Verify zero overlap between custom dataset sample IDs and public IDs."""
        custom_jsonl = _REPO_ROOT / "data" / "processed" / "unified" / "unified_dataset.jsonl"
        public_jsonl = (
            _REPO_ROOT / "data" / "processed" / "public" / "public_benchmark_dataset.jsonl"
        )

        if custom_jsonl.exists() and public_jsonl.exists():
            custom_ids = set()
            with open(custom_jsonl, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        custom_ids.add(json.loads(line)["sample_id"])

            public_ids = set()
            with open(public_jsonl, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        public_ids.add(json.loads(line)["sample_id"])

            intersection = custom_ids.intersection(public_ids)
            assert len(intersection) == 0, f"Pollution detected: {intersection}"

    def test_compatibility_enum_values(self) -> None:
        """Verify compatibility classification enum values."""
        assert DatasetCompatibility.COMPATIBLE.value == "COMPATIBLE"
        assert DatasetCompatibility.PARTIALLY_COMPATIBLE.value == "PARTIALLY_COMPATIBLE"
        assert DatasetCompatibility.INCOMPATIBLE.value == "INCOMPATIBLE"
