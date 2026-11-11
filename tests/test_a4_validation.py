"""Unit tests for the A4 real-evidence validation workflow (tools/validate_a4_evidence.py)."""

from pathlib import Path

import pytest

from forensics.schemas.memory import MemoryFeatures
from forensics.schemas.process import ProcessFeatures
from tools.validate_a4_evidence import (
    find_default_run001_dir,
    run_a4_validation,
    validate_ldrmodules_semantics,
    validate_malfind_semantics,
)


@pytest.fixture
def run_001_fixtures_dir() -> Path:
    """Path to RUN-001 Volatility 3 output fixtures."""
    return Path(__file__).resolve().parent / "fixtures" / "volatility" / "RUN-001"


def test_find_default_run001_dir() -> None:
    """Test locating RUN-001 evidence directory across environments."""
    found_dir = find_default_run001_dir()
    assert found_dir is not None
    assert found_dir.is_dir()


def test_a4_validation_on_clean_run001_fixtures(run_001_fixtures_dir: Path) -> None:
    """Verify that the validation suite executes cleanly on RUN-001 fixtures."""
    result = run_a4_validation(run_001_fixtures_dir, sample_id="RUN-001")

    assert result.sample_id == "RUN-001"
    assert result.process_status is True
    assert result.memory_status is True
    assert result.malfind_status is True
    assert result.ldrmodules_status is True
    assert result.schema_status is True
    assert result.overall_status is True


def test_a4_validation_on_multiline_malfind_evidence(tmp_path: Path) -> None:
    """Verify validator succeeds on multiline malfind evidence and accurately derives 22 findings."""
    multiline_fixture = (
        Path(__file__).resolve().parent
        / "fixtures"
        / "volatility"
        / "regression_malfind_multiline.txt"
    )
    assert multiline_fixture.is_file()

    # Set up test evidence directory
    (tmp_path / "malfind.txt").write_text(
        multiline_fixture.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "pslist.json").write_text("[]", encoding="utf-8")
    (tmp_path / "vadinfo.json").write_text("[]", encoding="utf-8")

    result = run_a4_validation(tmp_path, sample_id="RUN-001")

    assert result.malfind_status is True
    assert result.overall_status is True
    # Verify detail message explicitly records genuine findings count
    assert any("22 genuine injected regions" in d for d in result.details)


def test_a4_validation_detects_injected_code_regions_overcounting_bug(tmp_path: Path) -> None:
    """Verify that validator explicitly catches the 906 over-counting bug when simulated."""
    multiline_fixture = (
        Path(__file__).resolve().parent
        / "fixtures"
        / "volatility"
        / "regression_malfind_multiline.txt"
    )
    (tmp_path / "malfind.txt").write_text(
        multiline_fixture.read_text(encoding="utf-8"), encoding="utf-8"
    )

    # Simulate buggy memory extractor that overcounts raw parsed lines (e.g. 904 or 906)
    buggy_mem_features = MemoryFeatures(
        sample_id="RUN-001",
        rwx_page_count=0,
        injected_code_regions=906,  # The bug!
        unmapped_executable_pages=0,
        vad_protection_anomaly_count=0,
        ldrmodules_inconsistencies=0,
        yara_shellcode_matches=0,
        mean_memory_entropy=None,
        max_memory_entropy=None,
    )
    proc_features = ProcessFeatures(
        sample_id="RUN-001",
        total_process_count=10,
        hidden_process_count=0,
        anomalous_ppid_count=0,
        avg_threads_per_process=5.0,
        max_threads_in_single_process=10,
        total_handle_count=100,
        suspicious_dll_count=0,
        malfind_process_count=12,
        elevated_privilege_count=0,
        unlinked_dll_count=0,
    )

    details: list[str] = []
    status = validate_malfind_semantics(tmp_path, buggy_mem_features, proc_features, details)

    # Validator MUST reject the over-counted 906 value
    assert status is False
    assert any("Malfind FAIL" in d and "Extractor=906" in d for d in details)


def test_a4_validation_ldrmodules_wrapped_paths_semantics(tmp_path: Path) -> None:
    """Verify validator correctly checks ldrmodules record boundary filtering."""
    ldrmodules_raw = """
Volatility 3 Framework 2.28.0
PID\tProcess\tBase\tInLoad\tInInit\tInMem\tMappedPath
4\tSystem\t0x7ff80000\tTrue\tTrue\tTrue\t\\SystemRoot\\System32\\ntoskrnl.exe
100\tproc.exe\t0x7ff90000\tFalse\tFalse\tTrue\tC:\\Windows\\System32\\
\tvery_long_wrapped_driver_name.sys
200\tproc2.exe\t0x7ffa0000\tTrue\tTrue\tTrue\tC:\\Windows\\System32\\clean.dll
"""
    (tmp_path / "ldrmodules.txt").write_text(ldrmodules_raw.strip(), encoding="utf-8")

    mem_features = MemoryFeatures(
        sample_id="RUN-001",
        rwx_page_count=0,
        injected_code_regions=0,
        unmapped_executable_pages=0,
        vad_protection_anomaly_count=0,
        ldrmodules_inconsistencies=1,
        yara_shellcode_matches=0,
        mean_memory_entropy=None,
        max_memory_entropy=None,
    )
    proc_features = ProcessFeatures(
        sample_id="RUN-001",
        total_process_count=3,
        hidden_process_count=0,
        anomalous_ppid_count=0,
        avg_threads_per_process=2.0,
        max_threads_in_single_process=5,
        total_handle_count=50,
        suspicious_dll_count=0,
        malfind_process_count=0,
        elevated_privilege_count=0,
        unlinked_dll_count=1,
    )

    details: list[str] = []
    status = validate_ldrmodules_semantics(tmp_path, mem_features, proc_features, details)

    assert status is True
    assert any("LdrModules PASS" in d for d in details)
