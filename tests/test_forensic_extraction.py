"""Unit, integration, and semantic regression tests for Track A forensic extraction pipeline."""

import json
from pathlib import Path
from typing import Any

import pytest

from forensics.extraction import (
    calculate_shannon_entropy,
    extract_memory_features,
    extract_process_features,
    parse_ldrmodules_output,
    parse_malfind_output,
    parse_volatility_file,
    run_track_a_extraction,
)
from forensics.schemas import MemoryFeatures, ProcessFeatures


@pytest.fixture
def run_001_fixtures_dir() -> Path:
    """Path to RUN-001 Volatility 3 output fixtures."""
    return Path(__file__).resolve().parent / "fixtures" / "volatility" / "RUN-001"


def test_entropy_calculator() -> None:
    """Test Shannon entropy calculation on known inputs."""
    # Zero entropy for identical byte sequence
    assert calculate_shannon_entropy(b"AAAAAAA") == 0.0

    # High entropy for diverse character distribution
    high_ent = calculate_shannon_entropy(bytes(range(256)))
    assert 7.9 <= high_ent <= 8.0

    # Empty data
    assert calculate_shannon_entropy(b"") == 0.0


def test_extract_process_features_benign_run_001(run_001_fixtures_dir: Path) -> None:
    """Verify that RUN-001 is validated strictly as a clean benign sample."""
    sample_id = "EXEC_RUN-001"
    features = extract_process_features(run_001_fixtures_dir, sample_id=sample_id)

    assert isinstance(features, ProcessFeatures)
    assert features.sample_id == sample_id
    assert features.total_process_count == 10
    # On benign sample, all security anomaly metrics must be 0
    assert features.hidden_process_count == 0
    assert features.anomalous_ppid_count == 0
    assert features.suspicious_dll_count == 0
    assert features.malfind_process_count == 0
    # lsass.exe (PID 540) legitimately holds enabled SeDebugPrivilege in authentic Windows telemetry
    assert features.elevated_privilege_count == 1
    assert features.unlinked_dll_count == 0
    assert features.avg_threads_per_process > 0.0
    assert features.total_handle_count > 0


def test_extract_memory_features_benign_run_001(run_001_fixtures_dir: Path) -> None:
    """Verify that MemoryFeatures for benign RUN-001 has 0 anomalies and None entropy."""
    sample_id = "EXEC_RUN-001"
    features = extract_memory_features(run_001_fixtures_dir, sample_id=sample_id)

    assert isinstance(features, MemoryFeatures)
    assert features.sample_id == sample_id
    assert features.rwx_page_count == 0
    assert features.injected_code_regions == 0
    assert features.unmapped_executable_pages == 0
    assert features.vad_protection_anomaly_count == 0
    assert features.ldrmodules_inconsistencies == 0
    assert features.yara_shellcode_matches == 0
    # Raw memory bytes are not present in ordinary Volatility text output; entropy must be None
    assert features.mean_memory_entropy is None
    assert features.max_memory_entropy is None


def test_hidden_process_semantics_exited_vs_active(tmp_path: Path) -> None:
    """Verify psscan/psxview discrepancies distinguish terminated vs truly hidden processes."""
    # pslist has PID 4, 520
    (tmp_path / "pslist.json").write_text(
        json.dumps(
            [
                {"pid": 4, "ppid": 0, "imagefilename": "System"},
                {"pid": 520, "ppid": 440, "imagefilename": "services.exe"},
            ]
        ),
        encoding="utf-8",
    )

    # psscan has PID 4, 520, plus:
    # - PID 1820: terminated process with ExitTime (NOT hidden)
    # - PID 9999: active unlinked process with N/A ExitTime (HIDDEN)
    (tmp_path / "psscan.json").write_text(
        json.dumps(
            [
                {"pid": 4, "ppid": 0, "imagefilename": "System", "exittime": "N/A"},
                {"pid": 520, "ppid": 440, "imagefilename": "services.exe", "exittime": "N/A"},
                {
                    "pid": 1820,
                    "ppid": 520,
                    "imagefilename": "installer.exe",
                    "exittime": "2026-09-13 10:00:00 UTC",
                },
                {
                    "pid": 9999,
                    "ppid": 520,
                    "imagefilename": "hidden_rootkit.exe",
                    "exittime": "N/A",
                },
            ]
        ),
        encoding="utf-8",
    )

    features = extract_process_features(tmp_path, sample_id="TEST_HIDDEN")
    # Only PID 9999 should be counted as hidden; terminated PID 1820 should NOT be counted
    assert features.hidden_process_count == 1


def test_anomalous_ppid_rules_semantics(tmp_path: Path) -> None:
    """Verify legitimate process parentage rules vs malicious PPID spoofing/violation."""
    (tmp_path / "pslist.json").write_text(
        json.dumps(
            [
                {"pid": 4, "ppid": 0, "imagefilename": "System"},
                {"pid": 520, "ppid": 440, "imagefilename": "services.exe"},
                {"pid": 1000, "ppid": 520, "imagefilename": "svchost.exe"},  # Legitimate parent
                {
                    "pid": 2000,
                    "ppid": 9999,
                    "imagefilename": "svchost.exe",
                },  # Anomalous: svchost spawned by unknown/non-services
                {
                    "pid": 3000,
                    "ppid": 8888,
                    "imagefilename": "notepad.exe",
                },  # Legitimate: user app with exited parent
            ]
        ),
        encoding="utf-8",
    )

    features = extract_process_features(tmp_path, sample_id="TEST_PPID")
    # Only PID 2000 svchost violates strict core system daemon parentage
    assert features.anomalous_ppid_count == 1


def test_suspicious_dll_path_semantics(tmp_path: Path) -> None:
    """Verify that only genuinely suspicious user-writable DLL paths are flagged."""
    (tmp_path / "pslist.json").write_text(
        json.dumps([{"pid": 100, "ppid": 4, "imagefilename": "test.exe"}]),
        encoding="utf-8",
    )
    (tmp_path / "dlllist.json").write_text(
        json.dumps(
            [
                # Legitimate system paths:
                {"pid": 100, "path": "C:\\Windows\\System32\\ntdll.dll"},
                {"pid": 100, "path": "C:\\Program Files\\App\\lib.dll"},
                # Memory base address fallback:
                {"pid": 100, "base": "0x7ffb120000", "path": ""},
                # Suspicious staging paths:
                {"pid": 100, "path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\drop.dll"},
                {"pid": 100, "path": "C:\\Users\\Public\\malware.dll"},
            ]
        ),
        encoding="utf-8",
    )

    features = extract_process_features(tmp_path, sample_id="TEST_DLLS")
    # Exactly 2 DLLs in Temp and Public
    assert features.suspicious_dll_count == 2


def test_elevated_privileges_active_vs_disabled(tmp_path: Path) -> None:
    """Verify privileges token semantics (Disabled does not count as elevated)."""
    (tmp_path / "pslist.json").write_text(
        json.dumps([{"pid": 100, "ppid": 4, "imagefilename": "test.exe"}]),
        encoding="utf-8",
    )
    (tmp_path / "privileges.json").write_text(
        json.dumps(
            [
                {"pid": 100, "privilege": "SeDebugPrivilege", "attributes": "Disabled"},
                {
                    "pid": 100,
                    "privilege": "SeImpersonatePrivilege",
                    "attributes": "Disabled by default",
                },
                {"pid": 200, "privilege": "SeDebugPrivilege", "attributes": "Enabled"},
                {"pid": 200, "privilege": "SeTcbPrivilege", "attributes": "Enabled"},
            ]
        ),
        encoding="utf-8",
    )

    features = extract_process_features(tmp_path, sample_id="TEST_PRIVS")
    # PID 100 is Disabled (0). PID 200 has Enabled high-risk privileges (1 process).
    assert features.elevated_privilege_count == 1


def test_elevated_privileges_duplicate_pids_and_allowlist(tmp_path: Path) -> None:
    """Verify that duplicate rows for one PID count as 1, and excluded privileges are ignored."""
    (tmp_path / "pslist.json").write_text(
        json.dumps([{"pid": 500, "ppid": 4, "imagefilename": "proc.exe"}]),
        encoding="utf-8",
    )
    (tmp_path / "privileges.json").write_text(
        json.dumps(
            [
                # PID 500 has 3 separate rows with Enabled high-risk privileges (should count as ONE PID)
                {"pid": 500, "privilege": "SeDebugPrivilege", "attributes": "Enabled"},
                {"pid": 500, "privilege": "SeTcbPrivilege", "attributes": "Enabled"},
                {"pid": 500, "privilege": "SeDebugPrivilege", "attributes": "Enabled"},
                # Excluded privileges: SeImpersonatePrivilege and SeChangeNotifyPrivilege should NOT be counted
                {"pid": 600, "privilege": "SeImpersonatePrivilege", "attributes": "Enabled"},
                {"pid": 600, "privilege": "SeChangeNotifyPrivilege", "attributes": "Enabled"},
                # PID 700 has disabled high-risk privilege (should NOT be counted)
                {"pid": 700, "privilege": "SeLoadDriverPrivilege", "attributes": "Disabled"},
                # PID 800 has an enabled high-risk privilege (should count as a SECOND distinct PID)
                {"pid": 800, "privilege": "SeLoadDriverPrivilege", "attributes": "Enabled"},
            ]
        ),
        encoding="utf-8",
    )

    features = extract_process_features(tmp_path, sample_id="TEST_DEDUP_PRIVS")
    # Distinct PIDs holding enabled high-risk privileges: exactly PID 500 and PID 800 (count == 2)
    assert features.elevated_privilege_count == 2


def test_ldrmodules_large_count_and_header_immunity(tmp_path: Path) -> None:
    """Verify that ldrmodules accurately counts large unlinked modules and ignores header rows."""
    (tmp_path / "pslist.json").write_text(
        json.dumps([{"pid": 100, "ppid": 4, "imagefilename": "test.exe"}]),
        encoding="utf-8",
    )
    # Construct 15 genuine unlinked module records + 5 normal dynamic modules + 2 header/banner lines
    records: list[dict[str, Any]] = [
        # Header/metadata lines that must NOT be counted as unlinked modules:
        {"pid": "Pid", "process": "Process", "base": "Base", "inload": "InLoad", "inmem": "InMem"},
        {"pid": "", "process": "", "base": "", "inload": "", "inmem": ""},
    ]
    # 15 distinct unlinked module records
    for i in range(15):
        records.append(
            {
                "pid": 100 + i,
                "process": f"proc_{i}.exe",
                "base": f"0x{1000000 + i*0x1000:x}",
                "name": f"unlinked_{i}.dll",
                "inload": False,
                "ininit": False,
                "inmem": True,
            }
        )
    # 5 normal dynamically loaded modules (InInit=False, InLoad=True, InMem=True)
    for i in range(5):
        records.append(
            {
                "pid": 200 + i,
                "process": f"norm_{i}.exe",
                "base": f"0x{2000000 + i*0x1000:x}",
                "name": f"normal_{i}.dll",
                "inload": True,
                "ininit": False,
                "inmem": True,
            }
        )

    (tmp_path / "ldrmodules.json").write_text(json.dumps(records), encoding="utf-8")

    proc_feats = extract_process_features(tmp_path, sample_id="TEST_LARGE_LDR")
    mem_feats = extract_memory_features(tmp_path, sample_id="TEST_LARGE_LDR")

    # Exactly 15 unlinked modules are counted without arbitrary reduction or inflation
    assert proc_feats.unlinked_dll_count == 15
    assert mem_feats.ldrmodules_inconsistencies == 15


def test_ldrmodules_inconsistency_semantics(tmp_path: Path) -> None:
    """Verify unlinked DLLs in ldrmodules ignore InInit=False for dynamic modules."""
    (tmp_path / "pslist.json").write_text(
        json.dumps([{"pid": 100, "ppid": 4, "imagefilename": "test.exe"}]),
        encoding="utf-8",
    )
    (tmp_path / "ldrmodules.json").write_text(
        json.dumps(
            [
                # Dynamically loaded module: InInit=False is NORMAL
                {"pid": 100, "name": "dynamic.dll", "inload": True, "ininit": False, "inmem": True},
                # Unlinked reflective DLL: InLoad=False is ANOMALOUS
                {
                    "pid": 100,
                    "name": "injected.dll",
                    "inload": False,
                    "ininit": False,
                    "inmem": True,
                },
            ]
        ),
        encoding="utf-8",
    )

    proc_feats = extract_process_features(tmp_path, sample_id="TEST_LDR")
    mem_feats = extract_memory_features(tmp_path, sample_id="TEST_LDR")

    assert proc_feats.unlinked_dll_count == 1
    assert mem_feats.ldrmodules_inconsistencies == 1


def test_vadinfo_and_rwx_protection_semantics(tmp_path: Path) -> None:
    """Verify vadinfo RWX, unmapped executable, and protection delta detection."""
    (tmp_path / "vadinfo.json").write_text(
        json.dumps(
            [
                # Mapped standard executable (clean)
                {
                    "pid": 500,
                    "protection": "PAGE_EXECUTE_READ",
                    "initprotection": "PAGE_EXECUTE_READ",
                    "file": "C:\\Windows\\System32\\ntdll.dll",
                    "privatememory": 0,
                    "tag": "VadImageMap",
                },
                # Mapped RWX (rwx_page_count += 1)
                {
                    "pid": 500,
                    "protection": "PAGE_EXECUTE_READWRITE",
                    "initprotection": "PAGE_EXECUTE_READWRITE",
                    "file": "C:\\mapped\\file.bin",
                    "privatememory": 0,
                    "tag": "VadImageMap",
                },
                # Unmapped private executable (unmapped_executable_pages += 1)
                {
                    "pid": 500,
                    "protection": "PAGE_EXECUTE_READ",
                    "initprotection": "PAGE_EXECUTE_READ",
                    "file": "N/A",
                    "privatememory": 1,
                    "tag": "VadS",
                },
                # Protection changed via VirtualProtect (vad_protection_anomaly_count += 1)
                {
                    "pid": 500,
                    "protection": "PAGE_EXECUTE_READWRITE",
                    "initprotection": "PAGE_READWRITE",
                    "file": "N/A",
                    "privatememory": 1,
                    "tag": "Vad",
                },
            ]
        ),
        encoding="utf-8",
    )

    mem_feats = extract_memory_features(tmp_path, sample_id="TEST_VAD")
    assert mem_feats.rwx_page_count == 2
    assert mem_feats.unmapped_executable_pages == 2
    assert mem_feats.vad_protection_anomaly_count == 1


def test_memory_entropy_unsupported_vs_raw_bytes(tmp_path: Path) -> None:
    """Verify that entropy is None when raw bytes are absent, and calculated when present."""
    (tmp_path / "vadinfo.json").write_text(json.dumps([]), encoding="utf-8")

    # Without raw bytes: None (missing value policy: impute_median)
    no_bytes_feat = extract_memory_features(tmp_path, sample_id="NO_BYTES")
    assert no_bytes_feat.mean_memory_entropy is None
    assert no_bytes_feat.max_memory_entropy is None

    # With actual raw bytes: calculated
    raw_payload = b"\x90" * 50 + bytes(range(100))
    with_bytes_feat = extract_memory_features(
        tmp_path, sample_id="WITH_BYTES", raw_memory_bytes=raw_payload
    )
    assert with_bytes_feat.mean_memory_entropy is not None
    assert with_bytes_feat.mean_memory_entropy > 0.0


def test_run_track_a_pipeline_integration(run_001_fixtures_dir: Path, tmp_path: Path) -> None:
    """Test running the full Track A pipeline writing to interim storage."""
    sample_id = "EXEC_RUN-001"
    result = run_track_a_extraction(
        input_dir=run_001_fixtures_dir,
        sample_id=sample_id,
        output_base_dir=tmp_path,
    )

    assert result.sample_id == sample_id
    assert result.process_output_path.is_file()
    assert result.memory_output_path.is_file()

    # Verify JSON content matches schema
    proc_data = json.loads(result.process_output_path.read_text(encoding="utf-8"))
    proc_obj = ProcessFeatures.model_validate(proc_data)
    assert proc_obj.sample_id == sample_id
    assert proc_obj.hidden_process_count == 0

    mem_data = json.loads(result.memory_output_path.read_text(encoding="utf-8"))
    mem_obj = MemoryFeatures.model_validate(mem_data)
    assert mem_obj.sample_id == sample_id
    assert mem_obj.mean_memory_entropy is None


def test_tabular_text_parser_fallback(tmp_path: Path) -> None:
    """Verify parser fallback on standard Volatility 3 tabular CLI text format."""
    cli_output = """
Volatility 3 Framework 2.28.0
PID\tPPID\tImageFileName\tThreads\tHandles
4\t0\tSystem\t120\t350
280\t4\tsmss.exe\t4\t45
4820\t1840\tpowershell.exe\t15\t280
"""
    txt_file = tmp_path / "pslist.txt"
    txt_file.write_text(cli_output.strip(), encoding="utf-8")

    parsed = parse_volatility_file(txt_file)
    assert len(parsed) == 3
    assert parsed[0]["pid"] == "4"
    assert parsed[0]["imagefilename"] == "System"
    assert parsed[2]["imagefilename"] == "powershell.exe"


def test_malfind_multiline_does_not_inflate_injected_code_regions(tmp_path: Path) -> None:
    """Verify that multiline malfind output (hexdump/disassembly) does NOT inflate findings.

    Regression test for real RUN-001 evidence structure:
    Volatility 3 malfind emits a header line per finding followed by dozens of lines of
    hexdump and disassembly instructions. The extractor must count each genuine VAD finding
    exactly once (22 genuine findings in the 904-line fixture), rather than counting every
    parsed row (~906). Legitimate multiple VAD regions in the same process must be preserved.
    """
    fixture_path = (
        Path(__file__).resolve().parent
        / "fixtures"
        / "volatility"
        / "regression_malfind_multiline.txt"
    )
    assert fixture_path.is_file(), f"Fixture not found at {fixture_path}"

    lines = fixture_path.read_text(encoding="utf-8").splitlines()
    # Ensure fixture has realistic Volatility multiline output (>800 lines)
    assert len(lines) >= 800

    # 1. Directly parse malfind output
    findings = parse_malfind_output(fixture_path)

    # Exactly 22 genuine findings must be extracted, matching awk verification:
    # awk '$1 ~ /^[0-9]+$/ && $0 ~ /PAGE_EXECUTE/ {n++} END {print n}' -> 22
    assert len(findings) == 22

    # Multiple distinct VAD regions in the same process must be preserved
    pids = {f["pid"] for f in findings}
    assert len(pids) == 12
    # PID 1020 has 3 distinct VAD regions; all 3 must be preserved
    pid_1020_findings = [f for f in findings if f["pid"] == 1020]
    assert len(pid_1020_findings) == 3
    assert len({f["start_vpn"] for f in pid_1020_findings}) == 3

    # PID 520 has 2 distinct VAD regions
    pid_520_findings = [f for f in findings if f["pid"] == 520]
    assert len(pid_520_findings) == 2
    assert len({f["start_vpn"] for f in pid_520_findings}) == 2

    # 2. Integration test via extract_memory_features and extract_process_features
    # Set up test directory with malfind.txt and minimal companion files
    (tmp_path / "malfind.txt").write_text(
        fixture_path.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "vadinfo.json").write_text("[]", encoding="utf-8")
    (tmp_path / "pslist.json").write_text("[]", encoding="utf-8")

    mem_feats = extract_memory_features(tmp_path, sample_id="TEST_REGRESSION_MALFIND")
    proc_feats = extract_process_features(tmp_path, sample_id="TEST_REGRESSION_MALFIND")

    # Injected code regions must be exactly 22 (NOT 904 or 906)
    assert mem_feats.injected_code_regions == 22
    # Distinct processes flagged by malfind must be exactly 12
    assert proc_feats.malfind_process_count == 12


def test_ldrmodules_multiline_wrapped_paths_audit(tmp_path: Path) -> None:
    """Verify that ldrmodules wrapped paths, headers, and duplicates do not distort counts.

    In Volatility 3 CLI output, MappedPath values can be long and wrap across multiple lines.
    Continuation lines without valid PID and 0x Base must be filtered out cleanly, and duplicate
    records for the same (PID, Base) must not inflate the inconsistency count.
    """
    ldrmodules_raw = """
Volatility 3 Framework 2.28.0
PID\tProcess\tBase\tInLoad\tInInit\tInMem\tMappedPath
4\tSystem\t0x7ff80000\tTrue\tTrue\tTrue\t\\SystemRoot\\System32\\ntoskrnl.exe
100\tproc1.exe\t0x7ff90000\tTrue\tFalse\tTrue\tC:\\Windows\\System32\\
\tdrivers\\very_long_wrapped_driver_name_that_spans_multiple_lines.sys
100\tproc1.exe\t0x7ff90000\tTrue\tFalse\tTrue\tC:\\Windows\\System32\\drivers\\duplicate_entry.sys
200\tproc2.exe\t0x7ffa0000\tFalse\tFalse\tTrue\tC:\\Windows\\System32\\injected1.dll
300\tproc3.exe\t0x7ffb0000\tFalse\tFalse\tFalse\tC:\\Users\\Public\\injected2.dll
400\tproc4.exe\t0x7ffc0000\tTrue\tTrue\tTrue\tC:\\Program Files\\App\\valid.dll
*** Volatility Warning: partial memory range ***
"""
    (tmp_path / "ldrmodules.txt").write_text(ldrmodules_raw.strip(), encoding="utf-8")
    (tmp_path / "pslist.json").write_text("[]", encoding="utf-8")
    (tmp_path / "vadinfo.json").write_text("[]", encoding="utf-8")

    records = parse_ldrmodules_output(tmp_path / "ldrmodules.txt")
    # Total distinct valid module records:
    # PID 4 (0x7ff80000), PID 100 (0x7ff90000), PID 200 (0x7ffa0000), PID 300 (0x7ffb0000), PID 400 (0x7ffc0000)
    # Total = 5 valid modules (wrapped line and duplicate 0x7ff90000 must NOT add extra modules)
    assert len(records) == 5

    mem_feats = extract_memory_features(tmp_path, sample_id="TEST_LDR_WRAPPED")
    proc_feats = extract_process_features(tmp_path, sample_id="TEST_LDR_WRAPPED")

    # Inconsistencies: exactly PID 200 (InLoad=False) and PID 300 (InLoad=False, InMem=False) = 2
    assert mem_feats.ldrmodules_inconsistencies == 2
    assert proc_feats.unlinked_dll_count == 2
