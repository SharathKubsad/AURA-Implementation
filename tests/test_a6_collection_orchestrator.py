"""Automated Tests for Milestone A6: Custom Collection Orchestrator.

Tests:
- RUN ID allocation across categories
- Category validation & range boundaries
- Collision prevention & no accidental overwrite
- RUN-001 reservation
- State machine transitions & failure handling
- Canonical metadata generation
- SHA-256 evidence calculation & integrity verification
- Processing orchestration reusing existing A4 extraction pipeline
"""

import json
import shutil
from pathlib import Path

import pytest

from tools.collection_orchestrator import (
    CollectionState,
    CollectionStateMachine,
    allocate_next_run_id,
    build_run_metadata,
    calculate_directory_evidence_sha256,
    finalize_run_evidence,
    get_category_info,
    init_run_directory,
    load_categories_catalog,
    process_run_pipeline,
    scan_existing_run_ids,
    verify_run_evidence,
)
from tools.process_run_kali import resolve_run_directory


@pytest.fixture
def temp_run_workspace(tmp_path: Path) -> Path:
    """Fixture providing an isolated temporary workspace for run generation."""
    workspace = tmp_path / "custom_workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    return workspace


@pytest.fixture
def mock_evidence_run(tmp_path: Path) -> Path:
    """Fixture providing a mock completed RUN directory with required A4 evidence files."""
    run_dir = tmp_path / "RUN-099"
    run_dir.mkdir(parents=True, exist_ok=True)

    # Copy standard mock text outputs from existing RUN-001 test fixtures
    fixture_src = Path("tests/fixtures/run_001_synthetic")
    if not fixture_src.exists():
        fixture_src = Path("tests/fixtures/run_001_real")

    vol_files = [
        "pslist.txt",
        "psscan.txt",
        "pstree.txt",
        "threads.txt",
        "handles.txt",
        "dlllist.txt",
        "psxview.txt",
        "malfind.txt",
        "privileges.txt",
        "vadinfo.txt",
        "ldrmodules.txt",
    ]

    for vf in vol_files:
        src_file = fixture_src / vf
        if src_file.is_file():
            shutil.copy2(src_file, run_dir / vf)
        else:
            # Fallback dummy line
            (run_dir / vf).write_text("PID\tPPID\tImageFileName\n4\t0\tSystem\n", encoding="utf-8")

    # Add mock Track B evidence files
    (run_dir / "sysmon.evtx").write_bytes(b"MOCK_EVTX_CONTENT")
    (run_dir / "powershell.evtx").write_bytes(b"MOCK_PS_EVTX_CONTENT")
    (run_dir / "process_snapshot.csv").write_text("Id,ProcessName\n4,System\n", encoding="utf-8")
    (run_dir / "network_connections.csv").write_text(
        "LocalAddress,State\n0.0.0.0,Listen\n", encoding="utf-8"
    )

    # Finalize with valid metadata
    meta = build_run_metadata(
        run_id="RUN-099",
        category_name="powershell_fileless",
        evidence_sha256="0" * 64,
        notes="Automated mock test run",
    )
    (run_dir / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    # Update with real computed hash
    finalize_run_evidence(run_dir, ledger_path=run_dir / "allocated_runs.json")
    return run_dir


# ------------------------------------------------------------------------------
# 1. Category Validation Tests
# ------------------------------------------------------------------------------
def test_category_catalog_integrity():
    """Verify categories catalog contains all 12 categories with valid ranges."""
    catalog = load_categories_catalog()
    assert catalog["total_categories"] == 12
    categories = catalog["categories"]
    assert len(categories) == 12

    seen_ranges: list[tuple[int, int]] = []
    for cat in categories:
        assert "name" in cat
        assert "track" in cat
        assert "binary_label" in cat
        assert "run_range" in cat
        r_start, r_end = cat["run_range"]
        assert r_start > 1, "RUN-001 must be reserved and outside category ranges"
        assert r_start <= r_end

        # Check for range overlaps
        for prev_start, prev_end in seen_ranges:
            assert not (
                r_start <= prev_end and r_end >= prev_start
            ), f"Range collision detected between {cat['name']} [{r_start}, {r_end}] and existing [{prev_start}, {prev_end}]"
        seen_ranges.append((r_start, r_end))


def test_get_category_info_valid_and_invalid():
    """Test retrieving known category and rejecting unknown names."""
    info = get_category_info("powershell_fileless")
    assert info["track"] == "TRACK_A"
    assert info["binary_label"] == 1
    assert info["run_range"] == [2, 99]

    with pytest.raises(ValueError, match="Unknown category"):
        get_category_info("non_existent_category_xyz")


# ------------------------------------------------------------------------------
# 2. RUN ID Allocation & Overwrite Prevention
# ------------------------------------------------------------------------------
def test_run_id_allocation_and_reservation(temp_run_workspace: Path):
    """Test allocation selects next unused ID and never returns RUN-001."""
    cat_dir = temp_run_workspace / "powershell_fileless"
    cat_dir.mkdir(parents=True)
    isolated_ledger = temp_run_workspace / "allocated_runs.json"

    # Allocate first available
    num1, id1 = allocate_next_run_id(
        "powershell_fileless",
        search_dirs=[temp_run_workspace],
        ledger_path=isolated_ledger,
    )
    assert num1 == 2
    assert id1 == "RUN-002"

    # Simulate creating RUN-002
    (cat_dir / "RUN-002").mkdir()

    # Next allocation should advance to RUN-003
    num2, id2 = allocate_next_run_id(
        "powershell_fileless",
        search_dirs=[temp_run_workspace],
        ledger_path=isolated_ledger,
    )
    assert num2 == 3
    assert id2 == "RUN-003"


def test_scan_existing_run_ids(temp_run_workspace: Path):
    """Test scanning discovers run folders across directory hierarchies."""
    (temp_run_workspace / "RUN-005").mkdir()
    sub_cat = temp_run_workspace / "category_a"
    sub_cat.mkdir()
    (sub_cat / "RUN-042").mkdir()

    ids = scan_existing_run_ids([temp_run_workspace])
    assert 5 in ids
    assert 42 in ids


def test_init_run_directory_prevents_overwrite(temp_run_workspace: Path):
    """Test init_run_directory creates directory and blocks existing directory collision."""
    run_id, path = init_run_directory(
        "powershell_fileless", base_dir=temp_run_workspace, run_id="RUN-088"
    )
    assert path.is_dir()
    assert (path / "metadata.json").is_file()

    # Attempting to initialize the same run directory must raise FileExistsError
    with pytest.raises(FileExistsError):
        init_run_directory("powershell_fileless", base_dir=temp_run_workspace, run_id="RUN-088")


# ------------------------------------------------------------------------------
# 3. State Machine Transitions
# ------------------------------------------------------------------------------
def test_state_machine_valid_lifecycle():
    """Verify normal state machine flow: READY -> COLLECTING -> CAPTURE -> FINALIZING -> COMPLETE."""
    sm = CollectionStateMachine("RUN-999", "powershell_fileless")
    assert sm.state == CollectionState.READY

    sm.transition_to(CollectionState.COLLECTING, "Started activity")
    assert sm.state == CollectionState.COLLECTING

    sm.transition_to(CollectionState.CAPTURE, "Initiated capture")
    assert sm.state == CollectionState.CAPTURE

    sm.transition_to(CollectionState.FINALIZING, "Hashing evidence")
    assert sm.state == CollectionState.FINALIZING

    sm.transition_to(CollectionState.COMPLETE, "All steps verified")
    assert sm.state == CollectionState.COMPLETE


def test_state_machine_invalid_transition_rejected():
    """Verify illegal transitions are prevented by state machine."""
    sm = CollectionStateMachine("RUN-999", "powershell_fileless")
    with pytest.raises(ValueError, match="Invalid state transition"):
        sm.transition_to(CollectionState.COMPLETE, "Illegal jump")

    with pytest.raises(ValueError, match="Invalid state transition"):
        sm.transition_to(CollectionState.CAPTURE, "Illegal jump")


def test_state_machine_failure_transition():
    """Verify failure state transition from any active state."""
    sm = CollectionStateMachine("RUN-999", "powershell_fileless")
    sm.transition_to(CollectionState.COLLECTING, "Active")
    sm.fail("Memory capture timed out")
    assert sm.state == CollectionState.FAILED


# ------------------------------------------------------------------------------
# 4. Evidence Verification & SHA-256 Integrity
# ------------------------------------------------------------------------------
def test_sha256_calculation_and_tamper_detection(mock_evidence_run: Path):
    """Verify evidence hashing and detection of modified files."""
    hash1 = calculate_directory_evidence_sha256(mock_evidence_run)
    assert len(hash1) == 64

    # Verification passes on untampered directory
    valid, errors = verify_run_evidence(mock_evidence_run)
    assert valid is True
    assert len(errors) == 0

    # Tamper with an evidence file
    (mock_evidence_run / "pslist.txt").write_text("TAMPERED_CONTENT_ROW", encoding="utf-8")
    valid_after_tamper, errors_after = verify_run_evidence(mock_evidence_run)
    assert valid_after_tamper is False
    assert any("SHA-256 mismatch" in e for e in errors_after)


def test_incomplete_run_missing_metadata(tmp_path: Path):
    """Verify incomplete run without metadata is rejected."""
    empty_run = tmp_path / "RUN-EMPTY"
    empty_run.mkdir()
    valid, errors = verify_run_evidence(empty_run)
    assert valid is False
    assert any("Missing metadata.json" in e for e in errors)


# ------------------------------------------------------------------------------
# 5. Processing Orchestration & Pipeline Reuse
# ------------------------------------------------------------------------------
def test_process_run_pipeline_execution(mock_evidence_run: Path, tmp_path: Path):
    """Verify processing pipeline executes A4 extraction and produces valid reports."""
    interim_out = tmp_path / "interim_output"
    interim_out.mkdir()

    report = process_run_pipeline(
        mock_evidence_run,
        output_base_dir=interim_out,
        ledger_path=mock_evidence_run / "allocated_runs.json",
    )
    assert report["status"] == "PASS"
    assert report["sample_id"] == "EXEC_RUN-099"
    assert report["process_status"] == "PASS"
    assert report["memory_status"] == "PASS"

    # Check generated feature files
    proc_file = Path(report["process_features"])
    mem_file = Path(report["memory_features"])
    assert proc_file.is_file()
    assert mem_file.is_file()

    # Check validation report saved in run directory
    val_report_file = mock_evidence_run / "validation_report.json"
    assert val_report_file.is_file()


def test_resolve_run_directory(mock_evidence_run: Path):
    """Verify run directory resolution works with absolute and relative pathing."""
    resolved = resolve_run_directory(mock_evidence_run)
    assert resolved == mock_evidence_run.resolve()

    resolved_by_name = resolve_run_directory(
        mock_evidence_run.name, search_dirs=[mock_evidence_run.parent]
    )
    assert resolved_by_name.is_dir()


# ------------------------------------------------------------------------------
# 6. Hardened Ledger, Canonical Hashing & Automation Regression Tests
# ------------------------------------------------------------------------------
def test_canonical_directory_evidence_hashing_determinism(tmp_path: Path):
    """Verify canonical hashing is deterministic, sorts by normalized POSIX path, and detects 1-byte edits."""
    test_dir = tmp_path / "canonical_test_run"
    test_dir.mkdir()

    (test_dir / "b_file.txt").write_bytes(b"File B content")
    (test_dir / "a_file.txt").write_bytes(b"File A content")
    sub_dir = test_dir / "nested" / "sub"
    sub_dir.mkdir(parents=True)
    (sub_dir / "c_file.bin").write_bytes(b"\x00\x01\x02\x03\xff")
    (test_dir / "metadata.json").write_text('{"sample_id": "EXEC_RUN-999"}', encoding="utf-8")

    hash1 = calculate_directory_evidence_sha256(test_dir)
    assert len(hash1) == 64
    assert hash1.islower()

    # Re-evaluating gives identical hash
    hash2 = calculate_directory_evidence_sha256(test_dir)
    assert hash1 == hash2

    # Modifying a single byte in a nested file MUST alter the hash
    (sub_dir / "c_file.bin").write_bytes(b"\x00\x01\x02\x03\xfe")
    hash_tampered = calculate_directory_evidence_sha256(test_dir)
    assert hash_tampered != hash1

    # Modifying metadata.json must NOT alter evidence hash (metadata is excluded)
    (test_dir / "metadata.json").write_text('{"sample_id": "MODIFIED"}', encoding="utf-8")
    hash_after_meta = calculate_directory_evidence_sha256(test_dir)
    assert hash_after_meta == hash_tampered


def test_ledger_creation_and_reconstruction(tmp_path: Path):
    """Verify ledger creates RUN-001 baseline reservation and reconstructs from existing runs."""
    ledger_file = tmp_path / "allocated_runs.json"
    search_dir = tmp_path / "custom_data"
    search_dir.mkdir()

    # Create dummy existing directories
    (search_dir / "RUN-001").mkdir()
    (search_dir / "RUN-005").mkdir()

    from tools.collection_orchestrator import load_or_reconstruct_ledger

    ledger = load_or_reconstruct_ledger(ledger_path=ledger_file, search_dirs=[search_dir])
    assert ledger["version"] == "1.0.0"
    assert "RUN-001" in ledger["runs"]
    assert ledger["runs"]["RUN-001"]["status"] == "RESERVED_BASELINE"
    assert "RUN-005" in ledger["runs"]
    assert ledger["runs"]["RUN-005"]["status"] == "ALLOCATED"


def test_ledger_prevents_reallocation_after_transfer(tmp_path: Path):
    """Verify ledger prevents reusing RUN ID even if the local directory has been moved away."""
    ledger_file = tmp_path / "allocated_runs.json"
    empty_search_dir = tmp_path / "empty_staging"
    empty_search_dir.mkdir()

    # Pre-seed ledger with RUN-002, RUN-003
    from tools.collection_orchestrator import record_run_in_ledger

    record_run_in_ledger(
        run_id="RUN-002",
        category="powershell_fileless",
        status="TRANSFERRED",
        ledger_path=ledger_file,
    )
    record_run_in_ledger(
        run_id="RUN-003",
        category="powershell_fileless",
        status="TRANSFERRED",
        ledger_path=ledger_file,
    )

    # Next allocation for powershell_fileless must skip 001 (reserved), 002, and 003
    num, r_id = allocate_next_run_id(
        "powershell_fileless",
        search_dirs=[empty_search_dir],
        ledger_path=ledger_file,
    )
    assert num == 4
    assert r_id == "RUN-004"


def test_powershell_collector_source_integrity():
    """Verify collect_run_windows.ps1 contains Admin checks, canonical hashing, and transfer support."""
    ps1_path = Path("tools/collect_run_windows.ps1")
    assert ps1_path.is_file()
    content = ps1_path.read_text(encoding="utf-8")

    # Verify Admin check presence
    assert "WindowsBuiltInRole]::Administrator" in content
    assert "Administrator privileges are required" in content
    assert "Verb RunAs" in content

    # Verify canonical hashing implementation delegates to Python orchestrator
    assert "Get-CanonicalDirectoryEvidenceSha256" in content
    assert "hash-evidence" in content
    assert "collection_orchestrator.py" in content

    # Verify memory status distinctions
    assert "MEMORY CAPTURE SUCCESS" in content
    assert "MEMORY CAPTURE FAILED" in content
    assert "MEMORY CAPTURE SKIPPED" in content

    # Verify transfer switch and ledger support
    assert "[switch]$Transfer" in content
    assert "allocated_runs.json" in content

    # Verify PowerShell AST has zero syntax/parser errors on Windows
    import subprocess
    import sys

    if sys.platform == "win32":
        parse_cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "& { param($p) $e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$null, [ref]$e); exit $e.Count }",
            str(ps1_path),
        ]
        res = subprocess.run(parse_cmd, capture_output=True, text=True, timeout=10)
        assert (
            res.returncode == 0
        ), "PowerShell AST parser found syntax errors in collect_run_windows.ps1"


def test_windows_batch_launcher():
    """Verify collect_run_windows.bat prioritizes py -3 and supports safe launcher testing."""
    import subprocess
    import sys

    bat_path = Path("tools/collect_run_windows.bat")
    assert bat_path.is_file()
    content = bat_path.read_text(encoding="utf-8", errors="replace")

    # Verify py -3 priority over python
    assert "py -3 -c" in content
    assert "--test-launcher" in content
    assert "PYTHON_CMD" in content

    # On Windows, safely test the launcher without invoking any collection
    if sys.platform == "win32":
        res = subprocess.run(
            ["cmd.exe", "/c", str(bat_path), "--test-launcher"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert res.returncode == 0
        assert "[TEST] Launcher test successful" in res.stdout
        assert "PYTHON_CMD=py" in res.stdout or "PYTHON_CMD=" in res.stdout


def test_desktop_dumpit_discovery(tmp_path):
    """Verify DumpIt discovery recognizes desktop installation and recursive fallback safely."""
    import subprocess
    import sys

    ps1_path = Path("tools/collect_run_windows.ps1")
    assert ps1_path.is_file()
    content = ps1_path.read_text(encoding="utf-8")

    # Verify presence of exact required search locations in source
    assert "$env:USERPROFILE\\Desktop\\DumpIt\\x64\\DumpIt.exe" in content
    assert "$env:USERPROFILE\\Desktop\\DumpIt\\DumpIt.exe" in content
    assert "C:\\FMD-Collector\\tools\\DumpIt.exe" in content
    assert "C:\\Tools\\DumpIt\\DumpIt.exe" in content
    assert "C:\\FMD-Transfer\\DumpIt.exe" in content
    assert "$env:USERPROFILE\\Desktop\\DumpIt" in content
    assert 'Get-ChildItem -Path $DesktopDumpItDir -Filter "DumpIt.exe" -Recurse' in content
    assert '((Split-Path $_ -Leaf) -ieq "DumpIt.exe")' in content

    # On Windows, run a safe resolution test without executing DumpIt
    if sys.platform == "win32":
        # 1. Exact path recognition test
        dumpit_mock = tmp_path / "Desktop" / "DumpIt" / "x64" / "DumpIt.exe"
        dumpit_mock.parent.mkdir(parents=True, exist_ok=True)
        dumpit_mock.write_text("dummy")

        tmp_str = str(tmp_path).replace("\\", "/")
        ps_script = (
            f"$env:USERPROFILE = '{tmp_str}'\n"
            "$CandidateDumpIt = @(\n"
            "    @(\n"
            '        "$env:USERPROFILE\\Desktop\\DumpIt\\x64\\DumpIt.exe",\n'
            '        "$env:USERPROFILE\\Desktop\\DumpIt\\DumpIt.exe",\n'
            '        "C:\\FMD-Collector\\tools\\DumpIt.exe",\n'
            '        "C:\\Tools\\DumpIt\\DumpIt.exe",\n'
            '        "C:\\FMD-Transfer\\DumpIt.exe"\n'
            "    ) | Where-Object {\n"
            '        $_ -and (Test-Path -Path $_ -PathType Leaf) -and ((Split-Path $_ -Leaf) -ieq "DumpIt.exe")\n'
            "    }\n"
            ")\n"
            "if ($CandidateDumpIt -and $CandidateDumpIt.Count -gt 0) {\n"
            '    Write-Host ("RESOLVED:" + $CandidateDumpIt[0])\n'
            "} else {\n"
            '    Write-Host "NOT_RESOLVED"\n'
            "}\n"
        )
        res = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert res.returncode == 0
        assert "RESOLVED:" in res.stdout
        assert "x64" in res.stdout
        assert "DumpIt.exe" in res.stdout

        # 2. Recursive fallback test
        dumpit_mock.unlink()
        nested_mock = tmp_path / "Desktop" / "DumpIt" / "nested" / "tools" / "DumpIt.exe"
        nested_mock.parent.mkdir(parents=True, exist_ok=True)
        nested_mock.write_text("dummy")

        fallback_script = (
            f"$env:USERPROFILE = '{tmp_str}'\n"
            '$DesktopDumpItDir = "$env:USERPROFILE\\Desktop\\DumpIt"\n'
            "if ($DesktopDumpItDir -and (Test-Path -Path $DesktopDumpItDir -PathType Container)) {\n"
            '    $Found = Get-ChildItem -Path $DesktopDumpItDir -Filter "DumpIt.exe" -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ieq "DumpIt.exe" } | Select-Object -First 1\n'
            "    if ($Found) {\n"
            '        Write-Host ("RECURSIVE_RESOLVED:" + $Found.FullName)\n'
            "    }\n"
            "}\n"
        )
        res2 = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", fallback_script],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert res2.returncode == 0
        assert "RECURSIVE_RESOLVED:" in res2.stdout
        assert "nested" in res2.stdout


def test_windows_canonical_hashing_python_delegation(tmp_path):
    """Verify Windows finalization delegates hashing to Python with identical output, fails cleanly, and streams chunks."""
    import inspect
    import subprocess
    import sys

    # 1. Verify code implementation streams 64KB chunks and does not load full file into RAM
    code = inspect.getsource(calculate_directory_evidence_sha256)
    assert "while chunk := f.read(65536):" in code
    assert "read()" not in code.replace("read(65536)", "")
    assert "read_bytes()" not in code

    # 2. Build multi-file fixture with subdirectories
    fixture_dir = tmp_path / "hash_fixture_run"
    fixture_dir.mkdir()
    (fixture_dir / "process_snapshot.csv").write_text("pid,name\n4,System\n", encoding="utf-8")
    (fixture_dir / "network_connections.csv").write_text(
        "proto,local,remote\nTCP,127.0.0.1,80\n", encoding="utf-8"
    )
    nested = fixture_dir / "logs"
    nested.mkdir()
    (nested / "telemetry.bin").write_bytes(b"\xde\xad\xbe\xef" * 1024)
    # Excluded metadata files
    (fixture_dir / "metadata.json").write_text('{"sample_id": "EXEC_TEST"}', encoding="utf-8")

    expected_hash = calculate_directory_evidence_sha256(fixture_dir)
    assert len(expected_hash) == 64

    # 3. On Windows, verify PowerShell invocation of Get-CanonicalDirectoryEvidenceSha256 produces exact hash
    if sys.platform == "win32":
        ps1_path = Path("tools/collect_run_windows.ps1").resolve()
        lines = ps1_path.read_text(encoding="utf-8").splitlines()
        start_idx = next(
            i
            for i, line in enumerate(lines)
            if "function Get-CanonicalDirectoryEvidenceSha256" in line
        )
        end_idx = next(
            i
            for i, line in enumerate(lines[start_idx:], start_idx)
            if line == "}" and i > start_idx + 10
        )
        fn_text = "\n".join(lines[start_idx : end_idx + 1])

        ps_fixture_str = str(fixture_dir).replace("\\", "/")
        ps_script_dir = str(Path("tools").resolve()).replace("\\", "/")
        ps_repo_root = str(Path(".").resolve()).replace("\\", "/")

        ps_test_code = (
            f"$ScriptDir = '{ps_script_dir}'\n"
            f"$RepoRoot = '{ps_repo_root}'\n"
            f"$PythonCmd = 'py -3'\n"
            + fn_text
            + "\n"
            + f"$resHash = Get-CanonicalDirectoryEvidenceSha256 -TargetDirectory '{ps_fixture_str}' -PythonLauncher 'py -3'\n"
            + 'Write-Host ("PS_HASH:" + $resHash)\n'
        )
        res = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", ps_test_code],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert res.returncode == 0, f"PowerShell execution failed: {res.stderr}\n{res.stdout}"
        assert f"PS_HASH:{expected_hash}" in res.stdout

        # 4. Verify failed Python hash causes clean error (does NOT mark COMPLETE)
        ps_fail_code = (
            f"$ScriptDir = '{ps_script_dir}'\n"
            f"$RepoRoot = '{ps_repo_root}'\n"
            + fn_text
            + "\n"
            + "try {\n"
            + f"    $resHash = Get-CanonicalDirectoryEvidenceSha256 -TargetDirectory '{ps_fixture_str}' -PythonLauncher 'nonexistent_python_binary_xyz'\n"
            + '    Write-Host "UNEXPECTED_SUCCESS"\n'
            + "} catch {\n"
            + '    Write-Host ("EXPECTED_FAILURE:" + $_.Exception.Message)\n'
            + "}\n"
        )
        res_fail = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", ps_fail_code],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert res_fail.returncode == 0
        assert "UNEXPECTED_SUCCESS" not in res_fail.stdout
        assert "EXPECTED_FAILURE:" in res_fail.stdout
