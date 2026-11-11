"""Automated infrastructure and isolation audit tests for the analysis sandbox (Task A1)."""

import csv
from pathlib import Path


def test_sandbox_directories_exist() -> None:
    """Verify all required sandbox directory trees exist."""
    root = Path(__file__).resolve().parent.parent
    expected_dirs = [
        "sandbox/vm-configs",
        "sandbox/network",
        "sandbox/logging",
        "sandbox/snapshots",
        "sandbox/execution-logs",
    ]
    for rel_dir in expected_dirs:
        dir_path = root / rel_dir
        assert dir_path.is_dir(), f"Missing sandbox directory: {rel_dir}"


def test_sandbox_documentation_and_configs_exist() -> None:
    """Verify all required sandbox specifications and documentation exist."""
    root = Path(__file__).resolve().parent.parent
    expected_files = [
        "sandbox/README.md",
        "sandbox/vm-configs/attacker-kali.md",
        "sandbox/vm-configs/target-windows.md",
        "sandbox/vm-configs/target-linux.md",
        "sandbox/network/NETWORK_DESIGN.md",
        "sandbox/logging/LOGGING_PLAN.md",
        "sandbox/snapshots/SNAPSHOT_POLICY.md",
        "docs/THREAT_ANALYSIS_ENVIRONMENT.md",
        "sandbox/execution-logs/log.csv",
    ]
    for rel_file in expected_files:
        file_path = root / rel_file
        assert file_path.is_file(), f"Missing sandbox document/config: {rel_file}"
        assert file_path.stat().st_size > 0, f"File is empty: {rel_file}"


def test_network_isolation_safety_rules() -> None:
    """Audit network documents to verify unsafe modes (NAT/Bridged) are explicitly prohibited."""
    root = Path(__file__).resolve().parent.parent
    network_docs = [
        root / "sandbox" / "vm-configs" / "attacker-kali.md",
        root / "sandbox" / "vm-configs" / "target-windows.md",
        root / "sandbox" / "vm-configs" / "target-linux.md",
        root / "sandbox" / "network" / "NETWORK_DESIGN.md",
    ]

    for doc in network_docs:
        content = doc.read_text(encoding="utf-8").lower()
        # Must mandate Host-Only / Internal
        assert (
            "host-only" in content or "internal" in content
        ), f"{doc.name} does not specify Host-Only / Internal network mode"

        # Must prohibit Bridged and NAT modes
        assert "bridged" in content and (
            "forbidden" in content or "prohibited" in content
        ), f"{doc.name} does not explicitly prohibit Bridged mode"
        assert "nat" in content and (
            "forbidden" in content or "prohibited" in content
        ), f"{doc.name} does not explicitly prohibit NAT mode"


def test_evidence_storage_gitignore_exclusions() -> None:
    """Verify evidence storage patterns are strictly excluded by .gitignore."""
    root = Path(__file__).resolve().parent.parent
    gitignore_path = root / ".gitignore"
    assert gitignore_path.is_file(), ".gitignore must exist"

    content = gitignore_path.read_text(encoding="utf-8")
    mandatory_exclusions = [
        "*.raw",
        "*.mem",
        "*.vmem",
        "*.dmp",
        "*.lime",
        "*.pcap",
        "*.pcapng",
        "data/raw/",
    ]
    for pattern in mandatory_exclusions:
        assert (
            pattern in content
        ), f"Missing mandatory forensic artifact exclusion in .gitignore: {pattern}"


def test_execution_log_csv_header() -> None:
    """Verify that execution-logs/log.csv has the standardized forensic header."""
    root = Path(__file__).resolve().parent.parent
    log_csv = root / "sandbox" / "execution-logs" / "log.csv"
    assert log_csv.is_file()

    expected_columns = [
        "sample_id",
        "family",
        "vm",
        "os",
        "timestamp",
        "operator",
        "sample_sha256",
        "notes",
    ]
    with open(log_csv, encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        assert header == expected_columns, f"log.csv header mismatch. Found: {header}"
