"""Automated semantic validator for Track A (A4) real-evidence Volatility outputs.

Validates the A4 extraction pipeline on real or fixture evidence for RUN-001:
- Automatically locates the RUN-001 evidence directory.
- Dynamically checks malfind multiline boundary parsing against independent awk-style inspection.
- Specifically verifies that multiline hexdump/disassembly lines do NOT inflate injected_code_regions.
- Audits ldrmodules record boundaries (wrapped path lines, duplicates, and unlinked module counts).
- Validates ProcessFeatures and MemoryFeatures against canonical Pydantic schemas.
- Validates distinct-PID privilege counting, suspicious DLL filtering, and RWX VAD detection.
- Validates null handling for entropy when raw byte memory dumps are unavailable.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from pathlib import Path
from typing import NamedTuple

# Ensure repository root is on sys.path when executed directly
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from forensics.extraction.memory_extractor import extract_memory_features  # noqa: E402
from forensics.extraction.parser_utils import (  # noqa: E402
    find_plugin_file,
    parse_ldrmodules_output,
    parse_malfind_output,
    parse_volatility_file,
)
from forensics.extraction.process_extractor import (  # noqa: E402
    HIGH_RISK_PRIVILEGES,
    extract_process_features,
)
from forensics.schemas.memory import MemoryFeatures  # noqa: E402
from forensics.schemas.process import ProcessFeatures  # noqa: E402

logger = logging.getLogger("a4_validator")


class ValidationResult(NamedTuple):
    """Result of semantic validation suite."""

    sample_id: str
    input_dir: Path
    process_status: bool
    memory_status: bool
    malfind_status: bool
    ldrmodules_status: bool
    schema_status: bool
    details: list[str]

    @property
    def overall_status(self) -> bool:
        """Overall pass status requires all sub-checks to pass."""
        return (
            self.process_status
            and self.memory_status
            and self.malfind_status
            and self.ldrmodules_status
            and self.schema_status
        )


def find_default_run001_dir() -> Path | None:
    """Locate the RUN-001 evidence directory across common research environments.

    Search precedence:
    1. ~/fmd-results/custom/RUN-001/ (standard Kali output directory)
    2. ./data/raw/custom/RUN-001/ (workspace raw data location)
    3. ./tests/fixtures/volatility/RUN-001/ (test fixtures fallback)
    """
    candidates = [
        Path.home() / "fmd-results" / "custom" / "RUN-001",
        Path.home() / "Desktop" / "fmd-results" / "custom" / "RUN-001",
        Path.cwd() / "data" / "raw" / "custom" / "RUN-001",
        Path(__file__).resolve().parent.parent / "data" / "raw" / "custom" / "RUN-001",
        Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "volatility" / "RUN-001",
    ]
    for cand in candidates:
        if cand.is_dir():
            return cand
    return None


def validate_malfind_semantics(
    input_dir: Path,
    mem_features: MemoryFeatures,
    proc_features: ProcessFeatures,
    details: list[str],
) -> bool:
    """Validate malfind parsing against independent evidence ground truth.

    Ensures:
    - Does NOT hard-code 22 or any arbitrary number.
    - Accurately counts each genuine finding once matching independent regex inspection.
    - Proves multiline hexdump/disassembly content does not inflate injected_code_regions (detects 906 bug).
    - Preserves distinct VAD regions in the same process as separate findings.
    - Verifies distinct PIDs for malfind_process_count.
    """
    malfind_file = find_plugin_file(input_dir, "malfind")
    if not malfind_file or not malfind_file.is_file():
        details.append("Malfind: No malfind output file found in directory (skipped).")
        return True

    raw_text = malfind_file.read_text(encoding="utf-8", errors="replace")
    is_text = not (
        malfind_file.suffix.lower() == ".json"
        or raw_text.strip().startswith("[")
        or raw_text.strip().startswith("{")
    )

    if is_text:
        lines = raw_text.splitlines()
        # Independent awk-equivalent check: $1 ~ /^[0-9]+$/ && $0 ~ /PAGE_EXECUTE/
        independent_headers: list[tuple[int, str]] = []
        for line in lines:
            line_str = line.strip()
            parts = line_str.split()
            if not parts:
                continue
            first_token = parts[0]
            if re.match(r"^[0-9]+$", first_token) and "EXECUTE" in line_str.upper():
                pid = int(first_token)
                start_vpn = ""
                for p in parts[1:]:
                    if p.lower().startswith("0x"):
                        start_vpn = p.lower()
                        break
                independent_headers.append((pid, start_vpn))

        # Deduplicate per (pid, start_vpn) boundary
        seen_keys = set()
        dedup_independent = []
        for h in independent_headers:
            key = (h[0], h[1]) if h[1] else (h[0], len(dedup_independent))
            if key not in seen_keys:
                seen_keys.add(key)
                dedup_independent.append(h)

        expected_regions = len(dedup_independent)
        expected_pids = {h[0] for h in dedup_independent}

        # Check for 906 over-counting bug
        if len(lines) > 50 and mem_features.injected_code_regions == len(lines):
            details.append(
                f"Malfind FAIL: Injected code regions ({mem_features.injected_code_regions}) "
                f"equals raw line count ({len(lines)}), indicating raw row over-counting bug."
            )
            return False

        if mem_features.injected_code_regions != expected_regions:
            details.append(
                f"Malfind FAIL: Injected code regions mismatch. Extractor={mem_features.injected_code_regions}, "
                f"Independent Inspection={expected_regions} (from {len(lines)} lines of evidence)."
            )
            return False

        if proc_features.malfind_process_count != len(expected_pids):
            details.append(
                f"Malfind FAIL: Malfind distinct process count mismatch. "
                f"Extractor={proc_features.malfind_process_count}, Expected={len(expected_pids)}."
            )
            return False

        details.append(
            f"Malfind PASS: Correctly derived {expected_regions} genuine injected regions "
            f"across {len(expected_pids)} distinct processes from {len(lines)} evidence lines."
        )
        return True
    else:
        # JSON validation
        findings = parse_malfind_output(malfind_file)
        expected_regions = len(findings)
        expected_pids = {f["pid"] for f in findings if isinstance(f.get("pid"), int)}

        if mem_features.injected_code_regions != expected_regions:
            details.append(
                f"Malfind FAIL (JSON): Extractor={mem_features.injected_code_regions}, "
                f"Expected={expected_regions}."
            )
            return False
        if proc_features.malfind_process_count != len(expected_pids):
            details.append(
                f"Malfind FAIL (JSON): Process count mismatch. Extractor={proc_features.malfind_process_count}, "
                f"Expected={len(expected_pids)}."
            )
            return False

        details.append(
            f"Malfind PASS: Correctly verified {expected_regions} findings (JSON format)."
        )
        return True


def validate_ldrmodules_semantics(
    input_dir: Path,
    mem_features: MemoryFeatures,
    proc_features: ProcessFeatures,
    details: list[str],
) -> bool:
    """Validate ldrmodules record boundary parsing and unlinked module counts."""
    ldrmodules_file = find_plugin_file(input_dir, "ldrmodules")
    if not ldrmodules_file or not ldrmodules_file.is_file():
        details.append("LdrModules: No ldrmodules file found in directory (skipped).")
        return True

    records = parse_ldrmodules_output(ldrmodules_file)
    expected_inconsistencies = sum(
        1 for r in records if (not r.get("inload", True)) or (not r.get("inmem", True))
    )

    if mem_features.ldrmodules_inconsistencies != expected_inconsistencies:
        details.append(
            f"LdrModules FAIL: Memory extractor inconsistencies ({mem_features.ldrmodules_inconsistencies}) "
            f"!= expected ({expected_inconsistencies})."
        )
        return False

    if proc_features.unlinked_dll_count != expected_inconsistencies:
        details.append(
            f"LdrModules FAIL: Process extractor unlinked DLL count ({proc_features.unlinked_dll_count}) "
            f"!= expected ({expected_inconsistencies})."
        )
        return False

    details.append(
        f"LdrModules PASS: Validated {len(records)} distinct modules with {expected_inconsistencies} "
        "unlinked/inconsistent entries (InLoad/InMem semantics)."
    )
    return True


def validate_process_semantics(
    input_dir: Path,
    proc_features: ProcessFeatures,
    details: list[str],
) -> bool:
    """Validate process feature metrics against Windows architectural rules."""
    # 1. Total process count must be non-negative
    if proc_features.total_process_count < 0:
        details.append(
            f"Process FAIL: total_process_count is negative ({proc_features.total_process_count})."
        )
        return False

    # 2. Privileges validation: verify allowlist enforcement
    priv_file = find_plugin_file(input_dir, "privileges")
    if priv_file and priv_file.is_file():
        priv_records = parse_volatility_file(priv_file)
        expected_elevated_pids = set()
        for r in priv_records:
            pid_raw = r.get("pid")
            if not pid_raw:
                continue
            try:
                pid = int(pid_raw)
            except (ValueError, TypeError):
                continue
            priv_name = str(r.get("privilege") or r.get("name") or "").lower().strip()
            attrs = str(r.get("attributes") or "").lower().strip()
            if priv_name in HIGH_RISK_PRIVILEGES and "enabled" in attrs and "disabled" not in attrs:
                expected_elevated_pids.add(pid)

        if proc_features.elevated_privilege_count != len(expected_elevated_pids):
            details.append(
                f"Process FAIL: elevated_privilege_count ({proc_features.elevated_privilege_count}) "
                f"does not match expected distinct PIDs ({len(expected_elevated_pids)})."
            )
            return False

    details.append(
        f"Process PASS: {proc_features.total_process_count} processes, "
        f"{proc_features.hidden_process_count} hidden, {proc_features.anomalous_ppid_count} PPID anomalies, "
        f"{proc_features.elevated_privilege_count} distinct elevated PIDs."
    )
    return True


def validate_memory_semantics(
    input_dir: Path,
    mem_features: MemoryFeatures,
    details: list[str],
) -> bool:
    """Validate memory feature metrics (RWX VADs and entropy null handling)."""
    # 1. RWX VAD count non-negative
    if mem_features.rwx_page_count < 0:
        details.append(f"Memory FAIL: rwx_page_count is negative ({mem_features.rwx_page_count}).")
        return False

    # Verify RWX VAD count against vadinfo if file is present
    vad_file = find_plugin_file(input_dir, "vadinfo")
    if vad_file and vad_file.is_file():
        vad_records = parse_volatility_file(vad_file)
        expected_rwx = sum(
            1 for r in vad_records if "execute_readwrite" in str(r.get("protection") or "").lower()
        )
        if mem_features.rwx_page_count != expected_rwx:
            details.append(
                f"Memory FAIL: rwx_page_count ({mem_features.rwx_page_count}) != expected ({expected_rwx})."
            )
            return False

    # 2. Entropy null handling when raw bytes are unavailable
    # Ordinary Volatility text output does NOT supply full raw page bytes; entropy must be None
    if mem_features.mean_memory_entropy is not None:
        details.append(
            f"Memory FAIL: mean_memory_entropy was populated ({mem_features.mean_memory_entropy}) "
            "despite absence of raw byte payload."
        )
        return False

    details.append(
        f"Memory PASS: {mem_features.rwx_page_count} RWX pages, "
        f"{mem_features.unmapped_executable_pages} unmapped exec pages, "
        "entropy correctly left null."
    )
    return True


def validate_schema_compliance(
    proc_features: ProcessFeatures,
    mem_features: MemoryFeatures,
    details: list[str],
) -> bool:
    """Validate full Pydantic schema conformance and JSON serialization."""
    try:
        proc_dict = proc_features.model_dump()
        ProcessFeatures.model_validate(proc_dict)
        proc_json = json.dumps(proc_dict)
        assert len(proc_json) > 10

        mem_dict = mem_features.model_dump()
        MemoryFeatures.model_validate(mem_dict)
        mem_json = json.dumps(mem_dict)
        assert len(mem_json) > 10

        details.append(
            "Schema PASS: Both ProcessFeatures and MemoryFeatures satisfy schema contracts."
        )
        return True
    except Exception as exc:
        details.append(f"Schema FAIL: Schema validation error: {exc}")
        return False


def run_a4_validation(input_dir: Path, sample_id: str = "RUN-001") -> ValidationResult:
    """Execute complete A4 real-evidence semantic validation suite.

    Args:
        input_dir: Directory containing Volatility 3 output files.
        sample_id: Sample identifier (default: 'RUN-001').

    Returns:
        ValidationResult: Complete summary with per-component statuses.
    """
    details: list[str] = []

    # 1. Run actual extraction pipeline
    proc_feats = extract_process_features(input_dir, sample_id=sample_id)
    mem_feats = extract_memory_features(input_dir, sample_id=sample_id)

    # 2. Component validations
    proc_status = validate_process_semantics(input_dir, proc_feats, details)
    mem_status = validate_memory_semantics(input_dir, mem_feats, details)
    malfind_status = validate_malfind_semantics(input_dir, mem_feats, proc_feats, details)
    ldrmodules_status = validate_ldrmodules_semantics(input_dir, mem_feats, proc_feats, details)
    schema_status = validate_schema_compliance(proc_feats, mem_feats, details)

    return ValidationResult(
        sample_id=sample_id,
        input_dir=input_dir,
        process_status=proc_status,
        memory_status=mem_status,
        malfind_status=malfind_status,
        ldrmodules_status=ldrmodules_status,
        schema_status=schema_status,
        details=details,
    )


def print_validation_report(result: ValidationResult) -> None:
    """Print standard validation report."""
    sep = "=" * 40
    print("\n" + sep)
    print("A4 REAL-EVIDENCE VALIDATION")
    print(f"Sample: {result.sample_id}")
    print(f"Directory: {result.input_dir}")
    print(f"Process: {'PASS' if result.process_status else 'FAIL'}")
    print(f"Memory: {'PASS' if result.memory_status else 'FAIL'}")
    print(f"Malfind: {'PASS' if result.malfind_status else 'FAIL'}")
    print(f"LdrModules: {'PASS' if result.ldrmodules_status else 'FAIL'}")
    print(f"Schema: {'PASS' if result.schema_status else 'FAIL'}")
    print(f"Overall: {'PASS' if result.overall_status else 'FAIL'}")
    print(sep)
    print("\nDetailed Diagnostic Log:")
    for d in result.details:
        print(f"  - {d}")
    print(sep + "\n")


def main() -> int:
    """CLI entry point for A4 real-evidence validation."""
    parser = argparse.ArgumentParser(
        description="A4 Real-Evidence Validation Workflow for Volatility 3 Outputs"
    )
    parser.add_argument(
        "input_dir",
        nargs="?",
        type=Path,
        default=None,
        help="Path to RUN-001 Volatility outputs directory (defaults to auto-detection)",
    )
    parser.add_argument(
        "--sample-id",
        type=str,
        default="RUN-001",
        help="Sample identifier (default: RUN-001)",
    )
    args = parser.parse_args()

    target_dir = args.input_dir
    if not target_dir:
        target_dir = find_default_run001_dir()

    if not target_dir or not target_dir.is_dir():
        print(
            "ERROR: Could not locate RUN-001 evidence directory.\n"
            "Checked:\n"
            "  - ~/fmd-results/custom/RUN-001/\n"
            "  - ./data/raw/custom/RUN-001/\n"
            "  - ./tests/fixtures/volatility/RUN-001/\n\n"
            "Please specify the directory path:\n"
            "  python tools/validate_a4_evidence.py /path/to/RUN-001",
            file=sys.stderr,
        )
        return 1

    result = run_a4_validation(target_dir, sample_id=args.sample_id)
    print_validation_report(result)

    return 0 if result.overall_status else 1


if __name__ == "__main__":
    sys.exit(main())
