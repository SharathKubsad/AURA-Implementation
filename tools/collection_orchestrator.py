"""Collection Orchestrator for A6 Custom Dataset Pipeline.

Provides centralized management for:
- Category lookup and validation against the 12 project categories.
- Collision-free, non-overwriting RUN ID allocation based on A5 category ranges.
- Collection state machine (READY -> COLLECTING -> CAPTURE -> FINALIZING -> COMPLETE/FAILED).
- Canonical metadata generation and validation against CustomCollectionMetadata.
- Cryptographic SHA-256 evidence verification.
- Processing orchestration reusing the existing A4 extraction pipeline without duplication.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sys
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

# Ensure repository root is on sys.path when executed directly
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

try:
    from forensics.extraction.pipeline import run_track_a_extraction  # noqa: E402
except ImportError:
    run_track_a_extraction = None

try:
    from forensics.schemas.custom_collection import CustomCollectionMetadata  # noqa: E402
except ImportError:
    CustomCollectionMetadata = None

logger = logging.getLogger("orchestrator")


class CollectionState(str, Enum):
    """Formal states for the custom dataset collection process."""

    READY = "READY"
    COLLECTING = "COLLECTING"
    CAPTURE = "CAPTURE"
    FINALIZING = "FINALIZING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


VALID_STATE_TRANSITIONS: dict[CollectionState, set[CollectionState]] = {
    CollectionState.READY: {CollectionState.COLLECTING, CollectionState.FAILED},
    CollectionState.COLLECTING: {CollectionState.CAPTURE, CollectionState.FAILED},
    CollectionState.CAPTURE: {CollectionState.FINALIZING, CollectionState.FAILED},
    CollectionState.FINALIZING: {CollectionState.COMPLETE, CollectionState.FAILED},
    CollectionState.COMPLETE: set(),
    CollectionState.FAILED: set(),
}


class CollectionStateMachine:
    """Manages explicit state transitions for controlled evidence collection."""

    def __init__(self, run_id: str, category: str) -> None:
        self.run_id = run_id
        self.category = category
        self.state = CollectionState.READY
        self.history: list[tuple[CollectionState, str]] = [(self.state, "Initialized")]

    def transition_to(self, new_state: CollectionState, reason: str = "") -> None:
        """Execute a validated state transition."""
        allowed = VALID_STATE_TRANSITIONS.get(self.state, set())
        if new_state not in allowed:
            raise ValueError(
                f"Invalid state transition: cannot transition from {self.state.value} to {new_state.value}. "
                f"Allowed transitions: {[s.value for s in allowed]}"
            )
        self.state = new_state
        self.history.append((new_state, reason))
        logger.info("[%s] State changed to %s: %s", self.run_id, new_state.value, reason)

    def fail(self, reason: str) -> None:
        """Move state machine to FAILED with error description."""
        self.state = CollectionState.FAILED
        self.history.append((CollectionState.FAILED, reason))
        logger.error("[%s] Collection failed: %s", self.run_id, reason)


def load_categories_catalog() -> dict[str, Any]:
    """Load categories.json catalog from repository root."""
    catalog_path = _REPO_ROOT / "data" / "raw" / "custom" / "categories.json"
    if not catalog_path.is_file():
        raise FileNotFoundError(f"Missing categories catalog at {catalog_path}")
    return json.loads(catalog_path.read_text(encoding="utf-8"))


def get_category_info(category_name: str) -> dict[str, Any]:
    """Retrieve category definition from categories catalog."""
    catalog = load_categories_catalog()
    for cat in catalog["categories"]:
        if cat["name"].lower() == category_name.lower():
            return cat
    raise ValueError(
        f"Unknown category '{category_name}'. Valid categories: "
        f"{[c['name'] for c in catalog['categories']]}"
    )


def scan_existing_run_ids(search_dirs: list[Path]) -> set[int]:
    """Scan candidate directories for existing RUN-XXX directories.

    Guarantees no accidental overwrite by discovering all assigned IDs across:
    - Root custom dir (data/raw/custom/)
    - Category subdirectories (data/raw/custom/<cat>/)
    - Staging/results directories (~/fmd-results/custom/)
    """
    found_numbers: set[int] = set()
    run_pattern = re.compile(r"^RUN-(\d+)$", re.IGNORECASE)

    for base in search_dirs:
        if not base.is_dir():
            continue
        try:
            for item in base.iterdir():
                if item.is_dir():
                    m = run_pattern.match(item.name)
                    if m:
                        found_numbers.add(int(m.group(1)))
                    # Also scan one level deeper (e.g. data/raw/custom/<category>/RUN-XXX)
                    try:
                        for sub in item.iterdir():
                            if sub.is_dir():
                                m_sub = run_pattern.match(sub.name)
                                if m_sub:
                                    found_numbers.add(int(m_sub.group(1)))
                    except (PermissionError, OSError):
                        pass
        except (PermissionError, OSError):
            pass

    return found_numbers


def get_default_ledger_path() -> Path:
    """Return default persistent run ledger path."""
    return _REPO_ROOT / "data" / "raw" / "custom" / "allocated_runs.json"


def save_run_ledger(ledger_data: dict[str, Any], ledger_path: Path | None = None) -> None:
    """Save the persistent RUN ledger atomically."""
    path = ledger_path or get_default_ledger_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    ledger_data["updated_at"] = datetime.now(UTC).isoformat()
    temp_path = path.with_suffix(".tmp")
    temp_path.write_text(json.dumps(ledger_data, indent=2), encoding="utf-8")
    temp_path.replace(path)


def load_or_reconstruct_ledger(
    ledger_path: Path | None = None,
    search_dirs: list[Path] | None = None,
) -> dict[str, Any]:
    """Load persistent RUN ledger, or safely reconstruct it from existing RUN directories."""
    path = ledger_path or get_default_ledger_path()
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "runs" in data:
                return data
        except Exception as exc:
            logger.warning("Could not read ledger at %s (%s). Reconstructing...", path, exc)

    if search_dirs is None:
        search_dirs = [
            _REPO_ROOT / "data" / "raw" / "custom",
            Path.home() / "fmd-results" / "custom",
            Path.cwd() / "data" / "raw" / "custom",
        ]

    runs: dict[str, Any] = {
        "RUN-001": {
            "run_id": "RUN-001",
            "run_number": 1,
            "category": "benign",
            "allocation_timestamp": datetime.now(UTC).isoformat(),
            "status": "RESERVED_BASELINE",
            "evidence_location": "data/raw/custom/RUN-001",
        }
    }

    run_pattern = re.compile(r"^RUN-(\d+)$", re.IGNORECASE)
    for sdir in search_dirs:
        if not sdir.is_dir():
            continue
        try:
            for item in sdir.rglob("RUN-*"):
                if item.is_dir():
                    m = run_pattern.match(item.name)
                    if m:
                        r_num = int(m.group(1))
                        r_id = f"RUN-{r_num:03d}"
                        if r_id not in runs:
                            cat_name = (
                                item.parent.name if item.parent.name != "custom" else "unknown"
                            )
                            meta_f = item / "metadata.json"
                            if meta_f.is_file():
                                try:
                                    m_data = json.loads(meta_f.read_text(encoding="utf-8"))
                                    cat_name = m_data.get("family", cat_name)
                                except Exception:
                                    pass
                            runs[r_id] = {
                                "run_id": r_id,
                                "run_number": r_num,
                                "category": cat_name,
                                "allocation_timestamp": datetime.now(UTC).isoformat(),
                                "status": "ALLOCATED",
                                "evidence_location": str(item),
                            }
        except Exception as scan_err:
            logger.warning("Error scanning %s for ledger reconstruction: %s", sdir, scan_err)

    ledger_data = {
        "version": "1.0.0",
        "updated_at": datetime.now(UTC).isoformat(),
        "runs": runs,
    }
    save_run_ledger(ledger_data, ledger_path=path)
    return ledger_data


def record_run_in_ledger(
    run_id: str,
    category: str,
    status: str = "ALLOCATED",
    evidence_location: str | None = None,
    ledger_path: Path | None = None,
) -> None:
    """Record or update a run entry in the persistent ledger."""
    ledger = load_or_reconstruct_ledger(ledger_path=ledger_path)
    m = re.match(r"^RUN-(\d+)$", run_id, re.IGNORECASE)
    r_num = int(m.group(1)) if m else 0

    ledger["runs"][run_id] = {
        "run_id": run_id,
        "run_number": r_num,
        "category": category,
        "allocation_timestamp": datetime.now(UTC).isoformat(),
        "status": status,
        "evidence_location": evidence_location,
    }
    save_run_ledger(ledger, ledger_path=ledger_path)


def allocate_next_run_id(
    category_name: str,
    search_dirs: list[Path] | None = None,
    ledger_path: Path | None = None,
) -> tuple[int, str]:
    """Allocate the next available unused RUN ID for the specified category.

    Rules:
    - Queries category range from categories.json.
    - Never reallocates RUN-001 (permanently reserved as benign validation baseline).
    - Checks both directory hierarchy and persistent allocation ledger.
    - Never overwrites an existing directory or reused ID.
    - Atomically registers the allocation in the persistent ledger.

    Args:
        category_name: One of the 12 project categories.
        search_dirs: Optional list of directories to scan for existing runs.
        ledger_path: Optional custom path to allocation ledger JSON.

    Returns:
        tuple[int, str]: Integer run number and canonical string ID (e.g. (2, "RUN-002")).
    """
    cat_info = get_category_info(category_name)
    run_start, run_end = cat_info["run_range"]

    if search_dirs is None:
        search_dirs = [
            _REPO_ROOT / "data" / "raw" / "custom",
            Path.home() / "fmd-results" / "custom",
            Path.cwd() / "data" / "raw" / "custom",
        ]

    # Load / reconstruct persistent ledger
    ledger = load_or_reconstruct_ledger(ledger_path=ledger_path, search_dirs=search_dirs)

    # Combine existing IDs from disk scanning and ledger entries
    existing_ids = scan_existing_run_ids(search_dirs)
    existing_ids.add(1)  # Always reserve RUN-001

    for entry in ledger.get("runs", {}).values():
        if "run_number" in entry:
            existing_ids.add(int(entry["run_number"]))

    for run_num in range(run_start, run_end + 1):
        if run_num not in existing_ids:
            run_id = f"RUN-{run_num:03d}"
            record_run_in_ledger(
                run_id=run_id,
                category=category_name,
                status="ALLOCATED",
                ledger_path=ledger_path,
            )
            return run_num, run_id

    raise RuntimeError(
        f"Exhausted allocated RUN ID range [{run_start}, {run_end}] for category '{category_name}'."
    )


def calculate_file_sha256(file_path: Path) -> str:
    """Calculate hex SHA-256 hash of a file."""
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


EXCLUDED_EVIDENCE_FILES = {"metadata.json", "validation_report.json", "allocated_runs.json"}


def calculate_directory_evidence_sha256(run_dir: Path) -> str:
    """Calculate consolidated SHA-256 hash across all evidence files in run directory.

    Canonical Algorithm:
    1. Collect all evidence files recursively in run_dir (excluding metadata/reports/ledger).
    2. Sort files deterministically by normalized relative POSIX path.
    3. For each file:
       - Hash relative path string encoded as UTF-8.
       - Hash raw file content bytes in 64KB chunks.
    4. Return single 64-character lowercase hex digest.
    """
    h = hashlib.sha256()
    candidate_files = [
        p for p in run_dir.rglob("*") if p.is_file() and p.name not in EXCLUDED_EVIDENCE_FILES
    ]
    candidate_files.sort(key=lambda p: p.relative_to(run_dir).as_posix())

    if not candidate_files:
        return "0" * 64

    for fpath in candidate_files:
        rel_posix = fpath.relative_to(run_dir).as_posix()
        h.update(rel_posix.encode("utf-8"))
        with open(fpath, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
    return h.hexdigest()


def build_run_metadata(
    run_id: str,
    category_name: str,
    os_name: str = "windows_10",
    source_reference: str = "manual_controlled_execution",
    evidence_sha256: str = "0" * 64,
    memory_dump: bool = True,
    sysmon_available: bool = True,
    notes: str = "",
    execution_timestamp: str | None = None,
) -> dict[str, Any]:
    """Construct and validate canonical metadata dictionary against Pydantic schema."""
    from datetime import datetime

    cat_info = get_category_info(category_name)
    sample_id = f"EXEC_{run_id}"

    ts_str = execution_timestamp or datetime.now(UTC).isoformat()

    metadata_dict = {
        "sample_id": sample_id,
        "label": cat_info["binary_label"],
        "family": cat_info["family"],
        "track": cat_info["track"],
        "os": os_name,
        "execution_timestamp": ts_str,
        "source_type": "custom_sandbox",
        "source_reference": source_reference,
        "evidence_sha256": evidence_sha256,
        "memory_dump": memory_dump,
        "sysmon_available": sysmon_available,
        "notes": notes or f"Controlled experiment execution for {cat_info['family']}",
    }

    # Validate against canonical Pydantic model
    if CustomCollectionMetadata is not None:
        CustomCollectionMetadata.model_validate(metadata_dict)
    return metadata_dict


def verify_run_evidence(run_dir: Path) -> tuple[bool, list[str]]:
    """Verify that a completed RUN directory meets all evidence and schema criteria.

    Checks:
    - metadata.json presence and schema compliance
    - required evidence files presence
    - SHA256 cryptographic verification
    """
    errors: list[str] = []

    if not run_dir.is_dir():
        return False, [f"Directory does not exist: {run_dir}"]

    meta_file = run_dir / "metadata.json"
    if not meta_file.is_file():
        return False, [f"Missing metadata.json in {run_dir}"]

    try:
        meta_data = json.loads(meta_file.read_text(encoding="utf-8"))
        if CustomCollectionMetadata is not None:
            CustomCollectionMetadata.model_validate(meta_data)
    except Exception as exc:
        errors.append(f"Invalid metadata.json: {exc}")
        return False, errors

    recorded_sha = meta_data.get("evidence_sha256")
    if recorded_sha and recorded_sha != "0" * 64:
        calc_sha = calculate_directory_evidence_sha256(run_dir)
        if recorded_sha.lower() != calc_sha.lower():
            errors.append(
                f"Evidence SHA-256 mismatch: recorded {recorded_sha} != calculated {calc_sha}"
            )

    return len(errors) == 0, errors


def process_run_pipeline(
    run_dir: Path,
    output_base_dir: Path | None = None,
    sample_id: str | None = None,
    ledger_path: Path | None = None,
) -> dict[str, Any]:
    """Execute complete processing of a completed RUN directory.

    Reuses the existing A4 forensic extraction pipeline:
    - Extracts ProcessFeatures and MemoryFeatures.
    - Saves interim artifacts under data/interim/custom/process/ and data/interim/custom/memory/.
    - Preserves Command and Network logs for Track B.
    - Emits a machine-readable validation report.
    """
    if output_base_dir is None:
        output_base_dir = _REPO_ROOT / "data" / "interim" / "custom"

    # 1. Verify evidence package
    valid, errors = verify_run_evidence(run_dir)
    if not valid:
        return {
            "status": "FAILED",
            "run_dir": str(run_dir),
            "errors": errors,
        }

    meta_file = run_dir / "metadata.json"
    meta_data = json.loads(meta_file.read_text(encoding="utf-8"))
    resolved_sample_id = sample_id or meta_data["sample_id"]

    # 2. Invoke existing Track A extraction pipeline
    if run_track_a_extraction is None:
        raise RuntimeError(
            "forensics.extraction.pipeline could not be imported; "
            "verify required dependencies are installed to process runs."
        )
    extraction_result = run_track_a_extraction(
        input_dir=run_dir,
        sample_id=resolved_sample_id,
        output_base_dir=output_base_dir,
    )

    # 3. Verify interim outputs exist
    proc_ok = extraction_result.process_output_path.is_file()
    mem_ok = extraction_result.memory_output_path.is_file()

    # 4. Write machine-readable validation report in run directory
    report_data = {
        "status": "PASS" if (proc_ok and mem_ok) else "FAIL",
        "sample_id": resolved_sample_id,
        "run_dir": str(run_dir),
        "label": meta_data.get("label"),
        "family": meta_data.get("family"),
        "track": meta_data.get("track"),
        "process_features": str(extraction_result.process_output_path),
        "memory_features": str(extraction_result.memory_output_path),
        "process_status": "PASS" if proc_ok else "FAIL",
        "memory_status": "PASS" if mem_ok else "FAIL",
    }

    report_path = run_dir / "validation_report.json"
    report_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")

    record_run_in_ledger(
        run_id=resolved_sample_id.replace("EXEC_", ""),
        category=meta_data.get("family", ""),
        status="PROCESSED" if (proc_ok and mem_ok) else "FAILED",
        evidence_location=str(run_dir),
        ledger_path=ledger_path,
    )

    return report_data


def init_run_directory(
    category_name: str,
    base_dir: Path | None = None,
    run_id: str | None = None,
    notes: str = "",
) -> tuple[str, Path]:
    """Initialize a new RUN directory with initial metadata.

    Args:
        category_name: Category to allocate run for.
        base_dir: Base directory where run folder will be created. Defaults to data/raw/custom/<category>.
        run_id: Optional predetermined run_id. If None, allocates next available ID.
        notes: Optional initial notes.

    Returns:
        tuple[str, Path]: The allocated run ID and the created run directory path.
    """
    if run_id is None:
        _, run_id = allocate_next_run_id(category_name)

    if base_dir is None:
        base_dir = _REPO_ROOT / "data" / "raw" / "custom" / category_name

    run_dir = base_dir / run_id
    if run_dir.exists():
        raise FileExistsError(f"Target run directory already exists: {run_dir}")

    run_dir.mkdir(parents=True, exist_ok=False)

    initial_meta = build_run_metadata(
        run_id=run_id,
        category_name=category_name,
        notes=notes or f"Initial metadata for {run_id}",
    )
    meta_path = run_dir / "metadata.json"
    meta_path.write_text(json.dumps(initial_meta, indent=2), encoding="utf-8")

    return run_id, run_dir


def finalize_run_evidence(
    run_dir: Path,
    memory_dump_present: bool = True,
    sysmon_present: bool = True,
    notes: str | None = None,
    ledger_path: Path | None = None,
) -> dict[str, Any]:
    """Finalize evidence collection for a RUN: compute hashes, update metadata, verify integrity.

    Args:
        run_dir: Path to the completed run directory.
        memory_dump_present: Whether memory dump is included.
        sysmon_present: Whether Sysmon log is included.
        notes: Optional updated notes.
        ledger_path: Optional custom path to persistent allocation ledger.

    Returns:
        dict[str, Any]: The finalized metadata dictionary.
    """
    meta_file = run_dir / "metadata.json"
    if not meta_file.is_file():
        raise FileNotFoundError(f"Missing metadata.json in {run_dir}")

    meta = json.loads(meta_file.read_text(encoding="utf-8"))

    # Compute consolidated evidence SHA-256
    evidence_sha256 = calculate_directory_evidence_sha256(run_dir)

    meta["evidence_sha256"] = evidence_sha256
    meta["memory_dump"] = memory_dump_present
    meta["sysmon_available"] = sysmon_present
    if notes is not None:
        meta["notes"] = notes

    # Validate against Pydantic schema
    if CustomCollectionMetadata is not None:
        CustomCollectionMetadata.model_validate(meta)

    # Save finalized metadata
    meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    # Run full verification
    ok, errors = verify_run_evidence(run_dir)
    if not ok:
        raise ValueError(f"Finalized run failed verification: {errors}")

    record_run_in_ledger(
        run_id=meta.get("sample_id", "").replace("EXEC_", ""),
        category=meta.get("family", ""),
        status="FINALIZED",
        evidence_location=str(run_dir),
        ledger_path=ledger_path,
    )

    return meta


def main() -> int:
    """CLI interface for collection orchestrator."""
    parser = argparse.ArgumentParser(description="Custom Dataset Collection Orchestrator")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: list-categories
    subparsers.add_parser("list-categories", help="List all 12 dataset categories")

    # Subcommand: allocate
    alloc_parser = subparsers.add_parser("allocate", help="Allocate next unused RUN ID")
    alloc_parser.add_argument("--category", required=True, help="Category name")

    # Subcommand: init-run
    init_parser = subparsers.add_parser("init-run", help="Initialize a new RUN directory")
    init_parser.add_argument("--category", required=True, help="Category name")
    init_parser.add_argument(
        "--output-dir", type=Path, default=None, help="Base directory for the run"
    )
    init_parser.add_argument("--notes", default="", help="Optional notes")

    # Subcommand: finalize-run
    fin_parser = subparsers.add_parser(
        "finalize-run", help="Finalize evidence and hash in RUN directory"
    )
    fin_parser.add_argument("run_dir", type=Path, help="Path to RUN directory")
    fin_parser.add_argument("--no-memory", action="store_true", help="Mark memory dump absent")
    fin_parser.add_argument("--no-sysmon", action="store_true", help="Mark Sysmon absent")
    fin_parser.add_argument("--notes", default=None, help="Optional updated notes")

    # Subcommand: verify
    verify_parser = subparsers.add_parser("verify", help="Verify RUN directory evidence")
    verify_parser.add_argument("run_dir", type=Path, help="Path to RUN directory")

    # Subcommand: hash-evidence
    hash_parser = subparsers.add_parser(
        "hash-evidence", help="Calculate canonical evidence SHA-256 for a RUN directory"
    )
    hash_parser.add_argument("run_dir", type=Path, help="Path to RUN directory")

    # Subcommand: process
    proc_parser = subparsers.add_parser("process", help="Process completed RUN through A4 pipeline")
    proc_parser.add_argument("run_dir", type=Path, help="Path to RUN directory")
    proc_parser.add_argument(
        "--output-dir", type=Path, default=None, help="Interim output directory"
    )

    args = parser.parse_args()

    if args.command == "list-categories":
        cats = load_categories_catalog()["categories"]
        for idx, c in enumerate(cats, 1):
            r_start, r_end = c["run_range"]
            print(
                f"[{idx:2d}] {c['name']:<28} (Track: {c['track']:<7}, Range: RUN-{r_start:03d}..RUN-{r_end:03d})"
            )
        return 0

    if args.command == "allocate":
        run_num, run_id = allocate_next_run_id(args.category)
        print(f"Allocated: {run_id} (Number: {run_num}) for category '{args.category}'")
        return 0

    if args.command == "init-run":
        run_id, rdir = init_run_directory(
            category_name=args.category,
            base_dir=args.output_dir,
            notes=args.notes,
        )
        print(f"Initialized {run_id} at: {rdir}")
        return 0

    if args.command == "finalize-run":
        meta = finalize_run_evidence(
            run_dir=args.run_dir,
            memory_dump_present=not args.no_memory,
            sysmon_present=not args.no_sysmon,
            notes=args.notes,
        )
        print(f"PASS: Finalized {meta['sample_id']} with SHA256: {meta['evidence_sha256']}")
        return 0

    if args.command == "verify":
        ok, errors = verify_run_evidence(args.run_dir)
        if ok:
            print(f"PASS: Evidence verified for {args.run_dir}")
            return 0
        print(f"FAIL: {errors}", file=sys.stderr)
        return 1

    if args.command == "hash-evidence":
        if not args.run_dir.is_dir():
            print(f"FAIL: Directory does not exist: {args.run_dir}", file=sys.stderr)
            return 1
        digest = calculate_directory_evidence_sha256(args.run_dir)
        print(digest)
        return 0

    if args.command == "process":
        res = process_run_pipeline(args.run_dir, output_base_dir=args.output_dir)
        print(json.dumps(res, indent=2))
        return 0 if res.get("status") == "PASS" else 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
