"""Audit tool for the unified ML dataset.

Validates data/processed/unified/unified_dataset.jsonl and produces:
  data/processed/unified/unified_dataset_audit.json
  data/processed/unified/unified_dataset_audit.csv

Checks
------
* Exactly one row per sample_id
* No duplicate sample_ids
* Binary label in {0, 1}
* Family consistency (label ↔ family agreement)
* NaN / Inf in non-nullable numeric features
* Preserved legitimate None / null values for PCAP-null fields
* Zero-variance feature detection
* Feature missingness report
* Cross-modality feature presence (all expected column groups present)
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import math
import statistics
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from preprocessing.pipeline import (  # noqa: E402
    ALL_NUMERIC_FEATURE_COLS,
    COMMAND_FEATURE_COLS,
    MEMORY_FEATURE_COLS,
    NETWORK_FEATURE_COLS,
    PCAP_NULL_FIELDS,
    PROCESS_FEATURE_COLS,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("audit_unified_dataset")


# Fields that are legitimately null when telemetry is not present
# (PCAP unsupported fields + optional memory forensic entropy fields)
EXPECTED_NULL_FIELDS: frozenset[str] = PCAP_NULL_FIELDS | frozenset(
    [
        "mean_memory_entropy",
        "max_memory_entropy",
    ]
)


# ---------------------------------------------------------------------------
# Status enum
# ---------------------------------------------------------------------------


class AuditStatus(StrEnum):
    """Per-sample audit classification."""

    VALID = "valid"
    WARNING = "warning"
    INVALID = "invalid"


# ---------------------------------------------------------------------------
# Dataclass for per-sample result
# ---------------------------------------------------------------------------


@dataclass
class SampleAuditResult:
    """Audit result for one sample row."""

    sample_id: str
    status: AuditStatus
    binary_label: int | None
    family: str
    issues: list[str] = field(default_factory=list)
    nan_inf_fields: list[str] = field(default_factory=list)
    missing_fields: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _is_finite(val: Any) -> bool:
    """Return True iff val is a finite numeric value."""
    if val is None:
        return False
    try:
        return math.isfinite(float(val))
    except (TypeError, ValueError):
        return False


def _compute_variance(values: list[float]) -> float:
    """Compute population variance over a list of finite floats."""
    if len(values) < 2:
        return 0.0
    return statistics.pvariance(values)


# ---------------------------------------------------------------------------
# Per-sample audit
# ---------------------------------------------------------------------------


def _audit_sample(row: dict[str, Any]) -> SampleAuditResult:
    """Audit a single unified sample row.

    Args:
        row: Parsed JSON dict for one sample.

    Returns:
        SampleAuditResult with status and issue list.
    """
    sid = row.get("sample_id", "<unknown>")
    lbl = row.get("binary_label")
    family = str(row.get("family", "unknown"))
    issues: list[str] = []
    nan_inf_fields: list[str] = []
    missing_fields: list[str] = []

    # Binary label
    if lbl not in (0, 1):
        issues.append(f"binary_label is {lbl!r}, expected 0 or 1")

    # Family / label consistency
    if lbl == 0 and family != "benign":
        issues.append(f"binary_label=0 but family='{family}' (expected 'benign')")
    if lbl == 1 and family == "benign":
        issues.append("binary_label=1 but family='benign'")

    # Numeric feature checks
    for col in ALL_NUMERIC_FEATURE_COLS:
        val = row.get(col)
        if val is None:
            if col not in EXPECTED_NULL_FIELDS:
                # Non-expected nulls are unexpected but not fatal
                missing_fields.append(col)
            # Expected null fields being None is expected — do not flag
            continue
        try:
            fval = float(val)
            if math.isnan(fval) or math.isinf(fval):
                nan_inf_fields.append(col)
                issues.append(f"Feature '{col}' has non-finite value: {val}")
        except (TypeError, ValueError):
            issues.append(f"Feature '{col}' is non-numeric: {val!r}")

    if nan_inf_fields or missing_fields:
        status = AuditStatus.WARNING
    elif issues:
        status = AuditStatus.INVALID
    else:
        status = AuditStatus.VALID

    return SampleAuditResult(
        sample_id=sid,
        status=status,
        binary_label=lbl,
        family=family,
        issues=issues,
        nan_inf_fields=nan_inf_fields,
        missing_fields=missing_fields,
    )


# ---------------------------------------------------------------------------
# Dataset-level audit
# ---------------------------------------------------------------------------


def audit_unified_dataset(
    unified_dir: Path,
) -> dict[str, Any]:
    """Audit the unified dataset and return a full report dict.

    Args:
        unified_dir: Directory containing ``unified_dataset.jsonl``.

    Returns:
        Audit report dict.

    Raises:
        FileNotFoundError: If ``unified_dataset.jsonl`` is missing.
        ValueError: If duplicate sample_ids are detected.
    """
    jsonl_path = unified_dir / "unified_dataset.jsonl"
    if not jsonl_path.exists():
        raise FileNotFoundError(
            f"unified_dataset.jsonl not found at {jsonl_path}. Run build_unified_dataset.py first."
        )

    rows: list[dict[str, Any]] = []
    with jsonl_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))

    logger.info("Loaded %d rows from %s", len(rows), jsonl_path)

    # ---------------------------------------------------------------
    # Duplicate sample_id check
    # ---------------------------------------------------------------
    id_counts = Counter(r.get("sample_id") for r in rows)
    duplicates = {sid: cnt for sid, cnt in id_counts.items() if cnt > 1}
    if duplicates:
        raise ValueError(f"Duplicate sample_ids detected: {duplicates}")

    # ---------------------------------------------------------------
    # Per-sample audit
    # ---------------------------------------------------------------
    sample_results: list[SampleAuditResult] = [_audit_sample(r) for r in rows]
    status_counts = Counter(s.status for s in sample_results)

    # ---------------------------------------------------------------
    # Label / family distribution
    # ---------------------------------------------------------------
    label_counts: dict[str, int] = {}
    family_counts: dict[str, int] = {}
    for r in rows:
        lbl_key = "malware" if r.get("binary_label") == 1 else "benign"
        label_counts[lbl_key] = label_counts.get(lbl_key, 0) + 1
        fam = str(r.get("family", "unknown"))
        family_counts[fam] = family_counts.get(fam, 0) + 1

    # ---------------------------------------------------------------
    # Feature missingness per column
    # ---------------------------------------------------------------
    n = len(rows)
    missingness: dict[str, dict[str, Any]] = {}
    for col in ALL_NUMERIC_FEATURE_COLS:
        null_count = sum(1 for r in rows if r.get(col) is None)
        missingness[col] = {
            "n_missing": null_count,
            "missing_pct": round(null_count / n * 100, 2) if n else 0.0,
            "is_pcap_null_field": col in PCAP_NULL_FIELDS,
            "expected_null": col in PCAP_NULL_FIELDS,
        }

    # ---------------------------------------------------------------
    # Variance report per column
    # ---------------------------------------------------------------
    variance_report: dict[str, dict[str, Any]] = {}
    zero_variance_features: list[str] = []
    for col in ALL_NUMERIC_FEATURE_COLS:
        finite_vals = [float(r[col]) for r in rows if _is_finite(r.get(col))]
        var = _compute_variance(finite_vals)
        is_zv = var == 0.0 and len(finite_vals) > 0
        if is_zv:
            zero_variance_features.append(col)
        variance_report[col] = {
            "n_finite": len(finite_vals),
            "variance": round(var, 8),
            "is_zero_variance": is_zv,
            "mean": round(statistics.mean(finite_vals), 6) if finite_vals else None,
            "min": min(finite_vals) if finite_vals else None,
            "max": max(finite_vals) if finite_vals else None,
        }

    # ---------------------------------------------------------------
    # Modality column presence
    # ---------------------------------------------------------------
    modality_presence: dict[str, dict[str, Any]] = {}
    for modality, cols in [
        ("process", PROCESS_FEATURE_COLS),
        ("memory", MEMORY_FEATURE_COLS),
        ("command", COMMAND_FEATURE_COLS),
        ("network", NETWORK_FEATURE_COLS),
    ]:
        present = [c for c in cols if any(c in r for r in rows)]
        modality_presence[modality] = {
            "expected": len(cols),
            "present": len(present),
            "missing_cols": [c for c in cols if c not in present],
        }

    # ---------------------------------------------------------------
    # Build report
    # ---------------------------------------------------------------
    report: dict[str, Any] = {
        "audit_timestamp": datetime.now(tz=UTC).isoformat(),
        "unified_jsonl": str(jsonl_path),
        "summary": {
            "total_samples": n,
            "status_counts": {k.value: v for k, v in status_counts.items()},
            "label_distribution": label_counts,
            "family_distribution": family_counts,
            "duplicate_sample_ids": duplicates,
            "zero_variance_features": zero_variance_features,
        },
        "modality_presence": modality_presence,
        "missingness_per_feature": missingness,
        "variance_per_feature": variance_report,
        "samples": {
            s.sample_id: {
                "status": s.status.value,
                "binary_label": s.binary_label,
                "family": s.family,
                "issues": s.issues,
                "nan_inf_fields": s.nan_inf_fields,
                "missing_fields": s.missing_fields,
            }
            for s in sample_results
        },
    }

    return report


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------


def _write_json(report: dict[str, Any], path: Path) -> None:
    """Write audit report as pretty-printed JSON.

    Args:
        report: Audit report dict.
        path: Destination file path.
    """
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    logger.info("Wrote JSON audit to %s", path)


def _write_csv(report: dict[str, Any], path: Path) -> None:
    """Write per-sample audit summary as CSV.

    Args:
        report: Audit report dict.
        path: Destination CSV path.
    """
    fieldnames = [
        "sample_id",
        "status",
        "binary_label",
        "family",
        "issue_count",
        "nan_inf_count",
        "missing_count",
        "issues_summary",
    ]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for sid, info in sorted(report["samples"].items()):
            writer.writerow(
                {
                    "sample_id": sid,
                    "status": info["status"],
                    "binary_label": info["binary_label"],
                    "family": info["family"],
                    "issue_count": len(info["issues"]),
                    "nan_inf_count": len(info["nan_inf_fields"]),
                    "missing_count": len(info["missing_fields"]),
                    "issues_summary": " | ".join(info["issues"]) if info["issues"] else "",
                }
            )
    logger.info("Wrote CSV audit to %s", path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> None:
    """Entry point for CLI invocation."""
    parser = argparse.ArgumentParser(
        description="Audit the unified ML dataset for invariant violations."
    )
    parser.add_argument(
        "--unified-dir",
        type=Path,
        default=Path("data/processed/unified"),
        help="Directory containing unified_dataset.jsonl.",
    )
    args = parser.parse_args(argv)

    unified_dir: Path = args.unified_dir
    report = audit_unified_dataset(unified_dir)

    # Write outputs
    _write_json(report, unified_dir / "unified_dataset_audit.json")
    _write_csv(report, unified_dir / "unified_dataset_audit.csv")

    # Print summary
    s = report["summary"]
    print("\n" + "=" * 64)
    print("  UNIFIED DATASET AUDIT REPORT")
    print("=" * 64)
    print(f"  Total samples:         {s['total_samples']}")
    print(f"  Status breakdown:      {s['status_counts']}")
    print(f"  Label distribution:    {s['label_distribution']}")
    print(f"  Duplicate sample IDs:  {len(s['duplicate_sample_ids'])}")
    print(f"  Zero-variance features:{len(s['zero_variance_features'])}")
    if s["zero_variance_features"]:
        for zv in s["zero_variance_features"]:
            print(f"    - {zv}")
    print()
    print("  Modality column presence:")
    for mod, info in report["modality_presence"].items():
        status_str = "OK" if info["missing_cols"] == [] else f"MISSING: {info['missing_cols']}"
        print(f"    {mod:<12}  {info['present']}/{info['expected']} columns  {status_str}")
    print("=" * 64)

    # Exit non-zero if any fatal issues
    invalid_count = s["status_counts"].get("invalid", 0)
    if invalid_count > 0 or s["duplicate_sample_ids"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
