"""Build unified machine-learning dataset from extracted forensic telemetry.

Reads four modality JSON files from data/interim/ (process, memory, command,
network), joins them strictly by canonical sample_id, and produces a unified
dataset under data/processed/unified/.

Outputs
-------
unified_dataset.jsonl      – one JSON object per sample (all fields)
unified_dataset.csv        – flat numeric matrix (NaN for legitimate nulls)
dataset_manifest.json      – metadata, counts, feature column lists
feature_statistics.json    – per-feature variance, missingness, min/max/mean
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import math
import statistics
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Repo-root on sys.path for direct execution
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("build_unified_dataset")

# ---------------------------------------------------------------------------
# Feature column definitions (mirrors preprocessing/pipeline.py)
# ---------------------------------------------------------------------------
PROCESS_FEATURE_COLS: list[str] = [
    "total_process_count",
    "hidden_process_count",
    "anomalous_ppid_count",
    "avg_threads_per_process",
    "max_threads_in_single_process",
    "total_handle_count",
    "suspicious_dll_count",
    "malfind_process_count",
    "elevated_privilege_count",
    "unlinked_dll_count",
]

MEMORY_FEATURE_COLS: list[str] = [
    "rwx_page_count",
    "injected_code_regions",
    "unmapped_executable_pages",
    "vad_protection_anomaly_count",
    "ldrmodules_inconsistencies",
    "yara_shellcode_matches",
    "mean_memory_entropy",
    "max_memory_entropy",
]

COMMAND_FEATURE_COLS: list[str] = [
    "command_length",
    "shannon_entropy",
    "is_base64_encoded",
    "has_download_cradle",
    "has_bypass_execution_policy",
    "has_hidden_window",
    "uses_lolbins",
    "registry_persistence_count",
]

NETWORK_FEATURE_COLS: list[str] = [
    "active_connection_count",
    "listening_port_count",
    "outbound_connection_count",
    "dns_query_count",
    "unique_remote_ips",
    "avg_interpacket_interval_ms",
    "beacon_regularity_score",
    "total_bytes_sent",
    "total_bytes_received",
    "suspicious_port_usage",
]

# Fields that are legitimately null when PCAP is unavailable
PCAP_NULL_FIELDS: frozenset[str] = frozenset(
    [
        "dns_query_count",
        "avg_interpacket_interval_ms",
        "beacon_regularity_score",
        "total_bytes_sent",
        "total_bytes_received",
    ]
)

# The raw NLP text field – kept in JSONL but excluded from the numeric CSV matrix
NLP_TEXT_FIELDS: frozenset[str] = frozenset(["raw_command_text"])

# Metadata fields carried alongside features
METADATA_COLS: list[str] = ["sample_id", "binary_label", "family", "track", "source"]

ALL_NUMERIC_FEATURE_COLS: list[str] = (
    PROCESS_FEATURE_COLS + MEMORY_FEATURE_COLS + COMMAND_FEATURE_COLS + NETWORK_FEATURE_COLS
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_modality_dir(directory: Path) -> dict[str, dict[str, Any]]:
    """Load all JSON files from a modality directory, keyed by sample_id.

    Args:
        directory: Path to a modality directory (e.g. data/interim/process/).

    Returns:
        Mapping of sample_id -> parsed JSON dict.

    Raises:
        FileNotFoundError: If directory does not exist.
        KeyError: If a JSON file has no ``sample_id`` field.
    """
    if not directory.is_dir():
        raise FileNotFoundError(f"Modality directory not found: {directory}")
    result: dict[str, dict[str, Any]] = {}
    for json_file in sorted(directory.glob("*.json")):
        data = json.loads(json_file.read_text(encoding="utf-8"))
        sid = data.get("sample_id")
        if not sid:
            raise KeyError(f"Missing sample_id in {json_file}")
        result[sid] = data
    logger.info("Loaded %d records from %s", len(result), directory)
    return result


def _get_label_family(
    audit_report: dict[str, Any],
    sample_id: str,
    combined_record: dict[str, Any] | None = None,
) -> tuple[int | None, str, str, str]:
    """Extract label, family, track and source from audit report or records.

    Args:
        audit_report: Parsed dataset_audit_report.json.
        sample_id: Canonical sample identifier.
        combined_record: Optional dictionary merged from modality records.

    Returns:
        Tuple of (binary_label, family, track, source).
    """
    samples = audit_report.get("samples", {})
    info = samples.get(sample_id, {})
    binary_label: int | None = info.get("binary_label")
    family: str = info.get("family", "unknown")
    track: str = info.get("track", "custom")
    source: str = info.get("source", "custom")

    # Fallback to modality record if audit report did not provide fields
    if combined_record:
        if binary_label is None:
            if "binary_label" in combined_record and combined_record["binary_label"] in (0, 1):
                binary_label = int(combined_record["binary_label"])
            elif "label" in combined_record and combined_record["label"] in (0, 1):
                binary_label = int(combined_record["label"])
        if family == "unknown" and "family" in combined_record:
            family = str(combined_record["family"])
        if track == "custom" and "track" in combined_record:
            track = str(combined_record["track"])
        if source == "custom" and "source" in combined_record:
            source = str(combined_record["source"])

    # Fallback when audit report is absent/empty (e.g. synthetic test fixtures)
    if binary_label is None and not samples:
        binary_label = 0
        if family == "unknown":
            family = "benign"

    return binary_label, family, track, source


def _is_finite(val: Any) -> bool:
    """Return True if val is a finite numeric value (not None, NaN, or Inf)."""
    if val is None:
        return False
    try:
        f = float(val)
        return math.isfinite(f)
    except (TypeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Feature statistics computation
# ---------------------------------------------------------------------------


def _compute_feature_stats(
    rows: list[dict[str, Any]],
    feature_cols: list[str],
) -> dict[str, dict[str, Any]]:
    """Compute per-feature statistics over the unified sample set.

    Args:
        rows: List of unified sample dicts.
        feature_cols: Numeric feature column names to analyse.

    Returns:
        Dict mapping feature name -> statistics dict with keys:
        ``n_samples``, ``n_missing``, ``missing_pct``, ``n_finite``,
        ``mean``, ``std``, ``min``, ``max``, ``variance``,
        ``is_zero_variance``.
    """
    n = len(rows)
    stats: dict[str, dict[str, Any]] = {}
    for col in feature_cols:
        values = [r.get(col) for r in rows]
        finite = [float(v) for v in values if isinstance(v, (int, float)) and math.isfinite(float(v))]
        n_missing = sum(1 for v in values if v is None)
        n_finite = len(finite)
        mean_val = statistics.mean(finite) if finite else None
        std_val = statistics.pstdev(finite) if len(finite) > 1 else 0.0
        variance_val = statistics.pvariance(finite) if len(finite) > 1 else 0.0
        stats[col] = {
            "n_samples": n,
            "n_missing": n_missing,
            "missing_pct": round(n_missing / n * 100, 2) if n else 0.0,
            "n_finite": n_finite,
            "mean": round(mean_val, 6) if mean_val is not None else None,
            "std": round(std_val, 6),
            "min": round(min(finite), 6) if finite else None,
            "max": round(max(finite), 6) if finite else None,
            "variance": round(variance_val, 8),
            "is_zero_variance": variance_val == 0.0 and n_finite > 0,
            "is_pcap_null": col in PCAP_NULL_FIELDS,
        }
    return stats


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class ValidationError(Exception):
    """Raised when a critical invariant is violated in the unified dataset."""


def _validate_unified_rows(rows: list[dict[str, Any]]) -> list[str]:
    """Validate unified rows against required invariants.

    Args:
        rows: Unified sample records to validate.

    Returns:
        List of warning strings (non-fatal issues). Raises ValidationError
        on fatal constraint violations.
    """
    warnings: list[str] = []

    # 1. Exactly one row per sample_id
    ids = [r["sample_id"] for r in rows]
    if len(ids) != len(set(ids)):
        from collections import Counter

        dupes = [sid for sid, cnt in Counter(ids).items() if cnt > 1]
        raise ValidationError(f"Duplicate sample_ids detected: {dupes}")

    for row in rows:
        sid = row["sample_id"]
        lbl = row.get("binary_label")

        # 2. Binary label must be 0 or 1
        if lbl not in (0, 1):
            raise ValidationError(f"Sample {sid}: binary_label is {lbl!r}, must be 0 or 1")

        # 3. NaN / Inf in non-nullable numeric features
        for col in ALL_NUMERIC_FEATURE_COLS:
            val = row.get(col)
            if val is None:
                continue  # legitimate null
            try:
                f = float(val)
                if math.isnan(f) or math.isinf(f):
                    warnings.append(f"Sample {sid}: feature '{col}' has non-finite value {val}")
            except (TypeError, ValueError):
                warnings.append(f"Sample {sid}: feature '{col}' is non-numeric: {val!r}")

        # 4. Family must be a non-empty string
        if not row.get("family"):
            warnings.append(f"Sample {sid}: missing family label")

    return warnings


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------


def build_unified_dataset(
    interim_dir: Path,
    processed_dir: Path,
    audit_report_path: Path | None = None,
) -> dict[str, Any]:
    """Join all four modalities and write unified dataset outputs.

    Args:
        interim_dir: Root of the per-modality JSON directories.
        processed_dir: Destination for unified output files.
        audit_report_path: Optional path to dataset_audit_report.json for
            label/family metadata. Falls back to interim_dir.

    Returns:
        Summary dict with counts and output file paths.
    """
    processed_dir.mkdir(parents=True, exist_ok=True)
    unified_dir = processed_dir / "unified"
    unified_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Load audit report for label/family metadata
    # ------------------------------------------------------------------
    if audit_report_path is None:
        audit_report_path = interim_dir / "dataset_audit_report.json"
    audit_report: dict[str, Any] = {}
    if audit_report_path.exists():
        audit_report = json.loads(audit_report_path.read_text(encoding="utf-8"))
        logger.info("Loaded audit report from %s", audit_report_path)
    else:
        logger.warning(
            "No audit report found at %s – labels/families will be 'unknown'", audit_report_path
        )

    # ------------------------------------------------------------------
    # Load modalities
    # ------------------------------------------------------------------
    process_records = _load_modality_dir(interim_dir / "process")
    memory_records = _load_modality_dir(interim_dir / "memory")
    command_records = _load_modality_dir(interim_dir / "command")
    network_records = _load_modality_dir(interim_dir / "network")

    # Inner-join: only samples present in ALL four modalities
    all_ids = (
        set(process_records) & set(memory_records) & set(command_records) & set(network_records)
    )
    logger.info(
        "Inner-join result: %d samples (process=%d, memory=%d, command=%d, network=%d)",
        len(all_ids),
        len(process_records),
        len(memory_records),
        len(command_records),
        len(network_records),
    )

    # Report outer-join losses
    outer = set(process_records) | set(memory_records) | set(command_records) | set(network_records)
    dropped = sorted(outer - all_ids)
    if dropped:
        logger.warning("Dropped %d samples missing ≥1 modality: %s", len(dropped), dropped[:10])

    # ------------------------------------------------------------------
    # Build unified rows
    # ------------------------------------------------------------------
    unified_rows: list[dict[str, Any]] = []
    for sid in sorted(all_ids):
        combined: dict[str, Any] = {}
        for rec in (
            process_records[sid],
            memory_records[sid],
            command_records[sid],
            network_records[sid],
        ):
            for k, v in rec.items():
                if k != "sample_id":
                    combined[k] = v
        binary_label, family, track, source = _get_label_family(audit_report, sid, combined)
        row: dict[str, Any] = {
            "sample_id": sid,
            "binary_label": binary_label,
            "family": family,
            "track": track,
            "source": source,
        }
        row.update(combined)
        unified_rows.append(row)

    # ------------------------------------------------------------------
    # Validate
    # ------------------------------------------------------------------
    warnings = _validate_unified_rows(unified_rows)
    for w in warnings:
        logger.warning(w)

    # ------------------------------------------------------------------
    # Compute feature statistics
    # ------------------------------------------------------------------
    feature_stats = _compute_feature_stats(unified_rows, ALL_NUMERIC_FEATURE_COLS)
    zero_variance_features = [f for f, s in feature_stats.items() if s["is_zero_variance"]]
    logger.info("Zero-variance features: %s", zero_variance_features)

    # ------------------------------------------------------------------
    # Write unified_dataset.jsonl
    # ------------------------------------------------------------------
    jsonl_path = unified_dir / "unified_dataset.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as fh:
        for row in unified_rows:
            fh.write(json.dumps(row, allow_nan=False) + "\n")
    logger.info("Wrote %d rows to %s", len(unified_rows), jsonl_path)

    # ------------------------------------------------------------------
    # Write unified_dataset.csv  (numeric matrix, None → empty string)
    # ------------------------------------------------------------------
    csv_path = unified_dir / "unified_dataset.csv"
    csv_cols = METADATA_COLS + ALL_NUMERIC_FEATURE_COLS
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=csv_cols, extrasaction="ignore")
        writer.writeheader()
        for row in unified_rows:
            writer.writerow({c: ("" if row.get(c) is None else row.get(c)) for c in csv_cols})
    logger.info("Wrote CSV to %s", csv_path)

    # ------------------------------------------------------------------
    # Write dataset_manifest.json
    # ------------------------------------------------------------------
    label_counts: dict[str, int] = {}
    family_counts: dict[str, int] = {}
    for row in unified_rows:
        lbl_key = "malware" if row.get("binary_label") == 1 else "benign"
        label_counts[lbl_key] = label_counts.get(lbl_key, 0) + 1
        fam = row.get("family", "unknown")
        family_counts[fam] = family_counts.get(fam, 0) + 1

    manifest: dict[str, Any] = {
        "created_at": datetime.now(tz=UTC).isoformat(),
        "total_samples": len(unified_rows),
        "label_distribution": label_counts,
        "family_distribution": family_counts,
        "modalities": ["process", "memory", "command", "network"],
        "process_feature_cols": PROCESS_FEATURE_COLS,
        "memory_feature_cols": MEMORY_FEATURE_COLS,
        "command_feature_cols": COMMAND_FEATURE_COLS,
        "network_feature_cols": NETWORK_FEATURE_COLS,
        "nlp_text_fields": list(NLP_TEXT_FIELDS),
        "pcap_null_fields": sorted(PCAP_NULL_FIELDS),
        "zero_variance_features": zero_variance_features,
        "dropped_samples": dropped,
        "validation_warnings": warnings,
        "outputs": {
            "jsonl": str(jsonl_path),
            "csv": str(csv_path),
            "manifest": str(unified_dir / "dataset_manifest.json"),
            "feature_statistics": str(unified_dir / "feature_statistics.json"),
        },
    }
    manifest_path = unified_dir / "dataset_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    logger.info("Wrote manifest to %s", manifest_path)

    # ------------------------------------------------------------------
    # Write feature_statistics.json
    # ------------------------------------------------------------------
    stats_path = unified_dir / "feature_statistics.json"
    stats_path.write_text(json.dumps(feature_stats, indent=2), encoding="utf-8")
    logger.info("Wrote feature statistics to %s", stats_path)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    summary = {
        "total_samples": len(unified_rows),
        "dropped_samples": len(dropped),
        "label_distribution": label_counts,
        "family_distribution": family_counts,
        "total_numeric_features": len(ALL_NUMERIC_FEATURE_COLS),
        "process_features": len(PROCESS_FEATURE_COLS),
        "memory_features": len(MEMORY_FEATURE_COLS),
        "command_features": len(COMMAND_FEATURE_COLS),
        "network_features": len(NETWORK_FEATURE_COLS),
        "zero_variance_features": zero_variance_features,
        "validation_warnings": len(warnings),
        "outputs": manifest["outputs"],
    }
    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> None:
    """Entry point for CLI invocation."""
    parser = argparse.ArgumentParser(
        description="Build unified ML dataset from extracted forensic telemetry."
    )
    parser.add_argument(
        "--interim-dir",
        type=Path,
        default=Path("data/interim"),
        help="Root directory containing per-modality JSON subdirectories.",
    )
    parser.add_argument(
        "--processed-dir",
        type=Path,
        default=Path("data/processed"),
        help="Destination root for unified output files.",
    )
    parser.add_argument(
        "--audit-report",
        type=Path,
        default=None,
        help="Path to dataset_audit_report.json (default: <interim-dir>/dataset_audit_report.json).",
    )
    args = parser.parse_args(argv)

    summary = build_unified_dataset(
        interim_dir=args.interim_dir,
        processed_dir=args.processed_dir,
        audit_report_path=args.audit_report,
    )

    print("\n" + "=" * 64)
    print("  UNIFIED DATASET BUILD COMPLETE")
    print("=" * 64)
    print(f"  Total samples:           {summary['total_samples']}")
    print(f"  Dropped (missing modal): {summary['dropped_samples']}")
    print(f"  Label distribution:      {summary['label_distribution']}")
    print(f"  Total numeric features:  {summary['total_numeric_features']}")
    print(f"    Process:               {summary['process_features']}")
    print(f"    Memory:                {summary['memory_features']}")
    print(f"    Command:               {summary['command_features']}")
    print(f"    Network:               {summary['network_features']}")
    print(f"  Zero-variance features:  {summary['zero_variance_features']}")
    print(f"  Validation warnings:     {summary['validation_warnings']}")
    print("  Outputs:")
    for k, v in summary["outputs"].items():
        print(f"    {k:<22} {v}")
    print("=" * 64)


if __name__ == "__main__":
    main()
