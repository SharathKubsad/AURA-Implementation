"""Dataset audit tool for extracted custom forensic telemetry.

Inspects extracted JSON files in data/interim/ across all modalities (Process,
Memory, Command, Network), validates schemas, computes statistics, checks
numeric sanity, and classifies samples as valid, incomplete, invalid, or review.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import math
import re
import statistics
import sys
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

# Ensure repo root is on sys.path for direct execution
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from pydantic import ValidationError  # noqa: E402

from forensics.schemas.command import CommandFeatures  # noqa: E402
from forensics.schemas.memory import MemoryFeatures  # noqa: E402
from forensics.schemas.network import NetworkFeatures  # noqa: E402
from forensics.schemas.process import ProcessFeatures  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("dataset_audit")

MODALITIES = ("process", "memory", "command", "network")

# PCAP-dependent network fields that are expected to be null in host telemetry
NETWORK_UNSUPPORTED_FIELDS = (
    "dns_query_count",
    "avg_interpacket_interval_ms",
    "beacon_regularity_score",
    "total_bytes_sent",
    "total_bytes_received",
)


class AuditStatus(str, Enum):
    """Classification status for an audited sample."""

    VALID = "valid"
    INCOMPLETE = "incomplete"
    INVALID = "invalid"
    REVIEW = "review"


@dataclass
class SampleAuditResult:
    """Individual sample audit result."""

    sample_id: str
    status: AuditStatus
    family: str
    binary_label: int | None
    modalities_present: dict[str, bool] = field(default_factory=dict)
    schema_valid: dict[str, bool] = field(default_factory=dict)
    schema_errors: dict[str, list[str]] = field(default_factory=dict)
    null_fields: dict[str, list[str]] = field(default_factory=dict)
    sanity_violations: list[str] = field(default_factory=list)
    id_mismatches: list[str] = field(default_factory=list)
    raw_command_len: int | None = None
    network_null_count: int = 0
    issues: list[str] = field(default_factory=list)


def load_categories_config(categories_path: Path) -> dict[str, Any]:
    """Load categories definition from categories.json.

    Args:
        categories_path: Path to categories.json.

    Returns:
        Parsed JSON dictionary.
    """
    if not categories_path.is_file():
        logger.warning("Categories configuration file not found at %s", categories_path)
        return {"categories": []}

    with categories_path.open("r", encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)
        return data


def resolve_family_and_label(
    sample_id: str,
    categories_data: dict[str, Any],
) -> tuple[str, int | None]:
    """Derive family name and binary label from sample ID and categories config.

    Args:
        sample_id: Sample identifier (e.g. EXEC_RUN-001 or RUN-002).
        categories_data: Parsed categories.json dictionary.

    Returns:
        Tuple of (family_name, binary_label). If unknown, returns ('unknown', None).
    """
    # Check special run conventions first
    run_conventions = categories_data.get("run_conventions", {})
    for _run_key, conv in run_conventions.items():
        if isinstance(conv, dict) and conv.get("sample_id") == sample_id:
            return conv.get("family", "unknown"), conv.get("label")

    # Extract integer RUN number
    match = re.search(r"RUN-(\d+)", sample_id)
    if not match:
        return "unknown", None

    run_num = int(match.group(1))

    # RUN-001 special benign validation baseline
    if run_num == 1:
        return "benign", 0

    # Match against defined run ranges in categories
    for cat in categories_data.get("categories", []):
        run_range = cat.get("run_range")
        if run_range and len(run_range) == 2:
            start, end = run_range
            if start <= run_num <= end:
                return cat.get("family", "unknown"), cat.get("binary_label")

    return "unknown", None


def find_all_sample_ids(interim_dir: Path) -> tuple[list[str], list[str]]:
    """Discover all unique sample IDs and detect duplicates across modalities.

    Args:
        interim_dir: Root directory of data/interim.

    Returns:
        Tuple of (sorted_unique_sample_ids, list_of_duplicate_warnings).
    """
    seen_ids: set[str] = set()
    duplicates: list[str] = []

    for mod in MODALITIES:
        mod_dir = interim_dir / mod
        if not mod_dir.is_dir():
            continue

        mod_seen: set[str] = set()
        for p in mod_dir.glob("*.json"):
            sid = p.stem
            # Case-insensitive / normalized check within modality
            if sid.lower() in {x.lower() for x in mod_seen}:
                duplicates.append(f"Duplicate sample ID in {mod}: {sid}")
            mod_seen.add(sid)
            seen_ids.add(sid)

    # Sort naturally by RUN number if possible
    def _sort_key(s: str) -> tuple[int, str]:
        m = re.search(r"RUN-(\d+)", s)
        return (int(m.group(1)) if m else 999999, s)

    return sorted(seen_ids, key=_sort_key), duplicates


def audit_single_sample(
    sample_id: str,
    interim_dir: Path,
    categories_data: dict[str, Any],
) -> tuple[SampleAuditResult, dict[str, dict[str, Any]]]:
    """Audit all modality files for a single sample ID.

    Args:
        sample_id: Sample identifier (e.g. EXEC_RUN-001).
        interim_dir: Root directory of data/interim.
        categories_data: Parsed categories.json data.

    Returns:
        Tuple of (SampleAuditResult, parsed_modality_data_dict).
    """
    family, binary_label = resolve_family_and_label(sample_id, categories_data)

    modalities_present: dict[str, bool] = {}
    schema_valid: dict[str, bool] = {}
    schema_errors: dict[str, list[str]] = {}
    null_fields: dict[str, list[str]] = {}
    sanity_violations: list[str] = []
    id_mismatches: list[str] = []
    issues: list[str] = []

    parsed_data: dict[str, dict[str, Any]] = {}
    raw_command_len: int | None = None
    network_null_count: int = 0

    for mod in MODALITIES:
        file_path = interim_dir / mod / f"{sample_id}.json"
        if not file_path.is_file():
            modalities_present[mod] = False
            schema_valid[mod] = False
            continue

        modalities_present[mod] = True

        # 1. Parse JSON
        try:
            with file_path.open("r", encoding="utf-8") as fp:
                d = json.load(fp)
                parsed_data[mod] = d
        except Exception as err:
            schema_valid[mod] = False
            schema_errors[mod] = [f"JSON parse error: {err}"]
            sanity_violations.append(f"{mod}: Invalid JSON syntax ({err})")
            continue

        # 2. Check cross-modality sample_id consistency
        mod_sample_id = d.get("sample_id")
        if mod_sample_id != sample_id:
            mismatch_msg = (
                f"{mod} sample_id mismatch: file is '{sample_id}' but content has '{mod_sample_id}'"
            )
            id_mismatches.append(mismatch_msg)

        # 3. Schema validation via Pydantic
        s_errors: list[str] = []
        try:
            if mod == "process":
                ProcessFeatures.model_validate(d)
            elif mod == "memory":
                MemoryFeatures.model_validate(d)
            elif mod == "command":
                cmd_obj = CommandFeatures.model_validate(d)
                raw_command_len = len(cmd_obj.raw_command_text)
                if not cmd_obj.raw_command_text.strip() and binary_label != 0:
                    issues.append(
                        "command: raw_command_text is empty (in-memory execution with no command telemetry)"
                    )
            elif mod == "network":
                NetworkFeatures.model_validate(d)
                # Count null fields in network
                network_null_count = sum(1 for k in NETWORK_UNSUPPORTED_FIELDS if d.get(k) is None)
            schema_valid[mod] = True
        except ValidationError as val_err:
            schema_valid[mod] = False
            for error in val_err.errors():
                loc = ".".join(str(loc_item) for loc_item in error.get("loc", []))
                msg = f"{loc}: {error.get('msg')}"
                s_errors.append(msg)
            schema_errors[mod] = s_errors

        # 4. Null field tracking
        null_keys = [k for k, v in d.items() if v is None]
        if null_keys:
            null_fields[mod] = null_keys

        # 5. Numeric sanity checks (NaN, Inf, negative values where ge=0)
        for key, val in d.items():
            if isinstance(val, int | float) and not isinstance(val, bool):
                if math.isnan(val):
                    sanity_violations.append(f"{mod}.{key} is NaN")
                elif math.isinf(val):
                    sanity_violations.append(f"{mod}.{key} is Infinity")
                elif val < 0 and key not in ("label", "binary_label", "family_label"):
                    # Check if schema specifies non-negative (all numeric features in our schemas are ge=0)
                    sanity_violations.append(f"{mod}.{key} has impossible negative value: {val}")

    # Record missing modalities in issues
    missing_mods = [m for m in MODALITIES if not modalities_present.get(m, False)]
    if missing_mods:
        issues.append(f"Missing modalities: {', '.join(missing_mods)}")

    # Add schema errors to issues
    for mod, errs in schema_errors.items():
        issues.append(f"{mod} schema errors: {'; '.join(errs[:3])}")

    # Add sanity violations to issues
    if sanity_violations:
        issues.extend(sanity_violations)

    # Add ID mismatches to issues
    if id_mismatches:
        issues.extend(id_mismatches)

    # Check for unknown family
    if family == "unknown" or binary_label is None:
        issues.append("Unrecognized family or binary label (outside configured categories)")

    # 6. Determine final classification status: valid, incomplete, invalid, review
    has_all_modalities = all(modalities_present.get(m, False) for m in MODALITIES)
    has_schema_error = any(
        not schema_valid.get(m, False) for m in MODALITIES if modalities_present.get(m, False)
    )
    has_sanity_error = len(sanity_violations) > 0

    if has_schema_error or has_sanity_error:
        status = AuditStatus.INVALID
    elif (
        len(id_mismatches) > 0
        or (modalities_present.get("command", False) and raw_command_len == 0 and binary_label != 0)
        or family == "unknown"
        or binary_label is None
    ):
        status = AuditStatus.REVIEW
    elif not has_all_modalities:
        status = AuditStatus.INCOMPLETE
    else:
        status = AuditStatus.VALID

    result = SampleAuditResult(
        sample_id=sample_id,
        status=status,
        family=family,
        binary_label=binary_label,
        modalities_present=modalities_present,
        schema_valid=schema_valid,
        schema_errors=schema_errors,
        null_fields=null_fields,
        sanity_violations=sanity_violations,
        id_mismatches=id_mismatches,
        raw_command_len=raw_command_len,
        network_null_count=network_null_count,
        issues=issues,
    )
    return result, parsed_data


@dataclass
class DatasetAuditReport:
    """Full dataset audit report structure."""

    audit_timestamp: str
    interim_directory: str
    summary: dict[str, Any]
    samples: dict[str, dict[str, Any]]


def audit_custom_dataset(
    interim_dir: Path,
    categories_path: Path,
) -> DatasetAuditReport:
    """Run full audit across extracted custom dataset in interim directory.

    Args:
        interim_dir: Path to data/interim.
        categories_path: Path to data/raw/custom/categories.json.

    Returns:
        DatasetAuditReport containing full summary and per-sample details.
    """
    categories_data = load_categories_config(categories_path)
    sample_ids, duplicate_warnings = find_all_sample_ids(interim_dir)

    sample_results: list[SampleAuditResult] = []
    all_parsed_data: dict[str, dict[str, dict[str, Any]]] = {}

    for sid in sample_ids:
        res, pdata = audit_single_sample(sid, interim_dir, categories_data)
        sample_results.append(res)
        all_parsed_data[sid] = pdata

    # 1. Total sample count
    total_samples = len(sample_results)

    # 2. Status counts
    status_counts: dict[str, int] = {
        AuditStatus.VALID.value: 0,
        AuditStatus.INCOMPLETE.value: 0,
        AuditStatus.INVALID.value: 0,
        AuditStatus.REVIEW.value: 0,
    }
    for r in sample_results:
        status_counts[r.status.value] += 1

    # 3. Family distribution
    family_distribution: dict[str, int] = {}
    for r in sample_results:
        family_distribution[r.family] = family_distribution.get(r.family, 0) + 1

    # 4. Binary label distribution
    binary_label_dist: dict[str, int] = {"benign": 0, "malware": 0, "unknown": 0}
    for r in sample_results:
        if r.binary_label == 0:
            binary_label_dist["benign"] += 1
        elif r.binary_label == 1:
            binary_label_dist["malware"] += 1
        else:
            binary_label_dist["unknown"] += 1

    # 5. Modality availability & schema validation
    modality_availability: dict[str, dict[str, Any]] = {}
    schema_validation_stats: dict[str, dict[str, int]] = {}
    for mod in MODALITIES:
        present_cnt = sum(1 for r in sample_results if r.modalities_present.get(mod, False))
        valid_cnt = sum(1 for r in sample_results if r.schema_valid.get(mod, False))
        pct = (present_cnt / total_samples * 100.0) if total_samples > 0 else 0.0
        modality_availability[mod] = {
            "count": present_cnt,
            "percentage": round(pct, 2),
        }
        schema_validation_stats[mod] = {
            "present": present_cnt,
            "valid": valid_cnt,
            "invalid": present_cnt - valid_cnt,
        }

    all_four_count = sum(
        1 for r in sample_results if all(r.modalities_present.get(m, False) for m in MODALITIES)
    )
    modality_availability["all_four"] = {
        "count": all_four_count,
        "percentage": round(
            (all_four_count / total_samples * 100.0) if total_samples > 0 else 0.0, 2
        ),
    }

    # 6. Process and Memory specific availability
    proc_mem_availability = {
        "process_present": modality_availability["process"]["count"],
        "memory_present": modality_availability["memory"]["count"],
        "both_present": sum(
            1
            for r in sample_results
            if r.modalities_present.get("process", False)
            and r.modalities_present.get("memory", False)
        ),
        "missing_both": sum(
            1
            for r in sample_results
            if not r.modalities_present.get("process", False)
            and not r.modalities_present.get("memory", False)
        ),
    }

    # 7. Missing / null fields per modality across all samples
    missing_null_fields: dict[str, dict[str, int]] = {m: {} for m in MODALITIES}
    for r in sample_results:
        for mod, nfields in r.null_fields.items():
            for nf in nfields:
                missing_null_fields[mod][nf] = missing_null_fields[mod].get(nf, 0) + 1

    # 8. Command raw text statistics
    cmd_lengths = [r.raw_command_len for r in sample_results if r.raw_command_len is not None]
    cmd_empty_count = sum(1 for length in cmd_lengths if length == 0)
    command_text_stats: dict[str, Any] = {
        "available_count": len(cmd_lengths),
        "empty_count": cmd_empty_count,
        "min_length": min(cmd_lengths) if cmd_lengths else None,
        "max_length": max(cmd_lengths) if cmd_lengths else None,
        "mean_length": round(statistics.mean(cmd_lengths), 2) if cmd_lengths else None,
        "median_length": round(statistics.median(cmd_lengths), 2) if cmd_lengths else None,
    }

    # 9. Network unsupported / null feature statistics
    network_present_count = modality_availability["network"]["count"]
    network_unsupported_stats: dict[str, dict[str, Any]] = {}
    for nf in NETWORK_UNSUPPORTED_FIELDS:
        null_cnt = missing_null_fields["network"].get(nf, 0)
        pct = (null_cnt / network_present_count * 100.0) if network_present_count > 0 else 0.0
        network_unsupported_stats[nf] = {
            "null_count": null_cnt,
            "present_count": network_present_count - null_cnt,
            "null_percentage": round(pct, 2),
        }

    # 10. Numeric sanity checks & constant feature detection
    total_nans = sum(1 for r in sample_results for v in r.sanity_violations if "NaN" in v)
    total_infs = sum(1 for r in sample_results for v in r.sanity_violations if "Infinity" in v)
    total_negative_viol = sum(
        1 for r in sample_results for v in r.sanity_violations if "negative value" in v
    )

    constant_features: list[dict[str, Any]] = []
    # Evaluate variance / constant features across present samples per modality
    for mod in MODALITIES:
        # Collect observed values per numeric key
        val_map: dict[str, list[Any]] = {}
        for _sid, pdata in all_parsed_data.items():
            if mod in pdata:
                for k, v in pdata[mod].items():
                    if k in ("sample_id", "raw_command_text"):
                        continue
                    if v is not None and isinstance(v, int | float) and not isinstance(v, bool):
                        val_map.setdefault(k, []).append(v)

        for feat_name, vals in val_map.items():
            if len(vals) >= 2:
                unique_vals = set(vals)
                if len(unique_vals) == 1:
                    constant_features.append(
                        {
                            "modality": mod,
                            "feature": feat_name,
                            "constant_value": next(iter(unique_vals)),
                            "samples_observed": len(vals),
                        }
                    )

    # 11. Cross-modality ID mismatches and review list
    id_mismatches = [
        {"sample_id": r.sample_id, "mismatches": r.id_mismatches}
        for r in sample_results
        if r.id_mismatches
    ]
    samples_for_review = [
        {"sample_id": r.sample_id, "issues": r.issues}
        for r in sample_results
        if r.status == AuditStatus.REVIEW
    ]
    invalid_samples = [
        {"sample_id": r.sample_id, "issues": r.issues}
        for r in sample_results
        if r.status == AuditStatus.INVALID
    ]
    incomplete_samples = [r.sample_id for r in sample_results if r.status == AuditStatus.INCOMPLETE]

    summary: dict[str, Any] = {
        "total_samples": total_samples,
        "status_counts": status_counts,
        "unique_sample_ids": len(sample_ids),
        "duplicate_sample_warnings": duplicate_warnings,
        "binary_label_distribution": binary_label_dist,
        "family_distribution": family_distribution,
        "modality_availability": modality_availability,
        "process_memory_availability": proc_mem_availability,
        "schema_validation": schema_validation_stats,
        "missing_null_fields_per_modality": missing_null_fields,
        "command_raw_text_stats": command_text_stats,
        "network_unsupported_stats": network_unsupported_stats,
        "numeric_sanity": {
            "nan_count": total_nans,
            "inf_count": total_infs,
            "negative_impossible_count": total_negative_viol,
            "constant_features": constant_features,
        },
        "cross_modality_id_mismatches": id_mismatches,
        "samples_for_review": samples_for_review,
        "invalid_samples": invalid_samples,
        "incomplete_samples": incomplete_samples,
    }

    samples_dict: dict[str, dict[str, Any]] = {
        r.sample_id: {
            "status": r.status.value,
            "family": r.family,
            "binary_label": r.binary_label,
            "modalities_present": r.modalities_present,
            "schema_valid": r.schema_valid,
            "schema_errors": r.schema_errors,
            "null_fields": r.null_fields,
            "sanity_violations": r.sanity_violations,
            "id_mismatches": r.id_mismatches,
            "raw_command_len": r.raw_command_len,
            "network_null_count": r.network_null_count,
            "issues": r.issues,
        }
        for r in sample_results
    }

    report = DatasetAuditReport(
        audit_timestamp=datetime.now(UTC).isoformat(),
        interim_directory=str(interim_dir),
        summary=summary,
        samples=samples_dict,
    )
    return report


def save_audit_reports(
    report: DatasetAuditReport,
    json_path: Path,
    csv_path: Path,
) -> None:
    """Write audit report to JSON and CSV artifacts.

    Args:
        report: Completed DatasetAuditReport instance.
        json_path: Destination path for dataset_audit_report.json.
        csv_path: Destination path for dataset_audit_report.csv.
    """
    json_path.parent.mkdir(parents=True, exist_ok=True)
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    # 1. Write JSON report
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(asdict(report), f, indent=2)
    logger.info("Saved JSON audit report to %s", json_path)

    # 2. Write CSV report
    fieldnames = [
        "sample_id",
        "status",
        "family",
        "binary_label",
        "has_process",
        "has_memory",
        "has_command",
        "has_network",
        "process_valid",
        "memory_valid",
        "command_valid",
        "network_valid",
        "raw_command_len",
        "network_null_count",
        "issues",
    ]

    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for sid, sdata in report.samples.items():
            mods = sdata.get("modalities_present", {})
            s_val = sdata.get("schema_valid", {})
            issues_str = "; ".join(sdata.get("issues", []))
            writer.writerow(
                {
                    "sample_id": sid,
                    "status": sdata.get("status"),
                    "family": sdata.get("family"),
                    "binary_label": sdata.get("binary_label"),
                    "has_process": mods.get("process", False),
                    "has_memory": mods.get("memory", False),
                    "has_command": mods.get("command", False),
                    "has_network": mods.get("network", False),
                    "process_valid": s_val.get("process", False),
                    "memory_valid": s_val.get("memory", False),
                    "command_valid": s_val.get("command", False),
                    "network_valid": s_val.get("network", False),
                    "raw_command_len": sdata.get("raw_command_len", ""),
                    "network_null_count": sdata.get("network_null_count", 0),
                    "issues": issues_str,
                }
            )
    logger.info("Saved CSV audit report to %s", csv_path)


def print_terminal_summary(report: DatasetAuditReport) -> None:
    """Print clean and comprehensive summary to the terminal.

    Args:
        report: Completed DatasetAuditReport instance.
    """
    sum_data = report.summary
    total = sum_data["total_samples"]
    sc = sum_data["status_counts"]
    bl = sum_data["binary_label_distribution"]
    ma = sum_data["modality_availability"]
    cmd_st = sum_data["command_raw_text_stats"]
    san = sum_data["numeric_sanity"]

    sep = "=" * 64
    print(f"\n{sep}")
    print("           CUSTOM DATASET FORENSIC AUDIT REPORT")
    print(f"{sep}")
    print(f"Total Discovered Samples: {total}")
    print(
        f"Status Breakdown:         Valid: {sc['valid']} | Incomplete: {sc['incomplete']} | "
        f"Review: {sc['review']} | Invalid: {sc['invalid']}"
    )
    b_pct = (bl["benign"] / total * 100.0) if total else 0.0
    m_pct = (bl["malware"] / total * 100.0) if total else 0.0
    print(
        f"Binary Labels:            Malware: {bl['malware']} ({m_pct:.1f}%) | "
        f"Benign: {bl['benign']} ({b_pct:.1f}%)"
    )
    print(
        f"Unique Sample IDs:        {sum_data['unique_sample_ids']} "
        f"(Duplicate Warnings: {len(sum_data['duplicate_sample_warnings'])})"
    )

    print("\nModality Coverage & Schema Validity:")
    for m in MODALITIES:
        m_info = ma[m]
        v_info = sum_data["schema_validation"][m]
        print(
            f"  - {m.capitalize():10} {m_info['count']:2d}/{total} ({m_info['percentage']:5.1f}%) "
            f"| Schema Valid: {v_info['valid']}/{m_info['count']}"
        )
    print(
        f"  - {'All 4 Modalities':10} {ma['all_four']['count']:2d}/{total} ({ma['all_four']['percentage']:5.1f}%)"
    )

    print("\nCommand Telemetry (NLP Text):")
    print(
        f"  - Raw Text Available:   {cmd_st['available_count']}/{total} "
        f"({cmd_st['empty_count']} empty)"
    )
    if cmd_st["min_length"] is not None:
        print(
            f"  - String Length:        min={cmd_st['min_length']}, max={cmd_st['max_length']}, "
            f"mean={cmd_st['mean_length']}, median={cmd_st['median_length']}"
        )

    print("\nNetwork Unsupported / Null Features (PCAP-dependent):")
    for field_name, stats in sum_data["network_unsupported_stats"].items():
        print(
            f"  - {field_name:28} {stats['null_count']:2d}/{ma['network']['count']} null "
            f"({stats['null_percentage']:5.1f}%)"
        )

    print("\nNumeric Sanity Checks:")
    print(
        f"  - NaN: {san['nan_count']} | Inf: {san['inf_count']} | "
        f"Negative Violations: {san['negative_impossible_count']}"
    )
    const_feats = san["constant_features"]
    print(f"  - Suspiciously Constant Features: {len(const_feats)} detected")
    for cf in const_feats[:6]:
        print(
            f"      [{cf['modality']}] {cf['feature']} = {cf['constant_value']} "
            f"({cf['samples_observed']} samples)"
        )
    if len(const_feats) > 6:
        print(f"      ... and {len(const_feats) - 6} more")

    print("\nSamples Grouped by Family:")
    for fam, cnt in sorted(sum_data["family_distribution"].items(), key=lambda x: (-x[1], x[0])):
        print(f"  - {fam:28} {cnt:2d}")

    print("\nIntegrity & Review Flags:")
    print(f"  - Cross-Modality ID Mismatches: {len(sum_data['cross_modality_id_mismatches'])}")
    print(f"  - Samples Requiring Review:     {len(sum_data['samples_for_review'])}")
    for rev in sum_data["samples_for_review"][:5]:
        print(f"      {rev['sample_id']}: {', '.join(rev['issues'])}")
    if len(sum_data["samples_for_review"]) > 5:
        print(f"      ... and {len(sum_data['samples_for_review']) - 5} more")

    print(f"{sep}\n")


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for dataset audit tool.

    Args:
        argv: Optional command-line arguments.

    Returns:
        Exit code (0 for success).
    """
    parser = argparse.ArgumentParser(
        description="Dataset audit tool for extracted custom fileless malware forensic telemetry"
    )
    parser.add_argument(
        "--interim-dir",
        type=Path,
        default=Path("data/interim"),
        help="Root directory containing interim modality JSON folders (default: data/interim)",
    )
    parser.add_argument(
        "--categories",
        type=Path,
        default=Path("data/raw/custom/categories.json"),
        help="Path to categories.json configuration (default: data/raw/custom/categories.json)",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=Path("data/interim/dataset_audit_report.json"),
        help="Path to write JSON audit report (default: data/interim/dataset_audit_report.json)",
    )
    parser.add_argument(
        "--csv-out",
        type=Path,
        default=Path("data/interim/dataset_audit_report.csv"),
        help="Path to write CSV audit report (default: data/interim/dataset_audit_report.csv)",
    )

    args = parser.parse_args(argv)

    logger.info("Starting forensic dataset audit on %s ...", args.interim_dir)
    report = audit_custom_dataset(args.interim_dir, args.categories)
    save_audit_reports(report, args.json_out, args.csv_out)
    print_terminal_summary(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
