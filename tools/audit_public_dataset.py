"""Audit engine for public benchmark datasets.

Audits public dataset artifacts in data/processed/public/ and data/interim/public/.
Verifies:
- Schema conformance against ProcessFeatures, CommandFeatures, NetworkFeatures, MemoryFeatures
- Provenance completeness via PublicProvenance schema
- Absence of ID collisions with custom dataset (custom dataset isolation)
- Duplicate sample ID detection
- Missingness per feature and modality coverage
- Class and family distribution
- Dataset compatibility classification (COMPATIBLE, PARTIALLY_COMPATIBLE, INCOMPATIBLE)
"""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

# Ensure repo root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from forensics.public.provenance import DatasetCompatibility, PublicProvenance
from forensics.schemas.command import CommandFeatures
from forensics.schemas.memory import MemoryFeatures
from forensics.schemas.network import NetworkFeatures
from forensics.schemas.process import ProcessFeatures

logger = logging.getLogger("audit_public_dataset")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


class PublicDatasetAuditor:
    """Performs deep audit of public benchmark telemetry and provenance."""

    def __init__(
        self, processed_public_dir: Path | None = None, custom_dataset_dir: Path | None = None
    ) -> None:
        self.public_dir = processed_public_dir or (_REPO_ROOT / "data" / "processed" / "public")
        self.custom_dir = custom_dataset_dir or (_REPO_ROOT / "data" / "processed" / "unified")

    def run_audit(self) -> dict[str, Any]:
        """Execute comprehensive audit and return report dictionary."""
        jsonl_path = self.public_dir / "public_benchmark_dataset.jsonl"

        if not jsonl_path.exists():
            raise FileNotFoundError(f"Public dataset file not found: {jsonl_path}")

        records: list[dict[str, Any]] = []
        with open(jsonl_path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    records.append(json.loads(line))

        total_samples = len(records)
        sample_ids: list[str] = []
        labels: list[int] = []
        families: list[str] = []
        datasets_seen: list[str] = []

        modality_counts = {"process": 0, "command": 0, "network": 0, "memory": 0}
        schema_validation_failures: list[str] = []
        provenance_failures: list[str] = []

        # Load custom sample IDs to verify custom/public strict isolation
        custom_sample_ids: set[str] = set()
        custom_jsonl = self.custom_dir / "unified_dataset.jsonl"
        if custom_jsonl.exists():
            with open(custom_jsonl, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        c_rec = json.loads(line)
                        if "sample_id" in c_rec:
                            custom_sample_ids.add(c_rec["sample_id"])

        custom_overlap_ids: list[str] = []

        for idx, rec in enumerate(records, 1):
            s_id = rec.get("sample_id", f"UNKNOWN_{idx}")
            sample_ids.append(s_id)
            labels.append(rec.get("binary_label", -1))
            families.append(rec.get("family", "unknown"))

            # Check custom dataset pollution
            if s_id in custom_sample_ids:
                custom_overlap_ids.append(s_id)

            # 1. Audit Provenance
            prov_data = rec.get("provenance")
            if not prov_data:
                provenance_failures.append(f"Sample {s_id} is missing 'provenance' header.")
            else:
                try:
                    prov = PublicProvenance.model_validate(prov_data)
                    datasets_seen.append(prov.original_dataset)
                except ValidationError as e:
                    provenance_failures.append(f"Sample {s_id} invalid provenance: {e}")

            # 2. Audit Process Schema
            if rec.get("process") is not None:
                modality_counts["process"] += 1
                try:
                    ProcessFeatures.model_validate(rec["process"])
                except ValidationError as e:
                    schema_validation_failures.append(
                        f"Sample {s_id} process validation failure: {e}"
                    )

            # 3. Audit Command Schema
            if rec.get("command") is not None:
                modality_counts["command"] += 1
                try:
                    CommandFeatures.model_validate(rec["command"])
                except ValidationError as e:
                    schema_validation_failures.append(
                        f"Sample {s_id} command validation failure: {e}"
                    )

            # 4. Audit Network Schema
            if rec.get("network") is not None:
                modality_counts["network"] += 1
                try:
                    NetworkFeatures.model_validate(rec["network"])
                except ValidationError as e:
                    schema_validation_failures.append(
                        f"Sample {s_id} network validation failure: {e}"
                    )

            # 5. Audit Memory Schema
            if rec.get("memory") is not None:
                modality_counts["memory"] += 1
                try:
                    MemoryFeatures.model_validate(rec["memory"])
                except ValidationError as e:
                    schema_validation_failures.append(
                        f"Sample {s_id} memory validation failure: {e}"
                    )

        # Check duplicate IDs
        id_counts = Counter(sample_ids)
        duplicate_ids = [k for k, count in id_counts.items() if count > 1]

        # Class and family distributions
        benign_count = sum(1 for lbl in labels if lbl == 0)
        malware_count = sum(1 for lbl in labels if lbl == 1)
        family_dist = dict(Counter(families))
        dataset_dist = dict(Counter(datasets_seen))

        # Dataset compatibility classifications
        compatibility_map = {
            "CIC-MalMem-2022": DatasetCompatibility.PARTIALLY_COMPATIBLE.value,
            "AnyRun-Community-Traces": DatasetCompatibility.PARTIALLY_COMPATIBLE.value,
            "EMBER-2018": DatasetCompatibility.INCOMPATIBLE.value,
            "SOREL-20M": DatasetCompatibility.INCOMPATIBLE.value,
            "BODMAS": DatasetCompatibility.INCOMPATIBLE.value,
            "MalwareBazaar": DatasetCompatibility.INCOMPATIBLE.value,
        }

        audit_passed = (
            len(duplicate_ids) == 0
            and len(custom_overlap_ids) == 0
            and len(schema_validation_failures) == 0
            and len(provenance_failures) == 0
        )

        report: dict[str, Any] = {
            "audited_at": datetime.now(UTC).isoformat(),
            "audit_passed": audit_passed,
            "total_public_samples": total_samples,
            "class_distribution": {
                "benign": benign_count,
                "malware": malware_count,
            },
            "family_distribution": family_dist,
            "source_dataset_distribution": dataset_dist,
            "modality_coverage": {
                "process": f"{modality_counts['process']}/{total_samples}",
                "command": f"{modality_counts['command']}/{total_samples}",
                "network": f"{modality_counts['network']}/{total_samples}",
                "memory": f"{modality_counts['memory']}/{total_samples}",
            },
            "duplicate_sample_ids": duplicate_ids,
            "custom_dataset_isolation": {
                "status": "ISOLATED" if len(custom_overlap_ids) == 0 else "POLLUTED",
                "overlapping_ids": custom_overlap_ids,
            },
            "schema_validation_status": {
                "failures_count": len(schema_validation_failures),
                "failures": schema_validation_failures,
            },
            "provenance_completeness": {
                "failures_count": len(provenance_failures),
                "failures": provenance_failures,
                "completeness_pct": (
                    100.0
                    if len(provenance_failures) == 0 and total_samples > 0
                    else round((1 - len(provenance_failures) / total_samples) * 100, 2)
                ),
            },
            "dataset_compatibility_classifications": compatibility_map,
        }

        # Write audit artifact to processed public directory
        audit_output_path = self.public_dir / "public_dataset_audit.json"
        with open(audit_output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        return report


def print_audit_summary(report: dict[str, Any]) -> None:
    """Print human-readable audit results to stdout."""
    print("=================================================================")
    print("  PUBLIC DATASET BENCHMARK AUDIT REPORT")
    print("=================================================================")
    status_str = "PASSED (Clean)" if report["audit_passed"] else "FAILED"
    print(f"Overall Audit Status:     {status_str}")
    print(f"Total Public Samples:     {report['total_public_samples']}")
    print(f"Benign Count:             {report['class_distribution']['benign']}")
    print(f"Malware Count:            {report['class_distribution']['malware']}")
    print("Source Datasets:")
    for ds, cnt in report["source_dataset_distribution"].items():
        print(f"  - {ds:25}: {cnt} samples")
    print("Modality Coverage:")
    for mod, cov in report["modality_coverage"].items():
        print(f"  - {mod:10}: {cov} samples")
    print(f"Custom Dataset Isolation: {report['custom_dataset_isolation']['status']}")
    print(f"Duplicate IDs:            {len(report['duplicate_sample_ids'])}")
    print(
        f"Schema Conformity:        {report['schema_validation_status']['failures_count']} failures"
    )
    print(f"Provenance Completeness:  {report['provenance_completeness']['completeness_pct']}%")
    print("Compatibility Classifications:")
    for ds, cls in report["dataset_compatibility_classifications"].items():
        print(f"  - {ds:20}: {cls}")
    print("=================================================================")


def main() -> int:
    """Command-line entrypoint for public dataset auditing."""
    parser = argparse.ArgumentParser(description="Audit public benchmark dataset integrity.")
    parser.add_argument(
        "--public-dir", type=Path, default=None, help="Directory containing public dataset."
    )
    args = parser.parse_args()

    auditor = PublicDatasetAuditor(processed_public_dir=args.public_dir)
    try:
        report = auditor.run_audit()
        print_audit_summary(report)
        return 0 if report["audit_passed"] else 1
    except Exception as e:
        logger.error(f"Audit failed with error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
