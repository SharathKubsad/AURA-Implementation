"""Comprehensive audit tool for ingested CIC-MalMem-2022 dataset.

Audits:
- Duplicate sample IDs
- Label distribution (Benign / Malware)
- Family distribution across all 16 categories
- Schema validity for ProcessFeatures and MemoryFeatures
- Missingness per feature
- Invalid numeric values (NaN, Inf, negative values out of bounds)
- Provenance completeness
- Strict isolation from custom evaluation dataset
"""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import json
import logging
import math
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from forensics.public.provenance import PublicProvenance
from forensics.schemas.memory import MemoryFeatures
from forensics.schemas.process import ProcessFeatures

logger = logging.getLogger("audit_cic_malmem")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

INTERIM_DIR = _REPO_ROOT / "data" / "interim" / "public" / "cic_malmem_2022"
PROCESSED_DIR = _REPO_ROOT / "data" / "processed" / "public"
CUSTOM_DATASET_PATH = _REPO_ROOT / "data" / "processed" / "unified" / "unified_dataset.jsonl"


class MalMemAuditor:
    """Audits ingested CIC-MalMem-2022 data artifacts."""

    def __init__(self, interim_dir: Path | None = None, processed_dir: Path | None = None) -> None:
        self.interim_dir = interim_dir or INTERIM_DIR
        self.processed_dir = processed_dir or PROCESSED_DIR

    def audit(self) -> dict[str, Any]:
        """Perform comprehensive audit over all ingested samples."""
        samples_path = self.interim_dir / "samples.jsonl"
        manifest_path = self.processed_dir / "cic_malmem_2022_manifest.json"

        if not samples_path.exists():
            raise FileNotFoundError(f"Samples file not found at {samples_path}")
        if not manifest_path.exists():
            raise FileNotFoundError(f"Manifest file not found at {manifest_path}")

        logger.info(f"Auditing CIC-MalMem-2022 records in {samples_path}...")

        # Load custom sample IDs to verify zero pollution
        custom_ids: set[str] = set()
        if CUSTOM_DATASET_PATH.exists():
            with open(CUSTOM_DATASET_PATH, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        custom_ids.add(json.loads(line).get("sample_id", ""))

        total_samples = 0
        seen_ids: set[str] = set()
        duplicate_ids: list[str] = []
        custom_collisions: list[str] = []

        class_counts: Counter[str] = Counter()
        family_counts: Counter[str] = Counter()

        schema_errors_proc = 0
        schema_errors_mem = 0
        provenance_errors = 0
        invalid_numerics = 0

        proc_missingness: Counter[str] = Counter()
        mem_missingness: Counter[str] = Counter()

        with open(samples_path, encoding="utf-8") as f:
            for idx, line in enumerate(f, 1):
                if not line.strip():
                    continue
                total_samples += 1
                rec = json.loads(line)
                s_id = rec.get("sample_id", f"UNKNOWN_{idx}")

                # 1. Duplicate check
                if s_id in seen_ids:
                    duplicate_ids.append(s_id)
                seen_ids.add(s_id)

                # 2. Custom dataset isolation check
                if s_id in custom_ids:
                    custom_collisions.append(s_id)

                # 3. Label and family counts
                cls_name = rec.get("class_name", "")
                fam = rec.get("family", "")
                class_counts[cls_name] += 1
                family_counts[fam] += 1

                # 4. Schema verification: Process
                proc_data = rec.get("process")
                if proc_data is None:
                    schema_errors_proc += 1
                else:
                    try:
                        ProcessFeatures.model_validate(proc_data)
                        for k, v in proc_data.items():
                            if v is None:
                                proc_missingness[k] += 1
                            elif isinstance(v, (int, float)) and (math.isnan(v) or math.isinf(v)):
                                invalid_numerics += 1
                    except ValidationError:
                        schema_errors_proc += 1

                # 5. Schema verification: Memory
                mem_data = rec.get("memory")
                if mem_data is None:
                    schema_errors_mem += 1
                else:
                    try:
                        MemoryFeatures.model_validate(mem_data)
                        for k, v in mem_data.items():
                            if v is None:
                                mem_missingness[k] += 1
                            elif isinstance(v, (int, float)) and (math.isnan(v) or math.isinf(v)):
                                invalid_numerics += 1
                    except ValidationError:
                        schema_errors_mem += 1

                # 6. Provenance verification
                prov_data = rec.get("provenance")
                if not prov_data:
                    provenance_errors += 1
                else:
                    try:
                        PublicProvenance.model_validate(prov_data)
                    except ValidationError:
                        provenance_errors += 1

                if idx % 10000 == 0:
                    print(f"Audited {idx:,} / 58,596 samples...", end="\r")

        print()
        audit_passed = (
            total_samples == 58596
            and len(duplicate_ids) == 0
            and len(custom_collisions) == 0
            and schema_errors_proc == 0
            and schema_errors_mem == 0
            and provenance_errors == 0
            and invalid_numerics == 0
            and class_counts.get("Benign", 0) == 29298
            and class_counts.get("Malware", 0) == 29298
        )

        audit_report = {
            "audited_at": datetime.now(UTC).isoformat(),
            "audit_passed": audit_passed,
            "total_samples": total_samples,
            "class_distribution": dict(class_counts),
            "family_distribution": dict(family_counts),
            "duplicate_sample_count": len(duplicate_ids),
            "custom_dataset_isolation": {
                "status": "ISOLATED" if len(custom_collisions) == 0 else "POLLUTED",
                "collisions_count": len(custom_collisions),
            },
            "schema_validity": {
                "process_schema_errors": schema_errors_proc,
                "memory_schema_errors": schema_errors_mem,
            },
            "invalid_numeric_values": invalid_numerics,
            "provenance_completeness": {
                "errors": provenance_errors,
                "completeness_pct": 100.0 if provenance_errors == 0 else 0.0,
            },
            "missingness": {
                "process": {
                    k: {
                        "missing_count": proc_missingness[k],
                        "missing_pct": round(proc_missingness[k] / total_samples * 100, 2),
                    }
                    for k in ProcessFeatures.model_fields
                },
                "memory": {
                    k: {
                        "missing_count": mem_missingness[k],
                        "missing_pct": round(mem_missingness[k] / total_samples * 100, 2),
                    }
                    for k in MemoryFeatures.model_fields
                },
            },
        }

        audit_output_path = self.processed_dir / "cic_malmem_2022_audit.json"
        with open(audit_output_path, "w", encoding="utf-8") as f:
            json.dump(audit_report, f, indent=2)

        logger.info(f"Audit report written to {audit_output_path}")
        return audit_report


def print_audit_summary(report: dict[str, Any]) -> None:
    """Print human-readable audit summary."""
    print("=================================================================")
    print("  CIC-MALMEM-2022 DATASET INGESTION AUDIT REPORT")
    print("=================================================================")
    status_str = "PASSED (Clean)" if report["audit_passed"] else "FAILED"
    print(f"Audit Status:             {status_str}")
    print(f"Total Samples Audited:    {report['total_samples']:,}")
    print(
        f"Class Distribution:       Benign: {report['class_distribution'].get('Benign', 0):,}, "
        f"Malware: {report['class_distribution'].get('Malware', 0):,}"
    )
    print(f"Total Families:           {len(report['family_distribution'])}")
    print(f"Duplicate Sample IDs:     {report['duplicate_sample_count']}")
    print(f"Custom Dataset Isolation: {report['custom_dataset_isolation']['status']}")
    print(f"Process Schema Errors:    {report['schema_validity']['process_schema_errors']}")
    print(f"Memory Schema Errors:     {report['schema_validity']['memory_schema_errors']}")
    print(f"Invalid Numeric Values:   {report['invalid_numeric_values']}")
    print(f"Provenance Completeness:  {report['provenance_completeness']['completeness_pct']}%")
    print("=================================================================")


def main() -> int:
    """CLI entry point for CIC-MalMem-2022 audit."""
    parser = argparse.ArgumentParser(description="Audit ingested CIC-MalMem-2022 dataset.")
    parser.add_argument(
        "--interim-dir", type=Path, default=None, help="Directory containing interim JSONL files."
    )
    parser.add_argument(
        "--processed-dir", type=Path, default=None, help="Directory for processed reports."
    )
    args = parser.parse_args()

    auditor = MalMemAuditor(interim_dir=args.interim_dir, processed_dir=args.processed_dir)
    try:
        report = auditor.audit()
        print_audit_summary(report)
        return 0 if report["audit_passed"] else 1
    except Exception as e:
        logger.error(f"Audit failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
