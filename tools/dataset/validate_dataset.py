"""CLI tool for dataset quality and data-leakage auditing."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure repository root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.dataset.validation import DatasetValidator


def main() -> None:
    dataset_path = _REPO_ROOT / "data" / "processed" / "unified" / "unified_dataset.jsonl"
    out_json = _REPO_ROOT / "evaluation" / "dataset" / "dataset_quality_report.json"
    out_md = _REPO_ROOT / "evaluation" / "dataset" / "DATASET_QUALITY_REPORT.md"

    validator = DatasetValidator(dataset_path)
    res = validator.write_report(out_json, out_md)

    print("=" * 60)
    print("DATASET VALIDATION AUDIT")
    print("=" * 60)
    print(f"Dataset File:       {res['dataset_file']}")
    print(f"Total Executions:   {res['total_executions']} (Benign: {res['benign_executions']}, Malware: {res['malware_executions']})")
    print(f"Duplicates:         {res['duplicate_execution_ids']}")
    print(f"Status:             {res['status']}")
    print(f"Reports Written to: {out_json} & {out_md}")
    print("=" * 60)


if __name__ == "__main__":
    main()
