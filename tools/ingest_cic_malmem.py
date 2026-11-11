"""Ingestion pipeline for full CIC-MalMem-2022 public dataset.

Converts 58,596 volatile memory forensic records into canonical
ProcessFeatures and MemoryFeatures without synthetic feature fabrication.

Output:
- data/interim/public/cic_malmem_2022/process_features.jsonl
- data/interim/public/cic_malmem_2022/memory_features.jsonl
- data/interim/public/cic_malmem_2022/provenance.jsonl
- data/interim/public/cic_malmem_2022/samples.jsonl
- data/processed/public/cic_malmem_2022_manifest.json
"""

# ruff: noqa: E402

from __future__ import annotations

import csv
import hashlib
import json
import logging
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Ensure repo root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from forensics.public.memory_adapter import MemoryAdapter
from forensics.public.process_adapter import ProcessAdapter
from forensics.public.provenance import PublicProvenance
from forensics.schemas.memory import MemoryFeatures
from forensics.schemas.process import ProcessFeatures

logger = logging.getLogger("ingest_cic_malmem")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

RAW_CSV_PATH = (
    _REPO_ROOT / "data" / "raw" / "public" / "cic_malmem_2022" / "Obfuscated-MalMem2022.csv"
)
INTERIM_DIR = _REPO_ROOT / "data" / "interim" / "public" / "cic_malmem_2022"
PROCESSED_DIR = _REPO_ROOT / "data" / "processed" / "public"
ADAPTER_VERSION = "1.0.0"

SOURCE_FIELDS = [
    "Category",
    "pslist.nproc",
    "pslist.nppid",
    "pslist.avg_threads",
    "pslist.nprocs64bit",
    "pslist.avg_handlers",
    "dlllist.ndlls",
    "dlllist.avg_dlls_per_proc",
    "handles.nhandles",
    "handles.avg_handles_per_proc",
    "handles.nport",
    "handles.nfile",
    "handles.nevent",
    "handles.ndesktop",
    "handles.nkey",
    "handles.nthread",
    "handles.ndirectory",
    "handles.nsemaphore",
    "handles.ntimer",
    "handles.nsection",
    "handles.nmutant",
    "ldrmodules.not_in_load",
    "ldrmodules.not_in_init",
    "ldrmodules.not_in_mem",
    "ldrmodules.not_in_load_avg",
    "ldrmodules.not_in_init_avg",
    "ldrmodules.not_in_mem_avg",
    "malfind.ninjections",
    "malfind.commitCharge",
    "malfind.protection",
    "malfind.uniqueInjections",
    "psxview.not_in_pslist",
    "psxview.not_in_eprocess_pool",
    "psxview.not_in_ethread_pool",
    "psxview.not_in_pspcid_list",
    "psxview.not_in_csrss_handles",
    "psxview.not_in_session",
    "psxview.not_in_deskthrd",
    "psxview.not_in_pslist_false_avg",
    "psxview.not_in_eprocess_pool_false_avg",
    "psxview.not_in_ethread_pool_false_avg",
    "psxview.not_in_pspcid_list_false_avg",
    "psxview.not_in_csrss_handles_false_avg",
    "psxview.not_in_session_false_avg",
    "psxview.not_in_deskthrd_false_avg",
    "modules.nmodules",
    "svcscan.nservices",
    "svcscan.kernel_drivers",
    "svcscan.fs_drivers",
    "svcscan.process_services",
    "svcscan.shared_process_services",
    "svcscan.interactive_process_services",
    "svcscan.nactive",
    "callbacks.ncallbacks",
    "callbacks.nanonymous",
    "callbacks.ngeneric",
    "Class",
]

MAPPED_FIELDS = {
    "process": [
        "pslist.nproc",
        "psxview.not_in_pslist",
        "psxview.not_in_csrss_handles",
        "pslist.avg_threads",
        "handles.nhandles",
        "malfind.ninjections",
        "ldrmodules.not_in_load",
    ],
    "memory": [
        "malfind.protection",
        "malfind.ninjections",
        "malfind.uniqueInjections",
        "malfind.commitCharge",
        "ldrmodules.not_in_load",
        "ldrmodules.not_in_init",
        "ldrmodules.not_in_mem",
    ],
}

UNMAPPED_FIELDS = [
    "pslist.nppid",
    "pslist.nprocs64bit",
    "pslist.avg_handlers",
    "dlllist.ndlls",
    "dlllist.avg_dlls_per_proc",
    "handles.avg_handles_per_proc",
    "handles.nport",
    "handles.nfile",
    "handles.nevent",
    "handles.ndesktop",
    "handles.nkey",
    "handles.nthread",
    "handles.ndirectory",
    "handles.nsemaphore",
    "handles.ntimer",
    "handles.nsection",
    "handles.nmutant",
    "ldrmodules.not_in_load_avg",
    "ldrmodules.not_in_init_avg",
    "ldrmodules.not_in_mem_avg",
    "psxview.not_in_eprocess_pool",
    "psxview.not_in_ethread_pool",
    "psxview.not_in_pspcid_list",
    "psxview.not_in_session",
    "psxview.not_in_deskthrd",
    "psxview.not_in_pslist_false_avg",
    "psxview.not_in_eprocess_pool_false_avg",
    "psxview.not_in_ethread_pool_false_avg",
    "psxview.not_in_pspcid_list_false_avg",
    "psxview.not_in_csrss_handles_false_avg",
    "psxview.not_in_session_false_avg",
    "psxview.not_in_deskthrd_false_avg",
    "modules.nmodules",
    "svcscan.nservices",
    "svcscan.kernel_drivers",
    "svcscan.fs_drivers",
    "svcscan.process_services",
    "svcscan.shared_process_services",
    "svcscan.interactive_process_services",
    "svcscan.nactive",
    "callbacks.ncallbacks",
    "callbacks.nanonymous",
    "callbacks.ngeneric",
]


def extract_family_and_category(raw_category: str) -> tuple[str, str]:
    """Parse malware family and category from raw Category field."""
    cat_clean = raw_category.strip()
    if cat_clean.lower() == "benign":
        return "benign", "Benign"
    parts = cat_clean.split("-")
    if len(parts) >= 2:
        return parts[1].strip(), parts[0].strip()
    return "unknown_malware", cat_clean


def ingest_cic_malmem(csv_path: Path | None = None) -> dict[str, Any]:
    """Ingest CIC-MalMem-2022 dataset and validate against ProcessFeatures and MemoryFeatures."""
    target_csv = csv_path or RAW_CSV_PATH
    if not target_csv.exists():
        raise FileNotFoundError(f"CIC-MalMem-2022 CSV not found at {target_csv}")

    logger.info(f"Starting ingestion of CIC-MalMem-2022 from {target_csv}...")

    # 1. Compute checksum of the raw CSV
    hasher = hashlib.sha256()
    with open(target_csv, "rb") as f:
        while chunk := f.read(1024 * 1024):
            hasher.update(chunk)
    raw_sha256 = hasher.hexdigest()
    logger.info(f"Source CSV SHA-256: {raw_sha256}")

    # Prepare interim directories
    INTERIM_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    proc_jsonl = INTERIM_DIR / "process_features.jsonl"
    mem_jsonl = INTERIM_DIR / "memory_features.jsonl"
    prov_jsonl = INTERIM_DIR / "provenance.jsonl"
    samples_jsonl = INTERIM_DIR / "samples.jsonl"

    valid_proc_count = 0
    valid_mem_count = 0
    class_counts: Counter[str] = Counter()
    family_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()

    proc_missing_counts: Counter[str] = Counter()
    mem_missing_counts: Counter[str] = Counter()

    total_rows = 0

    with (
        open(target_csv, encoding="utf-8", errors="replace") as in_f,
        open(proc_jsonl, "w", encoding="utf-8") as out_p,
        open(mem_jsonl, "w", encoding="utf-8") as out_m,
        open(prov_jsonl, "w", encoding="utf-8") as out_pr,
        open(samples_jsonl, "w", encoding="utf-8") as out_s,
    ):
        reader = csv.DictReader(in_f)

        for idx, row in enumerate(reader, 1):
            total_rows += 1
            raw_cat = row.get("Category", "").strip()
            raw_cls = row.get("Class", "").strip()
            family, category = extract_family_and_category(raw_cat)

            class_counts[raw_cls] += 1
            family_counts[family] += 1
            category_counts[category] += 1

            sample_id = f"MALMEM_{idx:05d}"
            binary_label = 0 if raw_cls.lower() == "benign" else 1

            # 1. Convert to ProcessFeatures
            proc_feat = ProcessAdapter.from_malmem(row, sample_id)
            # Validate schema
            ProcessFeatures.model_validate(proc_feat)
            valid_proc_count += 1
            proc_dict = proc_feat.model_dump()
            out_p.write(json.dumps(proc_dict) + "\n")

            for k, v in proc_dict.items():
                if v is None:
                    proc_missing_counts[k] += 1

            # 2. Convert to MemoryFeatures
            mem_feat = MemoryAdapter.from_malmem(row, sample_id)
            # Validate schema
            MemoryFeatures.model_validate(mem_feat)
            valid_mem_count += 1
            mem_dict = mem_feat.model_dump()
            out_m.write(json.dumps(mem_dict) + "\n")

            for k, v in mem_dict.items():
                if v is None:
                    mem_missing_counts[k] += 1

            # 3. Build Provenance Record
            prov = PublicProvenance(
                original_dataset="CIC-MalMem-2022",
                original_sample_id=raw_cat if raw_cat != "Benign" else f"Benign_row_{idx}",
                original_label=raw_cls,
                original_family=family,
                source_reference="Carrier et al., ICISSP 2022 (https://www.unb.ca/cic/datasets/malmem-2022.html)",
                available_modalities=["process", "memory"],
                mapping_method="Volatility 2/3 metrics mapped to ProcessFeatures and MemoryFeatures; zero fabrication for command/network",
                checksum=raw_sha256,
            )
            prov_dict = prov.to_dict()
            out_pr.write(json.dumps(prov_dict) + "\n")

            # 4. Joint Sample Record
            sample_record = {
                "sample_id": sample_id,
                "binary_label": binary_label,
                "class_name": raw_cls,
                "category": category,
                "family": family,
                "provenance": prov_dict,
                "process": proc_dict,
                "memory": mem_dict,
                "command": None,
                "network": None,
            }
            out_s.write(json.dumps(sample_record) + "\n")

            if idx % 10000 == 0:
                print(f"Processed {idx:,} / 58,596 samples...", end="\r")

    print()
    logger.info(f"Ingestion complete: {total_rows:,} rows converted and validated.")

    # Missingness summary
    missingness_report = {
        "process": {
            k: {
                "missing_count": proc_missing_counts[k],
                "missing_pct": round(proc_missing_counts[k] / total_rows * 100, 2),
            }
            for k in ProcessFeatures.model_fields
        },
        "memory": {
            k: {
                "missing_count": mem_missing_counts[k],
                "missing_pct": round(mem_missing_counts[k] / total_rows * 100, 2),
            }
            for k in MemoryFeatures.model_fields
        },
    }

    manifest = {
        "dataset_name": "CIC-MalMem-2022",
        "manifest_version": "1.0.0",
        "adapter_version": ADAPTER_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "source_reference": "Carrier et al., ICISSP 2022 (https://www.unb.ca/cic/datasets/malmem-2022.html)",
        "source_file": str(target_csv.relative_to(_REPO_ROOT)),
        "source_file_sha256": raw_sha256,
        "raw_sample_count": total_rows,
        "valid_process_count": valid_proc_count,
        "valid_memory_count": valid_mem_count,
        "benign_count": class_counts.get("Benign", 0),
        "malware_count": class_counts.get("Malware", 0),
        "class_distribution": dict(class_counts),
        "category_distribution": dict(category_counts),
        "family_distribution": dict(family_counts),
        "provenance_completeness": 100.0,
        "source_fields": SOURCE_FIELDS,
        "mapped_fields": MAPPED_FIELDS,
        "unmapped_fields": UNMAPPED_FIELDS,
        "missingness": missingness_report,
        "interim_artifacts": {
            "process_features": str(proc_jsonl.relative_to(_REPO_ROOT)),
            "memory_features": str(mem_jsonl.relative_to(_REPO_ROOT)),
            "provenance": str(prov_jsonl.relative_to(_REPO_ROOT)),
            "samples": str(samples_jsonl.relative_to(_REPO_ROOT)),
        },
    }

    manifest_path = PROCESSED_DIR / "cic_malmem_2022_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    logger.info(f"Manifest written to {manifest_path}")
    return manifest


if __name__ == "__main__":
    ingest_cic_malmem()
