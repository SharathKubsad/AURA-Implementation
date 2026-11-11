"""Safely archive obsolete derived ML artifacts to archive/old_ml_pipeline/.

Preserves all raw forensic evidence (Dataset/ is NEVER modified or moved).
Moves old derived feature datasets, trained models, and evaluation outputs.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ARCHIVE_ROOT = REPO_ROOT / "archive" / "old_ml_pipeline"

# Targets to archive: (relative_source_path, relative_archive_subpath)
TARGETS = [
    # Old derived datasets in data/processed/
    ("data/processed/process_dataset.jsonl", "data/processed/process_dataset.jsonl"),
    ("data/processed/command_dataset.jsonl", "data/processed/command_dataset.jsonl"),
    ("data/processed/network_dataset.jsonl", "data/processed/network_dataset.jsonl"),
    ("data/processed/memory_dataset.jsonl", "data/processed/memory_dataset.jsonl"),
    ("data/processed/process_rich_v3_candidate.jsonl", "data/processed/process_rich_v3_candidate.jsonl"),
    ("data/processed/command_rich_v3_candidate.jsonl", "data/processed/command_rich_v3_candidate.jsonl"),
    ("data/processed/network_rich_v3_candidate.jsonl", "data/processed/network_rich_v3_candidate.jsonl"),
    ("data/processed/memory_rich_v3_candidate.jsonl", "data/processed/memory_rich_v3_candidate.jsonl"),
    ("data/processed/benchmark_dataset.csv", "data/processed/benchmark_dataset.csv"),
    ("data/processed/benchmark_dataset.parquet", "data/processed/benchmark_dataset.parquet"),
    
    # Old trained models in models/artifacts/
    ("models/artifacts", "models/artifacts"),
    ("models/process/artifacts", "models/process/artifacts"),
    ("models/memory/artifacts", "models/memory/artifacts"),
    ("models/network/artifacts", "models/network/artifacts"),
    ("models/command/artifacts", "models/command/artifacts"),
    ("models/multiclass/artifacts", "models/multiclass/artifacts"),
    
    # Old evaluation artifacts
    ("evaluation/binary", "evaluation/binary"),
    ("evaluation/custom_audit", "evaluation/custom_audit"),
    ("evaluation/generalization/artifacts", "evaluation/generalization/artifacts"),
    ("evaluation/robustness/artifacts", "evaluation/robustness/artifacts"),
    ("evaluation/xai/artifacts", "evaluation/xai/artifacts"),
]

def main() -> None:
    ARCHIVE_ROOT.mkdir(parents=True, exist_ok=True)
    archived_items = []
    
    for src_rel, dst_rel in TARGETS:
        src = REPO_ROOT / src_rel
        dst = ARCHIVE_ROOT / dst_rel
        
        if not src.exists():
            continue
            
        dst.parent.mkdir(parents=True, exist_ok=True)
        
        if src.is_dir():
            if dst.exists():
                shutil.rmtree(dst)
            shutil.move(str(src), str(dst))
            archived_items.append(f"DIR:  {src_rel} -> {dst.relative_to(REPO_ROOT)}")
        elif src.is_file():
            if dst.exists():
                dst.unlink()
            shutil.move(str(src), str(dst))
            archived_items.append(f"FILE: {src_rel} -> {dst.relative_to(REPO_ROOT)}")
            
    print(f"Successfully archived {len(archived_items)} items to archive/old_ml_pipeline:")
    for item in archived_items:
        print(f"  {item}")

if __name__ == "__main__":
    main()
