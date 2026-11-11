import os
import json
import csv
from pathlib import Path
from collections import defaultdict

dataset_root = Path("Dataset").resolve()

print(f"Inventorying: {dataset_root}")

# We will collect:
# 1. Total directories and files
# 2. Per-category directory tree
# 3. All runs and their evidence items
# 4. Classification: RAW_SOURCE_EVIDENCE, DERIVED_FORENSIC_OUTPUT, EXTRACTED_FEATURES, METADATA
# 5. Volatility plugins presence per run
# 6. Command/network evidence presence per run

file_records = []
runs_dict = defaultdict(lambda: {
    "category": "",
    "source_archive": "",
    "evidence_files": [],
    "volatility_files": [],
    "process_features": None,
    "memory_features": None,
    "metadata": None,
    "manifest": None
})

for root, dirs, files in os.walk(dataset_root):
    rel_root = Path(root).relative_to(dataset_root)
    parts = rel_root.parts
    if not parts:
        continue
    category = parts[0]
    
    for f in files:
        full_path = Path(root) / f
        rel_path = full_path.relative_to(dataset_root)
        size_bytes = full_path.stat().st_size
        suffix = full_path.suffix.lower()
        
        # Classification
        classification = "UNKNOWN"
        run_id = None
        
        if "source_evidence" in parts:
            classification = "RAW_SOURCE_EVIDENCE"
            # find which RUN
            idx = parts.index("source_evidence")
            if len(parts) > idx + 1:
                run_id = parts[idx + 1]
        elif "volatility" in parts:
            classification = "DERIVED_FORENSIC_OUTPUT"
            idx = parts.index("volatility")
            if len(parts) > idx + 1:
                run_id = parts[idx + 1]
        elif parts[-1] in ("process", "memory"):
            classification = "EXTRACTED_FEATURES"
            if f.endswith(".json"):
                run_id = Path(f).stem
        elif "metadata" in parts or f in ("manifest.json", "batch_summary.csv", "checksums.sha256"):
            classification = "METADATA"
            if f.endswith(".json") and f.startswith("RUN-"):
                run_id = Path(f).stem
        
        # If run_id found, record in runs_dict
        if run_id:
            runs_dict[run_id]["category"] = category
            runs_dict[run_id]["source_archive"] = f"{category}.tar.gz"
            if classification == "RAW_SOURCE_EVIDENCE":
                runs_dict[run_id]["evidence_files"].append((f, size_bytes))
            elif classification == "DERIVED_FORENSIC_OUTPUT":
                runs_dict[run_id]["volatility_files"].append((f, size_bytes))
            elif parts[-1] == "process":
                runs_dict[run_id]["process_features"] = str(rel_path)
            elif parts[-1] == "memory":
                runs_dict[run_id]["memory_features"] = str(rel_path)
            elif "metadata" in parts:
                runs_dict[run_id]["metadata"] = str(rel_path)

        file_records.append({
            "path": str(rel_path).replace("\\", "/"),
            "category": category,
            "run_id": run_id or "N/A",
            "file_name": f,
            "extension": suffix,
            "size_bytes": size_bytes,
            "classification": classification
        })

print(f"Total files cataloged: {len(file_records)}")
print(f"Total runs discovered: {len(runs_dict)}")

# Save full inventory JSON
out_dir = Path("evaluation/dataset_inventory")
out_dir.mkdir(parents=True, exist_ok=True)

with open(out_dir / "dataset_files_inventory.json", "w", encoding="utf-8") as f:
    json.dump(file_records, f, indent=2)

with open(out_dir / "runs_inventory.json", "w", encoding="utf-8") as f:
    json.dump(runs_dict, f, indent=2)

print(f"Saved dataset files inventory to {out_dir / 'dataset_files_inventory.json'}")
print(f"Saved runs inventory to {out_dir / 'runs_inventory.json'}")
