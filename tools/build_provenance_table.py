import tarfile
from pathlib import Path
import json

archives_dir = Path("C:/FMD-Dataset/archives")
unified_path = Path("data/processed/unified/unified_dataset.jsonl")

with open(unified_path, "r", encoding="utf-8") as f:
    unified_samples = [json.loads(line) for line in f if line.strip()]

print(f"Loaded {len(unified_samples)} unified samples.")

# Index all files inside all archives
archive_file_index = {} # (run_id, filename) -> file_size

for a in sorted(archives_dir.glob("*.tar.gz")):
    with tarfile.open(a, "r:gz") as tar:
        for m in tar.getmembers():
            if m.isfile():
                parts = m.name.replace("\\", "/").split("/")
                # Check for volatility
                if "volatility" in parts:
                    idx = parts.index("volatility")
                    if len(parts) > idx + 1:
                        run_id = parts[idx + 1]
                        fname = parts[-1]
                        archive_file_index[(run_id, fname)] = m.size
                # Check for source_evidence
                if "source_evidence" in parts:
                    idx = parts.index("source_evidence")
                    if len(parts) > idx + 1:
                        run_id = parts[idx + 1]
                        fname = parts[-1]
                        archive_file_index[(run_id, f"source:{fname}")] = m.size

plugins = [
    "pslist", "psscan", "pstree", "threads", "handles",
    "dlllist", "psxview", "malfind", "privileges", "vadinfo", "ldrmodules"
]

results = []
for s in unified_samples:
    sid = s["sample_id"]
    run_id = sid.replace("EXEC_", "")
    label = s.get("binary_label", s.get("label", 0))
    family = s.get("family", "unknown")
    
    # Check memory dump existence (check .raw, .dmp, .vmem in archive or on disk)
    mem_dump_exists = False
    raw_disk_dump = Path(f"data/raw/custom/{run_id}/memory.raw")
    if raw_disk_dump.exists():
        mem_dump_exists = True
    elif (run_id, "memory.raw") in archive_file_index:
        mem_dump_exists = True
        
    row = {
        "sample_id": sid,
        "run_id": run_id,
        "label": label,
        "family": family,
        "memory_dump_exists": mem_dump_exists,
    }
    
    for p in plugins:
        txt_name = f"{p}.txt"
        exists = (run_id, txt_name) in archive_file_index
        size = archive_file_index.get((run_id, txt_name), 0)
        row[f"{p}_exists"] = exists
        row[f"{p}_size"] = size
        
    results.append(row)

# Summary
total = len(results)
print(f"Total samples checked: {total}")
for p in plugins:
    cnt = sum(1 for r in results if r[f"{p}_exists"])
    print(f"  {p}_exists: {cnt}/{total}")

mem_cnt = sum(1 for r in results if r["memory_dump_exists"])
print(f"  memory_dump_exists: {mem_cnt}/{total}")

# Save json for detailed table creation
out_json = Path("evaluation/custom_audit/provenance_45_table.json")
out_json.parent.mkdir(parents=True, exist_ok=True)
with open(out_json, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)
print(f"Saved audit table to {out_json}")
