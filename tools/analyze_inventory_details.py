import json
from pathlib import Path
from collections import Counter, defaultdict

inv_path = Path("evaluation/dataset_inventory/dataset_files_inventory.json")
runs_path = Path("evaluation/dataset_inventory/runs_inventory.json")

with open(inv_path, "r", encoding="utf-8") as f:
    files = json.load(f)

with open(runs_path, "r", encoding="utf-8") as f:
    runs = json.load(f)

print("=== 1. FILE TYPES AND EXTENSIONS ===")
exts = Counter(f["extension"] for f in files)
for ext, count in exts.most_common():
    print(f"  {ext or '(none)'}: {count} files")

print("\n=== 2. CLASSIFICATION BREAKDOWN ===")
classes = Counter(f["classification"] for f in files)
for cls, count in classes.most_common():
    print(f"  {cls}: {count} files")

print("\n=== 3. CATEGORIES / PACKAGES ===")
cats = Counter(f["category"] for f in files)
for cat, count in cats.most_common():
    print(f"  {cat}: {count} files")

print(f"\n=== 4. RUNS SUMMARY ({len(runs)} total runs) ===")
# Inspect each run's evidence files
evidence_file_types = defaultdict(int)
vol_plugin_counts = defaultdict(int)

runs_table = []
for run_id in sorted(runs.keys()):
    r_data = runs[run_id]
    ev_files = [f[0] for f in r_data["evidence_files"]]
    vol_files = [f[0] for f in r_data["volatility_files"]]
    for ef in ev_files:
        evidence_file_types[ef] += 1
    for vf in vol_files:
        vol_plugin_counts[vf] += 1
        
    runs_table.append({
        "run_id": run_id,
        "category": r_data["category"],
        "source_archive": r_data["source_archive"],
        "evidence_files": ev_files,
        "volatility_files_count": len(vol_files),
        "has_process_feat": r_data["process_features"] is not None,
        "has_memory_feat": r_data["memory_features"] is not None,
        "has_metadata": r_data["metadata"] is not None,
    })

print("Evidence files frequency across 45 runs:")
for ef, cnt in evidence_file_types.items():
    print(f"  {ef}: {cnt}/45 runs")

print("\nVolatility plugin files frequency across 45 runs:")
for vf, cnt in vol_plugin_counts.items():
    print(f"  {vf}: {cnt}/45 runs")

# Check metadata files for labels and families
print("\n=== 5. CHECKING METADATA / LABELS / FAMILIES ===")
metadata_info = {}
dataset_root = Path("Dataset")
for run_id, r_data in runs.items():
    # Read manifest.json in category
    manifest_file = dataset_root / r_data["category"] / "manifest.json"
    manifest_label = None
    manifest_family = None
    if manifest_file.exists():
        with open(manifest_file, "r", encoding="utf-8") as mf:
            m_data = json.load(mf)
            manifest_label = m_data.get("label")
            manifest_family = m_data.get("family")
            
    # Read metadata/RUN-xxx.json if exists
    meta_path = r_data.get("metadata")
    meta_json = {}
    if meta_path:
        with open(dataset_root / meta_path, "r", encoding="utf-8-sig") as f:
            meta_json = json.load(f)
            
    metadata_info[run_id] = {
        "run_id": run_id,
        "category": r_data["category"],
        "manifest_label": manifest_label,
        "manifest_family": manifest_family,
        "meta_label": meta_json.get("label"),
        "meta_family": meta_json.get("family"),
        "meta_binary_label": meta_json.get("binary_label"),
        "operator": meta_json.get("operator"),
        "timestamp": meta_json.get("timestamp") or meta_json.get("start_time")
    }

print("Sample metadata entries:")
for rid in ["RUN-001", "RUN-002", "RUN-100", "RUN-400", "RUN-1100", "RUN-1106"]:
    if rid in metadata_info:
        print(f"  {rid}: {metadata_info[rid]}")

with open("evaluation/dataset_inventory/metadata_analysis.json", "w", encoding="utf-8") as f:
    json.dump(metadata_info, f, indent=2)
