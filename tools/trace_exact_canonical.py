import json
import tarfile
import tempfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(".").resolve()))
from forensics.extraction.process_extractor import extract_process_features
from forensics.extraction.memory_extractor import extract_memory_features

archives_dir = Path("C:/FMD-Dataset/archives")
unified_path = Path("data/processed/unified/unified_dataset.jsonl")

with open(unified_path, "r", encoding="utf-8") as f:
    unified_map = {json.loads(line)["sample_id"]: json.loads(line) for line in f if line.strip()}

samples_to_trace = [
    # Benign
    ("EXEC_RUN-1100", "custom_benign_batch.tar.gz", "RUN-1100", "benign"),
    ("EXEC_RUN-1105", "custom_benign_batch.tar.gz", "RUN-1105", "benign"),
    ("EXEC_RUN-001", "custom_powershell_fileless.tar.gz", "RUN-001", "benign"),
    # Malware
    ("EXEC_RUN-002", "custom_powershell_fileless.tar.gz", "RUN-002", "powershell_fileless"),
    ("EXEC_RUN-100", "custom_process_hollowing.tar.gz", "RUN-100", "process_hollowing"),
    ("EXEC_RUN-400", "custom_cobalt_strike_beacon.tar.gz", "RUN-400", "cobalt_strike_beacon"),
]

detailed_trace = []

for sid, arch_name, run_id, fam in samples_to_trace:
    arch_path = archives_dir / arch_name
    print(f"\n==========================================")
    print(f"Tracing {sid} ({fam}) from {arch_name}")
    print(f"==========================================")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        with tarfile.open(arch_path, "r:gz") as tar:
            for m in tar.getmembers():
                norm = m.name.replace("\\", "/")
                if f"volatility/{run_id}/" in norm:
                    tar.extract(m, tmp)
                    
        run_vol_dir = list(tmp.rglob(run_id))[0]
        proc_feat = extract_process_features(run_vol_dir, sample_id=sid)
        mem_feat = extract_memory_features(run_vol_dir, sample_id=sid)
        
        unified_val = unified_map.get(sid, {})
        
        feature_comparisons = {
            "malfind_process_count": {
                "source_plugin": "windows.malfind.txt",
                "extracted_value": proc_feat.malfind_process_count,
                "unified_value": unified_val.get("malfind_process_count"),
                "exact_match": proc_feat.malfind_process_count == unified_val.get("malfind_process_count")
            },
            "injected_code_regions": {
                "source_plugin": "windows.malfind.txt",
                "extracted_value": mem_feat.injected_code_regions,
                "unified_value": unified_val.get("injected_code_regions"),
                "exact_match": mem_feat.injected_code_regions == unified_val.get("injected_code_regions")
            },
            "rwx_page_count": {
                "source_plugin": "windows.vadinfo.txt",
                "extracted_value": mem_feat.rwx_page_count,
                "unified_value": unified_val.get("rwx_page_count"),
                "exact_match": mem_feat.rwx_page_count == unified_val.get("rwx_page_count")
            },
            "unmapped_executable_pages": {
                "source_plugin": "windows.vadinfo.txt",
                "extracted_value": mem_feat.unmapped_executable_pages,
                "unified_value": unified_val.get("unmapped_executable_pages"),
                "exact_match": mem_feat.unmapped_executable_pages == unified_val.get("unmapped_executable_pages")
            },
            "ldrmodules_inconsistencies": {
                "source_plugin": "windows.ldrmodules.txt",
                "extracted_value": mem_feat.ldrmodules_inconsistencies,
                "unified_value": unified_val.get("ldrmodules_inconsistencies"),
                "exact_match": mem_feat.ldrmodules_inconsistencies == unified_val.get("ldrmodules_inconsistencies")
            },
            "total_process_count": {
                "source_plugin": "windows.pslist.txt",
                "extracted_value": proc_feat.total_process_count,
                "unified_value": unified_val.get("total_process_count"),
                "exact_match": proc_feat.total_process_count == unified_val.get("total_process_count")
            },
            "total_handle_count": {
                "source_plugin": "windows.handles.txt",
                "extracted_value": proc_feat.total_handle_count,
                "unified_value": unified_val.get("total_handle_count"),
                "exact_match": proc_feat.total_handle_count == unified_val.get("total_handle_count")
            }
        }
        
        for k, v in feature_comparisons.items():
            print(f"  {k:28}: extracted={v['extracted_value']} | unified={v['unified_value']} | MATCH={v['exact_match']}")
            
        detailed_trace.append({
            "sample_id": sid,
            "run_id": run_id,
            "family": fam,
            "archive": arch_name,
            "comparisons": feature_comparisons
        })

out_json = Path("evaluation/custom_audit/manual_trace_6_samples_exact.json")
with open(out_json, "w", encoding="utf-8") as f:
    json.dump(detailed_trace, f, indent=2)
print(f"\nAll 6 samples traced successfully. Saved to {out_json}")
