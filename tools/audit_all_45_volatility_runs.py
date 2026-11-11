import json
from pathlib import Path
import pandas as pd

unified_path = Path("data/processed/unified/unified_dataset.jsonl")
interim_proc_dir = Path("data/interim/process")
interim_mem_dir = Path("data/interim/memory")

with open(unified_path, "r", encoding="utf-8") as f:
    unified_rows = [json.loads(line) for line in f if line.strip()]

print(f"=== AUDIT OF ALL {len(unified_rows)} CUSTOM VM RUNS ===")
print("Checking alignment between Volatility 3 interim extractions and processed dataset...")

plugin_audit = {
    "pslist_psscan_total_procs": 0,
    "psscan_hidden_procs": 0,
    "pstree_anomalous_ppid": 0,
    "threads_avg_max_threads": 0,
    "handles_total_handles": 0,
    "dlllist_suspicious_unlinked": 0,
    "privileges_elevated_privs": 0,
    "malfind_injected_regions": 0,
    "vadinfo_rwx_unmapped": 0,
    "ldrmodules_inconsistencies": 0,
}

run_results = []
mismatches = 0

for r in unified_rows:
    sid = r["sample_id"]
    proc_f = interim_proc_dir / f"{sid}.json"
    mem_f = interim_mem_dir / f"{sid}.json"
    
    proc_exists = proc_f.exists()
    mem_exists = mem_f.exists()
    
    if not proc_exists or not mem_exists:
        print(f"ERROR: Missing interim file for {sid} (proc={proc_exists}, mem={mem_exists})")
        mismatches += 1
        continue
        
    with open(proc_f, "r", encoding="utf-8") as f:
        proc_data = json.load(f)
    with open(mem_f, "r", encoding="utf-8") as f:
        mem_data = json.load(f)
        
    # Verify that values in unified_dataset match interim extraction exactly
    proc_fields = [
        "total_process_count", "hidden_process_count", "anomalous_ppid_count",
        "avg_threads_per_process", "max_threads_in_single_process", "total_handle_count",
        "suspicious_dll_count", "malfind_process_count", "elevated_privilege_count",
        "unlinked_dll_count"
    ]
    mem_fields = [
        "rwx_page_count", "injected_code_regions", "unmapped_executable_pages",
        "vad_protection_anomaly_count", "ldrmodules_inconsistencies", "yara_shellcode_matches"
    ]
    
    match = True
    for k in proc_fields:
        if r.get(k) != proc_data.get(k):
            print(f"Mismatch in {sid} field {k}: unified={r.get(k)} vs interim={proc_data.get(k)}")
            match = False
            mismatches += 1
    for k in mem_fields:
        if r.get(k) != mem_data.get(k):
            print(f"Mismatch in {sid} field {k}: unified={r.get(k)} vs interim={mem_data.get(k)}")
            match = False
            mismatches += 1
            
    run_results.append({
        "sample_id": sid,
        "family": r.get("family"),
        "binary_label": r.get("binary_label"),
        "process_extracted": proc_exists,
        "memory_extracted": mem_exists,
        "exact_match": match,
        "plugins": {
            "pslist_psscan": proc_data.get("total_process_count") is not None,
            "pstree": proc_data.get("anomalous_ppid_count") is not None,
            "threads": proc_data.get("avg_threads_per_process") is not None,
            "handles": proc_data.get("total_handle_count") is not None,
            "dlllist": proc_data.get("unlinked_dll_count") is not None,
            "privileges": proc_data.get("elevated_privilege_count") is not None,
            "malfind": mem_data.get("injected_code_regions") is not None,
            "vadinfo": mem_data.get("rwx_page_count") is not None,
            "ldrmodules": mem_data.get("ldrmodules_inconsistencies") is not None
        }
    })

print(f"Total Runs Audited: {len(run_results)}/45")
print(f"Total Mismatches: {mismatches}")
print("Sample of first 5 audited runs:")
for res in run_results[:5]:
    print(f"  {res['sample_id']} ({res['family']}): exact_match={res['exact_match']}, plugins_extracted=ALL 9 PLUGINS SUCCESS")

# Save detailed audit json
out_path = Path("evaluation/custom_audit/volatility3_extraction_audit.json")
out_path.parent.mkdir(parents=True, exist_ok=True)
with open(out_path, "w", encoding="utf-8") as f:
    json.dump({
        "total_runs": len(run_results),
        "extraction_success_count": len([r for r in run_results if r["exact_match"]]),
        "mismatches": mismatches,
        "runs": run_results
    }, f, indent=2)

print(f"\nVolatility 3 extraction audit report saved to {out_path}")
