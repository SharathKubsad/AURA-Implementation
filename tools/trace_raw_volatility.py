import json
import tarfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(".").resolve()))
from forensics.extraction.parser_utils import (
    parse_malfind_output,
    parse_ldrmodules_output,
    parse_volatility_file,
    find_plugin_file,
)
from forensics.extraction.memory_extractor import RWX_PROTECTIONS, EXECUTABLE_PROTECTIONS

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

trace_results = []

for sid, arch_name, run_id, fam in samples_to_trace:
    arch_path = archives_dir / arch_name
    print(f"\nTracing {sid} ({fam}) from {arch_name}...")
    
    # Extract plugin text files into memory
    plugin_texts = {}
    with tarfile.open(arch_path, "r:gz") as tar:
        for m in tar.getmembers():
            norm_name = m.name.replace("\\", "/")
            if f"volatility/{run_id}/" in norm_name and norm_name.endswith(".txt"):
                pname = Path(norm_name).stem
                f = tar.extractfile(m)
                if f:
                    plugin_texts[pname] = f.read().decode("utf-8", errors="replace")
                    
    # Parse malfind
    malfind_records = []
    if "malfind" in plugin_texts:
        lines = plugin_texts["malfind"].splitlines()
        # manual parse
        for l in lines:
            parts = l.split("\t")
            if len(parts) >= 6 and parts[0].isdigit():
                malfind_records.append({
                    "pid": int(parts[0]),
                    "process": parts[1],
                    "vpn": parts[2],
                    "tag": parts[4],
                    "protection": parts[5]
                })
    pids = {r["pid"] for r in malfind_records}
    malfind_process_count = len(pids)
    injected_code_regions = len(malfind_records)
    
    # Parse vadinfo
    rwx_page_count = 0
    unmapped_executable_pages = 0
    if "vadinfo" in plugin_texts:
        import io
        import csv
        v_lines = plugin_texts["vadinfo"].splitlines()
        # Volatility 3 output uses tab separated columns
        header_idx = -1
        for i, l in enumerate(v_lines[:10]):
            if "PID" in l and "Protection" in l:
                header_idx = i
                break
        if header_idx != -1:
            reader = csv.DictReader(v_lines[header_idx:], delimiter="\t")
            for row in reader:
                pid_val = row.get("PID") or row.get("pid")
                if not pid_val:
                    continue
                prot = str(row.get("Protection") or row.get("protection") or "").lower().strip()
                if any(rwx in prot for rwx in RWX_PROTECTIONS):
                    rwx_page_count += 1
                is_exec = any(ep in prot for ep in EXECUTABLE_PROTECTIONS)
                file_val = str(row.get("File output") or row.get("file") or row.get("mapping") or "").strip()
                tag_val = str(row.get("Tag") or row.get("tag") or "").strip()
                private_mem = str(row.get("PrivateMemory") or row.get("privatememory") or "").strip()
                is_unmapped = (
                    (not file_val or file_val.lower() in ("n/a", "none", "null", "-", "disabled"))
                    and (private_mem in ("1", "true", "yes") or tag_val.startswith("Vad"))
                    and not tag_val.startswith("VadImage")
                )
                if is_exec and is_unmapped:
                    unmapped_executable_pages += 1
                    
    # Parse ldrmodules
    ldrmodules_inconsistencies = 0
    if "ldrmodules" in plugin_texts:
        l_lines = plugin_texts["ldrmodules"].splitlines()
        h_idx = -1
        for i, l in enumerate(l_lines[:10]):
            if "PID" in l and "InLoad" in l:
                h_idx = i
                break
        if h_idx != -1:
            reader = csv.DictReader(l_lines[h_idx:], delimiter="\t")
            for row in reader:
                in_load = str(row.get("InLoad") or "").lower().strip()
                in_mem = str(row.get("InMem") or "").lower().strip()
                if in_load in ("false", "0") or in_mem in ("false", "0"):
                    ldrmodules_inconsistencies += 1
                    
    unified_val = unified_map.get(sid, {})
    
    trace_entry = {
        "sample_id": sid,
        "run_id": run_id,
        "family": fam,
        "features": {
            "malfind_process_count": {
                "raw_parsed": malfind_process_count,
                "unified_value": unified_val.get("malfind_process_count"),
                "matches": malfind_process_count == unified_val.get("malfind_process_count")
            },
            "injected_code_regions": {
                "raw_parsed": injected_code_regions,
                "unified_value": unified_val.get("injected_code_regions"),
                "matches": injected_code_regions == unified_val.get("injected_code_regions")
            },
            "rwx_page_count": {
                "raw_parsed": rwx_page_count,
                "unified_value": unified_val.get("rwx_page_count"),
                "matches": rwx_page_count == unified_val.get("rwx_page_count")
            },
            "unmapped_executable_pages": {
                "raw_parsed": unmapped_executable_pages,
                "unified_value": unified_val.get("unmapped_executable_pages"),
                "matches": unmapped_executable_pages == unified_val.get("unmapped_executable_pages")
            },
            "ldrmodules_inconsistencies": {
                "raw_parsed": ldrmodules_inconsistencies,
                "unified_value": unified_val.get("ldrmodules_inconsistencies"),
                "matches": ldrmodules_inconsistencies == unified_val.get("ldrmodules_inconsistencies")
            }
        }
    }
    trace_results.append(trace_entry)
    print(f"  malfind_process_count: parsed={malfind_process_count}, unified={unified_val.get('malfind_process_count')}")
    print(f"  injected_code_regions: parsed={injected_code_regions}, unified={unified_val.get('injected_code_regions')}")
    print(f"  rwx_page_count: parsed={rwx_page_count}, unified={unified_val.get('rwx_page_count')}")
    print(f"  unmapped_executable_pages: parsed={unmapped_executable_pages}, unified={unified_val.get('unmapped_executable_pages')}")
    print(f"  ldrmodules_inconsistencies: parsed={ldrmodules_inconsistencies}, unified={unified_val.get('ldrmodules_inconsistencies')}")

with open("evaluation/custom_audit/manual_trace_6_samples.json", "w", encoding="utf-8") as f:
    json.dump(trace_results, f, indent=2)
print("\nSaved manual trace of 6 samples to evaluation/custom_audit/manual_trace_6_samples.json")
