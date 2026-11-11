import json
import os
import tarfile
from pathlib import Path
from collections import Counter

repo_root = Path(".").resolve()
unified_file = repo_root / "data/processed/unified/unified_dataset.jsonl"
interim_proc = repo_root / "data/interim/process"
interim_mem = repo_root / "data/interim/memory"
interim_cmd = repo_root / "data/interim/command"
interim_net = repo_root / "data/interim/network"
raw_custom = repo_root / "data/raw/custom"
archives_dir = Path("C:/FMD-Dataset/archives")

print("="*60)
print("FORENSIC PROVENANCE AUDIT: 45 SAMPLES INVESTIGATION")
print("="*60)

# 1. Load unified dataset
with open(unified_file, "r", encoding="utf-8") as f:
    unified_rows = [json.loads(line) for line in f if line.strip()]

print(f"Total samples in unified dataset: {len(unified_rows)}")

# Map sample_id to run ID
# e.g., EXEC_RUN-001 -> RUN-001
sample_ids = [r["sample_id"] for r in unified_rows]
print(f"Sample IDs: {sample_ids[:5]} ... {sample_ids[-5:]}")

# 2. Inspect Archives structure
print("\n--- ARCHIVES CONTENT ANALYSIS ---")
archive_contents = {}
for a in sorted(archives_dir.glob("*.tar.gz")):
    with tarfile.open(a, "r:gz") as tar:
        names = tar.getnames()
        # Find all prefixes/directories
        top_subdirs = set()
        runs_in_archive = set()
        has_vol = False
        has_raw_mem = False
        has_pcap = False
        has_evtx = False
        for n in names:
            parts = n.split("/")
            if len(parts) > 1:
                top_subdirs.add(parts[1])
            if "source_evidence" in parts:
                idx = parts.index("source_evidence")
                if len(parts) > idx + 1:
                    runs_in_archive.add(parts[idx + 1])
            if "volatility" in n:
                has_vol = True
            if any(n.endswith(ext) for ext in [".raw", ".mem", ".vmem", ".dmp"]):
                has_raw_mem = True
            if any(n.endswith(ext) for ext in [".pcap", ".pcapng"]):
                has_pcap = True
            if n.endswith(".evtx"):
                has_evtx = True
        archive_contents[a.name] = {
            "total_files": len(names),
            "subdirs": list(top_subdirs),
            "runs": sorted(list(runs_in_archive)),
            "has_vol": has_vol,
            "has_raw_mem": has_raw_mem,
            "has_pcap": has_pcap,
            "has_evtx": has_evtx
        }
        print(f"\nArchive: {a.name}")
        print(f"  Total items: {len(names)}")
        print(f"  Subdirs: {top_subdirs}")
        print(f"  Runs identified ({len(runs_in_archive)}): {sorted(list(runs_in_archive))[:6]}")
        print(f"  Volatility outputs present: {has_vol}")
        print(f"  Raw memory dump present: {has_raw_mem}")
        print(f"  PCAP present: {has_pcap}")
        print(f"  EVTX present: {has_evtx}")

# 3. Check what exists in data/raw/custom
print("\n--- DATA/RAW/CUSTOM SCAN ---")
custom_runs_on_disk = {}
for item in raw_custom.iterdir():
    if item.is_dir():
        files = list(item.glob("*"))
        custom_runs_on_disk[item.name] = [f.name for f in files]
print(f"Directories in data/raw/custom: {list(custom_runs_on_disk.keys())}")
for d, fs in custom_runs_on_disk.items():
    if fs != ["README.md"]:
        print(f"  {d}: {fs[:10]}")

# 4. Check data/interim
print("\n--- DATA/INTERIM SCAN ---")
print(f"Process interim: {len(list(interim_proc.glob('*.json')))} files")
print(f"Memory interim: {len(list(interim_mem.glob('*.json')))} files")
print(f"Command interim exists: {interim_cmd.exists()} (count: {len(list(interim_cmd.glob('*.json'))) if interim_cmd.exists() else 0})")
print(f"Network interim exists: {interim_net.exists()} (count: {len(list(interim_net.glob('*.json'))) if interim_net.exists() else 0})")

# 5. Check Command values
print("\n--- COMMAND VALUES IN UNIFIED DATASET ---")
cmd_texts = [r.get("raw_command_text") for r in unified_rows]
cmd_counts = Counter(cmd_texts)
print(f"Unique raw_command_text count: {len(cmd_counts)}")
for cmd, cnt in cmd_counts.items():
    print(f"  Count {cnt}: {repr(cmd)}")

# 6. Check Network values
print("\n--- NETWORK VALUES IN UNIFIED DATASET ---")
listening_ports = [r.get("listening_port_count") for r in unified_rows]
print(f"Listening port counts: {Counter(listening_ports)}")
pcap_fields = [
    "dns_query_count", "avg_interpacket_interval_ms", "beacon_regularity_score",
    "total_bytes_sent", "total_bytes_received"
]
for fld in pcap_fields:
    vals = [r.get(fld) for r in unified_rows]
    null_cnt = sum(1 for v in vals if v is None)
    print(f"  {fld}: {null_cnt}/{len(unified_rows)} NULL")

# 7. Check Key Volatility Feature Values
print("\n--- KEY VOLATILITY / MEMORY FEATURE VALUES ---")
key_features = [
    "malfind_process_count", "rwx_page_count", "injected_code_regions",
    "unmapped_executable_pages", "ldrmodules_inconsistencies"
]
for fld in key_features:
    vals = [r.get(fld) for r in unified_rows]
    counts = Counter(vals)
    print(f"  {fld} distribution: {dict(counts.most_common(10))}")
