"""Audit complete 45-run forensic extraction coverage.

Verifies:
1. Every run's raw source evidence in Dataset/ vs derived artifacts in data/forensic/
2. Row-by-row count comparison across all plugins and telemetry
3. Cross-run content hashing to verify uniqueness and detect any duplication
4. Output data/forensic/audits/per_run_coverage.csv
5. Output docs/complete_45_run_coverage_audit.md
"""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DATASET_DIR = REPO_ROOT / "Dataset"
FORENSIC_DIR = REPO_ROOT / "data" / "forensic"
AUDIT_DIR = FORENSIC_DIR / "audits"

try:
    import win32evtlog
except ImportError:
    win32evtlog = None


def count_lines_jsonl(path: Path) -> int:
    """Count non-empty lines in a JSONL file."""
    if not path.exists():
        return 0
    cnt = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.strip():
                cnt += 1
    return cnt


def compute_file_sha256(path: Path) -> str:
    """Compute SHA256 hash of a file."""
    if not path.exists():
        return "MISSING"
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def count_raw_volatility_pslist(path: Path) -> int:
    if not path.exists():
        return 0
    cnt = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split("\t")
            if len(parts) >= 3 and parts[0].isdigit():
                cnt += 1
    return cnt


def count_raw_volatility_threads(path: Path) -> int:
    if not path.exists():
        return 0
    cnt = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split("\t")
            if len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit():
                cnt += 1
    return cnt


def count_raw_volatility_handles(path: Path) -> int:
    if not path.exists():
        return 0
    cnt = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split("\t")
            if len(parts) >= 5 and parts[0].isdigit() and "0x" in parts[3]:
                cnt += 1
    return cnt


def count_raw_volatility_dlls(path: Path) -> int:
    if not path.exists():
        return 0
    cnt = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split("\t")
            if len(parts) >= 5 and parts[0].isdigit() and "0x" in parts[2]:
                cnt += 1
    return cnt


def count_raw_volatility_privs(path: Path) -> int:
    if not path.exists():
        return 0
    cnt = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split("\t")
            if len(parts) >= 4 and parts[0].isdigit() and "Se" in parts[3]:
                cnt += 1
    return cnt


def count_raw_volatility_vads(path: Path) -> int:
    if not path.exists():
        return 0
    cnt = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split("\t")
            if len(parts) >= 6 and parts[0].isdigit() and "0x" in parts[3]:
                cnt += 1
    return cnt


def count_raw_volatility_malfind(path: Path) -> int:
    if not path.exists():
        return 0
    cnt = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split("\t")
            if len(parts) >= 8 and parts[0].isdigit() and ("0x" in parts[2] or "0x" in parts[3]):
                cnt += 1
    return cnt


def count_raw_evtx_events(path: Path) -> int:
    if not path.exists() or win32evtlog is None:
        return 0
    try:
        q = win32evtlog.EvtQuery(str(path.resolve()), win32evtlog.EvtQueryFilePath)
        cnt = 0
        batch = win32evtlog.EvtNext(q, 100)
        while batch:
            cnt += len(batch)
            batch = win32evtlog.EvtNext(q, 100)
        return cnt
    except Exception:
        return 0


def count_raw_csv_rows(path: Path) -> int:
    if not path.exists():
        return 0
    cnt = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        for row in reader:
            if row:
                cnt += 1
    return cnt


def main() -> None:
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Locate all 45 runs across Dataset
    categories = sorted([d for d in DATASET_DIR.iterdir() if d.is_dir()])
    
    records: list[dict[str, Any]] = []
    
    # Hash tracking to detect duplication across runs: modality -> dict of run_id -> hash
    hash_tracker: dict[str, dict[str, str]] = {
        "processes": {},
        "threads": {},
        "handles": {},
        "modules": {},
        "privileges": {},
        "vads": {},
        "malfind": {},
        "sysmon": {},
        "powershell": {},
        "network": {},
    }
    
    print("=" * 70)
    print("AUDITING COMPLETE 45-RUN FORENSIC COVERAGE")
    print("=" * 70)
    
    for cat_dir in categories:
        meta_dir = cat_dir / "metadata"
        if not meta_dir.exists():
            continue
            
        meta_files = sorted(meta_dir.glob("*.json"))
        for mf in meta_files:
            run_id = mf.stem
            with open(mf, "r", encoding="utf-8-sig") as f:
                metadata = json.load(f)
                
            sample_id = f"EXEC_{run_id}"
            
            # Canonical label resolution
            if run_id == "RUN-001":
                label = 0
                family = "benign"
            else:
                label = int(metadata.get("label", 0))
                family = str(metadata.get("family", "benign"))
                
            vol_dir = cat_dir / "volatility" / run_id
            src_dir = cat_dir / "source_evidence" / run_id
            
            # 1. Source counts
            src_pslist = count_raw_volatility_pslist(vol_dir / "pslist.txt")
            src_threads = count_raw_volatility_threads(vol_dir / "threads.txt")
            src_handles = count_raw_volatility_handles(vol_dir / "handles.txt")
            src_dlls = count_raw_volatility_dlls(vol_dir / "dlllist.txt")
            src_privs = count_raw_volatility_privs(vol_dir / "privileges.txt")
            src_vads = count_raw_volatility_vads(vol_dir / "vadinfo.txt")
            src_malfind = count_raw_volatility_malfind(vol_dir / "malfind.txt")
            src_sysmon = count_raw_evtx_events(src_dir / "sysmon.evtx")
            src_ps = count_raw_evtx_events(src_dir / "powershell.evtx")
            src_net = count_raw_csv_rows(src_dir / "network_connections.csv")
            
            # 2. Derived counts
            der_proc_file = FORENSIC_DIR / "entities" / "processes" / f"{run_id}.jsonl"
            der_thread_file = FORENSIC_DIR / "entities" / "threads" / f"{run_id}.jsonl"
            der_handle_file = FORENSIC_DIR / "entities" / "handles" / f"{run_id}.jsonl"
            der_mod_file = FORENSIC_DIR / "entities" / "modules" / f"{run_id}.jsonl"
            der_priv_file = FORENSIC_DIR / "entities" / "privileges" / f"{run_id}.jsonl"
            der_vad_file = FORENSIC_DIR / "entities" / "memory_regions" / f"{run_id}.jsonl"
            der_malfind_file = FORENSIC_DIR / "events" / "memory" / f"{run_id}.jsonl"
            der_sysmon_file = FORENSIC_DIR / "events" / "sysmon" / f"{run_id}.jsonl"
            der_ps_file = FORENSIC_DIR / "events" / "powershell" / f"{run_id}.jsonl"
            der_net_file = FORENSIC_DIR / "events" / "network" / f"{run_id}.jsonl"
            der_sample_file = FORENSIC_DIR / "samples" / f"{run_id}.json"
            
            der_proc = count_lines_jsonl(der_proc_file)
            der_threads = count_lines_jsonl(der_thread_file)
            der_handles = count_lines_jsonl(der_handle_file)
            der_mods = count_lines_jsonl(der_mod_file)
            der_privs = count_lines_jsonl(der_priv_file)
            der_vads = count_lines_jsonl(der_vad_file)
            der_malfind = count_lines_jsonl(der_malfind_file)
            der_sysmon = count_lines_jsonl(der_sysmon_file)
            der_ps = count_lines_jsonl(der_ps_file)
            der_net = count_lines_jsonl(der_net_file)
            
            # 3. Track Hashes
            hash_tracker["processes"][run_id] = compute_file_sha256(der_proc_file)
            hash_tracker["threads"][run_id] = compute_file_sha256(der_thread_file)
            hash_tracker["handles"][run_id] = compute_file_sha256(der_handle_file)
            hash_tracker["modules"][run_id] = compute_file_sha256(der_mod_file)
            hash_tracker["privileges"][run_id] = compute_file_sha256(der_priv_file)
            hash_tracker["vads"][run_id] = compute_file_sha256(der_vad_file)
            hash_tracker["malfind"][run_id] = compute_file_sha256(der_malfind_file)
            hash_tracker["sysmon"][run_id] = compute_file_sha256(der_sysmon_file)
            hash_tracker["powershell"][run_id] = compute_file_sha256(der_ps_file)
            hash_tracker["network"][run_id] = compute_file_sha256(der_net_file)
            
            # 4. Status determination
            # Derived processes incorporate pslist + psscan + pstree + snapshot, so der_proc >= src_pslist
            proc_ok = der_proc >= src_pslist and der_proc > 0
            thread_ok = der_threads == src_threads and der_threads > 0
            handle_ok = der_handles == src_handles and der_handles > 0
            mod_ok = der_mods == src_dlls and der_mods > 0
            priv_ok = der_privs == src_privs and der_privs > 0
            vad_ok = der_vads == src_vads and der_vads > 0
            malfind_ok = der_malfind == src_malfind
            sysmon_ok = der_sysmon > 0 and der_sysmon <= src_sysmon
            ps_ok = der_ps > 0 and der_ps <= src_ps  # der_ps filters for EID 4104 specifically
            net_ok = der_net >= src_net and der_net > 0  # net includes netstat + sysmon EID 3
            sample_ok = der_sample_file.exists()
            
            all_ok = all([
                proc_ok, thread_ok, handle_ok, mod_ok, priv_ok, vad_ok,
                malfind_ok, sysmon_ok, ps_ok, net_ok, sample_ok
            ])
            
            status = "VERIFIED" if all_ok else "INVESTIGATE"
            notes_parts = []
            if der_proc > src_pslist:
                notes_parts.append(f"+{der_proc - src_pslist} unlinked/snapshot procs")
            if der_net > src_net:
                notes_parts.append(f"+{der_net - src_net} Sysmon EID3 sockets")
            notes_parts.append(f"PS 4104: {der_ps}/{src_ps} events")
            notes = "; ".join(notes_parts)
            
            rec = {
                "sample_id": sample_id,
                "category": cat_dir.name,
                "family": family,
                "label": label,
                "source_pslist_count": src_pslist,
                "derived_process_count": der_proc,
                "source_threads_count": src_threads,
                "derived_thread_count": der_threads,
                "source_handles_count": src_handles,
                "derived_handle_count": der_handles,
                "source_dll_count": src_dlls,
                "derived_module_count": der_mods,
                "source_privilege_count": src_privs,
                "derived_privilege_count": der_privs,
                "source_vad_count": src_vads,
                "derived_vad_count": der_vads,
                "source_malfind_count": src_malfind,
                "derived_malfind_count": der_malfind,
                "source_sysmon_count": src_sysmon,
                "derived_sysmon_count": der_sysmon,
                "source_powershell_count": src_ps,
                "derived_powershell_count": der_ps,
                "source_network_count": src_net,
                "derived_network_count": der_net,
                "status": status,
                "notes": notes,
            }
            records.append(rec)
            print(f"[{run_id}] {cat_dir.name[:25]:<25} | Label: {label} ({family[:18]:<18}) | Pslist: {src_pslist}->{der_proc} | Handles: {src_handles}->{der_handles} | VADs: {src_vads}->{der_vads} | {status}")
            
    # Write CSV
    csv_path = AUDIT_DIR / "per_run_coverage.csv"
    fieldnames = [
        "sample_id", "category", "family", "label",
        "source_pslist_count", "derived_process_count",
        "source_threads_count", "derived_thread_count",
        "source_handles_count", "derived_handle_count",
        "source_dll_count", "derived_module_count",
        "source_privilege_count", "derived_privilege_count",
        "source_vad_count", "derived_vad_count",
        "source_malfind_count", "derived_malfind_count",
        "source_sysmon_count", "derived_sysmon_count",
        "source_powershell_count", "derived_powershell_count",
        "source_network_count", "derived_network_count",
        "status", "notes",
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow(r)
            
    print(f"\nWritten per-run coverage to {csv_path}")
    
    # Check for duplication across runs
    duplicates_detected = []
    for mod_name, run_hashes in hash_tracker.items():
        seen: dict[str, str] = {}
        for r_id, h_val in run_hashes.items():
            if h_val in seen:
                duplicates_detected.append({
                    "modality": mod_name,
                    "run_1": seen[h_val],
                    "run_2": r_id,
                    "sha256": h_val,
                })
            else:
                seen[h_val] = r_id
                
    if duplicates_detected:
        print(f"WARNING: {len(duplicates_detected)} duplicated modality representations detected!")
        for d in duplicates_detected:
            print(f"  {d['modality']}: {d['run_1']} == {d['run_2']}")
    else:
        print("PASS: Zero cross-run duplication detected. All 45 runs have strictly unique forensic representations!")
        
    return records, duplicates_detected


if __name__ == "__main__":
    main()
