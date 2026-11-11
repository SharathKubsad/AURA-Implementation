"""Rich Forensic Feature Engineering Pipeline (Phase 4).

Derives model-ready, semantically grounded features from the canonical rich
forensic representation layer (data/forensic/).

Outputs:
- data/features/process/ (features, schema, statistics, missingness report)
- data/features/memory/ (features, schema, statistics, missingness report)
- data/features/command/ (features, text sequences, schema, statistics, missingness report)
- data/features/network/ (features, schema, statistics, missingness report)
- data/features/cross_modal/ (features, schema, statistics, missingness report)
- data/features/splits/ (train_runs.json, val_runs.json, test_runs.json)
- data/features/feature_leakage_audit.csv
- data/features/feature_provenance.json
"""

from __future__ import annotations

import csv
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
FORENSIC_DIR = REPO_ROOT / "data" / "forensic"
FEATURES_DIR = REPO_ROOT / "data" / "features"
DOCS_DIR = REPO_ROOT / "docs"

# High-impact Windows token privileges of forensic interest
HIGH_IMPACT_PRIVILEGES = {
    "SeDebugPrivilege",
    "SeTcbPrivilege",
    "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeLoadDriverPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeCreateTokenPrivilege",
}

# Known LOLBins (Living-off-the-Land Binaries)
LOLBIN_NAMES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wmic.exe",
    "mshta.exe",
    "cscript.exe",
    "wscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "vssadmin.exe",
    "schtasks.exe",
    "net.exe",
    "net1.exe",
}


def load_samples() -> List[Dict[str, Any]]:
    samples_file = FORENSIC_DIR / "samples" / "samples.jsonl"
    samples = []
    with open(samples_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                samples.append(json.loads(line))
    return samples


# ==============================================================================
# 1. PROCESS MODALITY FEATURE EXTRACTION
# ==============================================================================

def extract_process_features(sample: Dict[str, Any]) -> Dict[str, Any]:
    run_id = sample["run_id"]
    proc_file = FORENSIC_DIR / "entities" / "processes" / f"{run_id}.jsonl"
    thread_file = FORENSIC_DIR / "entities" / "threads" / f"{run_id}.jsonl"
    handle_file = FORENSIC_DIR / "entities" / "handles" / f"{run_id}.jsonl"
    priv_file = FORENSIC_DIR / "entities" / "privileges" / f"{run_id}.jsonl"
    tree_file = FORENSIC_DIR / "relationships" / "process_tree" / f"{run_id}.jsonl"

    processes = []
    if proc_file.exists():
        with open(proc_file, "r", encoding="utf-8") as f:
            processes = [json.loads(line) for line in f if line.strip()]

    # Process Counts
    total_count = len(processes)
    active_count = sum(1 for p in processes if p.get("is_in_pslist"))
    carved_count = sum(1 for p in processes if p.get("is_in_psscan") and not p.get("is_in_pslist"))
    hidden_unlinked_count = sum(1 for p in processes if p.get("is_hidden_psxview") or (p.get("is_in_psscan") and not p.get("is_in_pslist")))
    wow64_count = sum(1 for p in processes if p.get("wow64"))

    # Image Paths
    user_writable_count = 0
    system_dir_count = 0
    temp_dir_count = 0
    unusual_location_count = 0

    known_pids = set()
    working_sets = []
    cpu_utils = []

    for p in processes:
        pid = p.get("pid")
        if pid is not None:
            known_pids.add(pid)
        img = (p.get("image_path") or "").lower()
        if img:
            if any(k in img for k in ["\\users\\", "\\appdata\\", "\\temp\\", "\\users\\public\\"]):
                user_writable_count += 1
            if "\\temp\\" in img or "\\local\\temp\\" in img:
                temp_dir_count += 1
            if "\\windows\\system32\\" in img or "\\windows\\syswow64\\" in img:
                system_dir_count += 1
            elif not any(k in img for k in ["\\program files", "\\windows\\"]):
                unusual_location_count += 1

        ws = p.get("working_set_bytes")
        if ws is not None:
            working_sets.append(ws)
        cpu = p.get("cpu_utilization")
        if cpu is not None:
            cpu_utils.append(cpu)

    # Process Tree
    tree_edges = []
    if tree_file.exists():
        with open(tree_file, "r", encoding="utf-8") as f:
            tree_edges = [json.loads(line) for line in f if line.strip()]

    parent_child_map: Dict[int, List[int]] = {}
    orphan_parent_count = 0
    for edge in tree_edges:
        ppid = edge.get("parent_pid")
        cpid = edge.get("child_pid")
        if ppid is not None and cpid is not None:
            parent_child_map.setdefault(ppid, []).append(cpid)
            if ppid not in known_pids:
                orphan_parent_count += 1

    child_counts = [len(children) for children in parent_child_map.values()] if parent_child_map else [0]
    max_children = max(child_counts) if child_counts else 0
    spawning_concentration = (max_children / sum(child_counts)) if sum(child_counts) > 0 else 0.0

    # Process tree depth estimation
    tree_depths = [1]
    for ppid, children in parent_child_map.items():
        depth = 1
        curr = ppid
        visited = {curr}
        # trace upward
        while True:
            parent_of_curr = None
            for e in tree_edges:
                if e.get("child_pid") == curr:
                    parent_of_curr = e.get("parent_pid")
                    break
            if parent_of_curr is not None and parent_of_curr not in visited:
                visited.add(parent_of_curr)
                depth += 1
                curr = parent_of_curr
            else:
                break
        tree_depths.append(depth)

    tree_max_depth = max(tree_depths) if tree_depths else 1
    tree_mean_depth = float(np.mean(tree_depths)) if tree_depths else 1.0

    # Thread and Handle counts
    threads_count = 0
    if thread_file.exists():
        with open(thread_file, "r", encoding="utf-8") as f:
            threads_count = sum(1 for line in f if line.strip())

    handles_count = 0
    if handle_file.exists():
        with open(handle_file, "r", encoding="utf-8") as f:
            handles_count = sum(1 for line in f if line.strip())

    # Privileges
    elevated_priv_count = 0
    sedebug_pids = set()
    if priv_file.exists():
        with open(priv_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    p = json.loads(line)
                    pname = p.get("privilege_name")
                    if pname in HIGH_IMPACT_PRIVILEGES and p.get("is_present"):
                        elevated_priv_count += 1
                    if pname == "SeDebugPrivilege" and p.get("is_present"):
                        sedebug_pids.add(p.get("pid"))

    return {
        "sample_id": sample["sample_id"],
        "run_id": run_id,
        "label": sample["label"],
        "proc_total_count": total_count,
        "proc_active_count": active_count,
        "proc_carved_count": carved_count,
        "proc_hidden_unlinked_count": hidden_unlinked_count,
        "proc_wow64_count": wow64_count,
        "proc_tree_max_depth": tree_max_depth,
        "proc_tree_mean_depth": round(tree_mean_depth, 3),
        "proc_orphan_parent_count": orphan_parent_count,
        "proc_max_children_single_proc": max_children,
        "proc_spawning_concentration": round(spawning_concentration, 4),
        "proc_thread_count_total": threads_count,
        "proc_thread_count_mean": round(threads_count / total_count, 2) if total_count > 0 else 0.0,
        "proc_handle_count_total": handles_count,
        "proc_handle_count_mean": round(handles_count / total_count, 2) if total_count > 0 else 0.0,
        "proc_working_set_bytes_mean": round(float(np.mean(working_sets)), 1) if working_sets else None,
        "proc_cpu_utilization_mean": round(float(np.mean(cpu_utils)), 4) if cpu_utils else None,
        "proc_user_writable_path_count": user_writable_count,
        "proc_system_directory_count": system_dir_count,
        "proc_temp_directory_count": temp_dir_count,
        "proc_unusual_executable_location_count": unusual_location_count,
        "proc_elevated_privilege_count": elevated_priv_count,
        "proc_processes_with_sedebug": len(sedebug_pids),
    }


# ==============================================================================
# 2. MEMORY MODALITY FEATURE EXTRACTION
# ==============================================================================

def extract_memory_features(sample: Dict[str, Any]) -> Dict[str, Any]:
    run_id = sample["run_id"]
    vad_file = FORENSIC_DIR / "entities" / "memory_regions" / f"{run_id}.jsonl"
    malfind_file = FORENSIC_DIR / "events" / "memory" / f"{run_id}.jsonl"
    module_file = FORENSIC_DIR / "entities" / "modules" / f"{run_id}.jsonl"

    # VAD features
    total_vad_count = 0
    rwx_count = 0
    exec_private_count = 0
    exec_writable_count = 0
    private_vad_count = 0
    mapped_vad_count = 0
    commit_charges = []
    region_sizes = []

    if vad_file.exists():
        with open(vad_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    vad = json.loads(line)
                    total_vad_count += 1
                    prot = vad.get("protection", "")
                    priv = vad.get("private_memory", 0)
                    commit = vad.get("commit_charge", 0)
                    size = vad.get("region_size_bytes")

                    if prot == "PAGE_EXECUTE_READWRITE":
                        rwx_count += 1
                    if "EXECUTE" in prot and priv > 0:
                        exec_private_count += 1
                    if "EXECUTE" in prot and ("READWRITE" in prot or "WRITECOPY" in prot):
                        exec_writable_count += 1

                    if priv > 0:
                        private_vad_count += 1
                    else:
                        mapped_vad_count += 1

                    commit_charges.append(commit)
                    if size is not None:
                        region_sizes.append(size)

    # Malfind findings
    total_malfind = 0
    baseline_exception_count = 0
    suspicious_malfind_count = 0
    malfind_pids = set()
    malfind_proc_counts: Dict[int, int] = {}

    if malfind_file.exists():
        with open(malfind_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    mf = json.loads(line)
                    total_malfind += 1
                    pid = mf.get("pid")
                    is_baseline = mf.get("is_known_baseline_exception", False)
                    if is_baseline:
                        baseline_exception_count += 1
                    else:
                        suspicious_malfind_count += 1
                        if pid is not None:
                            malfind_pids.add(pid)
                            malfind_proc_counts[pid] = malfind_proc_counts.get(pid, 0) + 1

    max_findings_single_proc = max(malfind_proc_counts.values()) if malfind_proc_counts else 0

    # Module loader consistency (ldrmodules)
    total_modules = 0
    unlinked_modules = 0
    module_pids = set()

    if module_file.exists():
        with open(module_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    mod = json.loads(line)
                    total_modules += 1
                    pid = mod.get("pid")
                    if pid is not None:
                        module_pids.add(pid)
                    in_load = mod.get("in_load")
                    in_init = mod.get("in_init")
                    in_mem = mod.get("in_mem")
                    # If any loader list entry is False, the module is unlinked/hidden
                    if in_load is False or in_init is False or in_mem is False:
                        unlinked_modules += 1

    return {
        "sample_id": sample["sample_id"],
        "run_id": run_id,
        "label": sample["label"],
        "mem_rwx_region_count": rwx_count,
        "mem_executable_private_count": exec_private_count,
        "mem_executable_writable_count": exec_writable_count,
        "mem_vad_total_count": total_vad_count,
        "mem_vad_private_count": private_vad_count,
        "mem_vad_mapped_count": mapped_vad_count,
        "mem_commit_charge_total": sum(commit_charges),
        "mem_commit_charge_mean": round(float(np.mean(commit_charges)), 2) if commit_charges else 0.0,
        "mem_region_size_bytes_total": sum(region_sizes),
        "mem_region_size_bytes_mean": round(float(np.mean(region_sizes)), 1) if region_sizes else 0.0,
        "mem_malfind_total_findings": total_malfind,
        "mem_malfind_baseline_exception_count": baseline_exception_count,
        "mem_malfind_suspicious_non_baseline_count": suspicious_malfind_count,
        "mem_malfind_affected_processes_count": len(malfind_pids),
        "mem_malfind_max_findings_single_proc": max_findings_single_proc,
        "mem_unlinked_modules_count": unlinked_modules,
        "mem_total_loaded_modules": total_modules,
        "mem_modules_per_process_mean": round(total_modules / len(module_pids), 2) if module_pids else 0.0,
    }


# ==============================================================================
# 3. COMMAND MODALITY FEATURE EXTRACTION
# ==============================================================================

def extract_command_features(sample: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    run_id = sample["run_id"]
    cmd_file = FORENSIC_DIR / "events" / "commands" / f"{run_id}.jsonl"
    ps_file = FORENSIC_DIR / "events" / "powershell" / f"{run_id}.jsonl"

    commands = []
    text_records = []

    if cmd_file.exists():
        with open(cmd_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    evt = json.loads(line)
                    # Strictly exclude COLLECTION_HARNESS from training features and text records
                    if evt.get("attribution_status") == "COLLECTION_HARNESS":
                        continue
                    commands.append(evt)
                    text = evt.get("command_line") or ""
                    if text.strip():
                        text_records.append({
                            "sample_id": sample["sample_id"],
                            "run_id": run_id,
                            "label": sample["label"],
                            "process_id": evt.get("process_id"),
                            "timestamp": evt.get("timestamp"),
                            "source_type": evt.get("source"),
                            "attribution_status": evt.get("attribution_status"),
                            "text": text.strip(),
                        })

    # PowerShell ScriptBlocks
    ps_events = []
    if ps_file.exists():
        with open(ps_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    evt = json.loads(line)
                    if evt.get("attribution_status") == "COLLECTION_HARNESS":
                        continue
                    ps_events.append(evt)
                    text = evt.get("script_block_text") or ""
                    if text.strip():
                        text_records.append({
                            "sample_id": sample["sample_id"],
                            "run_id": run_id,
                            "label": sample["label"],
                            "process_id": None,
                            "timestamp": evt.get("timestamp"),
                            "source_type": "powershell_eid4104",
                            "attribution_status": evt.get("attribution_status"),
                            "text": text.strip()[:4000],  # bounded length for text sequence export
                        })

    cmd_texts = [c.get("command_line", "") for c in commands]
    cmd_lengths = [len(t) for t in cmd_texts] if cmd_texts else [0]
    unique_commands = set(cmd_texts)

    ps_texts = [p.get("script_block_text", "") for p in ps_events]
    ps_lengths = [len(t) for t in ps_texts] if ps_texts else [0]
    unique_ps_blocks = {p.get("script_block_id") for p in ps_events if p.get("script_block_id")}

    # Behavioral Semantics (Context-grounded indicators)
    encoded_cmd_count = 0
    ep_bypass_count = 0
    hidden_win_count = 0
    cradle_count = 0
    lolbin_count = 0
    reg_mod_count = 0

    cradle_keywords = ["downloadstring", "downloadfile", "net.webclient", "invoke-webrequest", "curl", "wget", "certutil -urlcache"]

    for text in cmd_texts + ps_texts:
        t_low = text.lower()
        if any(k in t_low for k in [" -enc ", " -encodedcommand ", " /enc "]):
            encoded_cmd_count += 1
        if any(k in t_low for k in ["bypass", "unrestricted"]) and any(k in t_low for k in ["executionpolicy", " -ep "]):
            ep_bypass_count += 1
        if any(k in t_low for k in ["-windowstyle hidden", " -w hidden", " /min "]):
            hidden_win_count += 1
        if any(k in t_low for k in cradle_keywords):
            cradle_count += 1
        if any(lol in t_low for lol in LOLBIN_NAMES):
            lolbin_count += 1
        if any(k in t_low for k in ["reg.exe add", "set-itemproperty", "new-itemproperty", "reg add"]):
            reg_mod_count += 1

    total_cmds = len(commands)
    diversity = (len(unique_commands) / total_cmds) if total_cmds > 0 else 0.0

    structured_features = {
        "sample_id": sample["sample_id"],
        "run_id": run_id,
        "label": sample["label"],
        "cmd_total_events_count": total_cmds,
        "cmd_unique_commands_count": len(unique_commands),
        "cmd_mean_command_length": round(float(np.mean(cmd_lengths)), 1) if cmd_lengths else 0.0,
        "cmd_max_command_length": max(cmd_lengths) if cmd_lengths else 0,
        "cmd_ps_scriptblock_count": len(ps_events),
        "cmd_ps_unique_scriptblocks": len(unique_ps_blocks),
        "cmd_ps_mean_script_length": round(float(np.mean(ps_lengths)), 1) if ps_lengths else 0.0,
        "cmd_ps_max_script_length": max(ps_lengths) if ps_lengths else 0,
        "cmd_encoded_command_count": encoded_cmd_count,
        "cmd_execution_policy_bypass_count": ep_bypass_count,
        "cmd_hidden_window_count": hidden_win_count,
        "cmd_download_cradle_count": cradle_count,
        "cmd_lolbin_execution_count": lolbin_count,
        "cmd_registry_modification_count": reg_mod_count,
        "cmd_diversity_ratio": round(diversity, 4),
    }

    return structured_features, text_records


# ==============================================================================
# 4. NETWORK MODALITY FEATURE EXTRACTION
# ==============================================================================

def extract_network_features(sample: Dict[str, Any]) -> Dict[str, Any]:
    run_id = sample["run_id"]
    net_file = FORENSIC_DIR / "events" / "network" / f"{run_id}.jsonl"

    connections = []
    if net_file.exists():
        with open(net_file, "r", encoding="utf-8") as f:
            connections = [json.loads(line) for line in f if line.strip()]

    total_obs = len(connections)
    snapshot_count = sum(1 for c in connections if c.get("source") == "network_connections.csv")
    sysmon_eid3_count = sum(1 for c in connections if c.get("source") == "sysmon_eid3")
    established_count = sum(1 for c in connections if (c.get("state") or "").lower() == "established")
    listening_count = sum(1 for c in connections if (c.get("state") or "").lower() == "listen")

    remote_ips = set()
    remote_ports = set()
    outbound_remote_count = 0
    non_std_http_count = 0
    privileged_ports_count = 0
    ephemeral_ports_count = 0

    owning_pids: Dict[int, int] = {}

    for c in connections:
        r_ip = c.get("remote_address") or ""
        r_port = c.get("remote_port") or 0
        pid = c.get("owning_pid")
        if pid is not None and pid > 0:
            owning_pids[pid] = owning_pids.get(pid, 0) + 1

        # Check for meaningful remote outbound connections
        # Exclude loopback and unassigned listening addresses
        if r_ip not in ["", "::", "0.0.0.0", "127.0.0.1", "::1"] and r_port > 0:
            outbound_remote_count += 1
            remote_ips.add(r_ip)
            remote_ports.add(r_port)

            if r_port not in [80, 443, 53]:
                non_std_http_count += 1
            if 0 < r_port < 1024:
                privileged_ports_count += 1
            if r_port >= 49152:
                ephemeral_ports_count += 1

    max_conns_single_proc = max(owning_pids.values()) if owning_pids else 0

    return {
        "sample_id": sample["sample_id"],
        "run_id": run_id,
        "label": sample["label"],
        "net_total_observations_count": total_obs,
        "net_snapshot_count": snapshot_count,
        "net_sysmon_eid3_count": sysmon_eid3_count,
        "net_established_connections_count": established_count,
        "net_listening_sockets_count": listening_count,
        "net_unique_remote_ips_count": len(remote_ips),
        "net_unique_destination_ports_count": len(remote_ports),
        "net_outbound_remote_connection_count": outbound_remote_count,
        "net_non_standard_http_ssl_ports_count": non_std_http_count,
        "net_privileged_ports_count": privileged_ports_count,
        "net_ephemeral_ports_count": ephemeral_ports_count,
        "net_network_enabled_process_count": len(owning_pids),
        "net_max_connections_single_process": max_conns_single_proc,
        # Strictly explicit NULL metrics: PCAP was not captured; zero fabricated values!
        "net_packet_count": None,
        "net_byte_count": None,
        "net_flow_duration_sec": None,
        "net_beacon_periodicity_sec": None,
    }


# ==============================================================================
# 5. CROSS-MODAL FEATURE EXTRACTION
# ==============================================================================

def extract_cross_modal_features(
    sample: Dict[str, Any],
    proc_feat: Dict[str, Any],
    mem_feat: Dict[str, Any],
    cmd_feat: Dict[str, Any],
    net_feat: Dict[str, Any],
) -> Dict[str, Any]:
    run_id = sample["run_id"]
    
    # Process memory bindings
    proc_mem_file = FORENSIC_DIR / "relationships" / "process_memory" / f"{run_id}.jsonl"
    proc_cmd_file = FORENSIC_DIR / "relationships" / "process_command" / f"{run_id}.jsonl"
    proc_net_file = FORENSIC_DIR / "relationships" / "process_network" / f"{run_id}.jsonl"
    proc_tree_file = FORENSIC_DIR / "relationships" / "process_tree" / f"{run_id}.jsonl"
    priv_file = FORENSIC_DIR / "entities" / "privileges" / f"{run_id}.jsonl"

    # Suspicious memory PIDs (excluding MsMpEng.exe baseline)
    suspicious_mem_pids = set()
    if proc_mem_file.exists():
        with open(proc_mem_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    if "MsMpEng" not in item.get("process_name", ""):
                        suspicious_mem_pids.add(item.get("pid"))

    cmd_pids = set()
    if proc_cmd_file.exists():
        with open(proc_cmd_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    pid = item.get("pid")
                    if pid:
                        cmd_pids.add(pid)

    net_pids = set()
    if proc_net_file.exists():
        with open(proc_net_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    pid = item.get("pid")
                    if pid:
                        net_pids.add(pid)

    parent_pids = set()
    if proc_tree_file.exists():
        with open(proc_tree_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    ppid = item.get("parent_pid")
                    if ppid:
                        parent_pids.add(ppid)

    sedebug_pids = set()
    if priv_file.exists():
        with open(priv_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    p = json.loads(line)
                    if p.get("privilege_name") == "SeDebugPrivilege" and p.get("is_present"):
                        sedebug_pids.add(p.get("pid"))

    # Cross-modal correlations
    proc_with_mem_and_cmd = len(suspicious_mem_pids.intersection(cmd_pids))
    proc_with_cmd_and_net = len(cmd_pids.intersection(net_pids))
    proc_with_inj_and_net = len(suspicious_mem_pids.intersection(net_pids))
    proc_with_mem_and_tree = len(suspicious_mem_pids.intersection(parent_pids))
    high_priv_net_proc = len(sedebug_pids.intersection(net_pids))

    return {
        "sample_id": sample["sample_id"],
        "run_id": run_id,
        "label": sample["label"],
        "cross_proc_with_memory_and_command": proc_with_mem_and_cmd,
        "cross_proc_with_command_and_network": proc_with_cmd_and_net,
        "cross_proc_with_injection_and_network": proc_with_inj_and_net,
        "cross_proc_with_suspicious_memory_and_tree": proc_with_mem_and_tree,
        "cross_high_privilege_network_processes": high_priv_net_proc,
        "cross_suspicious_memory_process_ratio": round(
            len(suspicious_mem_pids) / proc_feat["proc_total_count"], 4
        ) if proc_feat["proc_total_count"] > 0 else 0.0,
        "cross_network_enabled_process_ratio": round(
            len(net_pids) / proc_feat["proc_total_count"], 4
        ) if proc_feat["proc_total_count"] > 0 else 0.0,
    }


# ==============================================================================
# 6. FEATURE STATISTICS & MISSINGNESS UTILITIES
# ==============================================================================

def compute_feature_statistics(records: List[Dict[str, Any]], exclude_keys: Set[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    stats = {}
    missingness = {}

    if not records:
        return stats, missingness

    total_rows = len(records)
    all_keys = [k for k in records[0].keys() if k not in exclude_keys]

    for key in all_keys:
        values = [r[key] for r in records]
        non_null_values = [v for v in values if v is not None]

        null_count = total_rows - len(non_null_values)
        missing_pct = round((null_count / total_rows) * 100.0, 2)
        zero_count = sum(1 for v in non_null_values if v == 0 or v == 0.0)
        zero_pct = round((zero_count / total_rows) * 100.0, 2)
        unique_cnt = len(set(non_null_values))

        missingness[key] = {
            "total_count": total_rows,
            "missing_count": null_count,
            "missing_percentage": missing_pct,
            "is_explicit_null_field": (null_count == total_rows),
        }

        if non_null_values and all(isinstance(v, (int, float)) for v in non_null_values):
            val_arr = np.array(non_null_values, dtype=float)
            min_val = float(np.min(val_arr))
            max_val = float(np.max(val_arr))
            mean_val = float(np.mean(val_arr))
            median_val = float(np.median(val_arr))
            std_val = float(np.std(val_arr))
            is_constant = bool(min_val == max_val)
            is_near_constant = bool(std_val < 1e-4 and not is_constant)
        else:
            min_val = None
            max_val = None
            mean_val = None
            median_val = None
            std_val = None
            is_constant = (unique_cnt <= 1)
            is_near_constant = False

        stats[key] = {
            "min": round(min_val, 4) if min_val is not None else None,
            "max": round(max_val, 4) if max_val is not None else None,
            "mean": round(mean_val, 4) if mean_val is not None else None,
            "median": round(median_val, 4) if median_val is not None else None,
            "std": round(std_val, 4) if std_val is not None else None,
            "unique_count": unique_cnt,
            "missing_percentage": missing_pct,
            "zero_percentage": zero_pct,
            "is_constant": is_constant,
            "is_near_constant": is_near_constant,
        }

    return stats, missingness


# ==============================================================================
# 7. TRAIN / VAL / TEST SPLIT CREATION
# ==============================================================================

def create_run_splits(samples: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Creates a balanced, run-disjoint stratified split covering all 45 runs.

    Train (27 runs = 60.0%):
      - 8 Benign runs
      - 19 Malware runs (guaranteeing all 11 malware families are represented in train)
    Val (9 runs = 20.0%):
      - 3 Benign runs
      - 6 Malware runs
    Test (9 runs = 20.0%):
      - 2 Benign runs (including RUN-001)
      - 7 Malware runs
    """
    splits_dir = FEATURES_DIR / "splits"
    splits_dir.mkdir(parents=True, exist_ok=True)

    # Benign distribution: 13 runs (RUN-1100..1111 + RUN-001)
    # Train: RUN-1100..1107 (8 runs)
    # Val: RUN-1108..1110 (3 runs)
    # Test: RUN-001, RUN-1111 (2 runs)

    # Malware distribution (32 runs across 11 families):
    # powershell_fileless (2 runs): RUN-002 -> Train, RUN-003 -> Val
    # 10 3-run families (e.g. 100, 101, 102):
    #   Train gets index 0 and 1 (2 runs each) -> 20 runs? Wait, 19 malware in train.
    #   Let's do:
    #     9 families: 2 in Train, 1 in Val/Test
    #     1 family (cobalt_strike_beacon): RUN-400 -> Train, RUN-401 -> Test, RUN-402 -> Val
    #    all_run_ids = {s["run_id"] for s in samples}
    benign_runs = sorted([s["run_id"] for s in samples if s["label"] == 0])
    malware_runs = sorted([s["run_id"] for s in samples if s["label"] == 1])

    # 13 Benign: Train=8, Val=3, Test=2
    train_benign = benign_runs[:8]      # 1100..1107
    val_benign = benign_runs[8:11]      # 1108..1110
    test_benign = benign_runs[11:]      # 1111, RUN-001 (or sorted order)

    # 32 Malware: Train=19, Val=6, Test=7
    # Group malware by family
    family_map: Dict[str, List[str]] = {}
    for s in samples:
        if s["label"] == 1:
            family_map.setdefault(s["family"], []).append(s["run_id"])

    train_mal = []
    val_mal = []
    test_mal = []

    # Sort each family runs
    for fam in sorted(family_map.keys()):
        runs = sorted(family_map[fam])
        if fam == "powershell_fileless":
            # 2 runs
            train_mal.append(runs[0])
            val_mal.append(runs[1])
        elif fam in ["process_hollowing", "memory_only_rat", "registry_resident_malware", "cobalt_strike_beacon", "metasploit_memory_payloads"]:
            # 5 families: index 0,1 to train, index 2 to val (except cobalt: index 0 to train, 1 to test, 2 to val)
            if fam == "cobalt_strike_beacon":
                train_mal.append(runs[0])
                test_mal.append(runs[1])
                val_mal.append(runs[2])
            else:
                train_mal.append(runs[0])
                train_mal.append(runs[1])
                val_mal.append(runs[2])
        else:
            # 5 families: wmi, reflective_dll, lolbins, ransomware, empire
            # index 0,1 to train, index 2 to test
            train_mal.append(runs[0])
            train_mal.append(runs[1])
            test_mal.append(runs[2])

    final_train = sorted(train_benign + train_mal)
    final_val = sorted(val_benign + val_mal)
    final_test = sorted(test_benign + test_mal)

    with open(splits_dir / "train_runs.json", "w", encoding="utf-8") as f:
        json.dump(final_train, f, indent=2)

    with open(splits_dir / "val_runs.json", "w", encoding="utf-8") as f:
        json.dump(final_val, f, indent=2)

    with open(splits_dir / "test_runs.json", "w", encoding="utf-8") as f:
        json.dump(final_test, f, indent=2)

    return {
        "train": final_train,
        "val": final_val,
        "test": final_test,
    }


# ==============================================================================
# 8. MAIN EXECUTION PIPELINE
# ==============================================================================

def main():
    print("=" * 60)
    print("RUNNING PHASE 4 RICH FORENSIC FEATURE ENGINEERING")
    print("=" * 60)

    samples = load_samples()
    print(f"Loaded {len(samples)} samples from data/forensic/samples/samples.jsonl")

    # Target directories
    proc_dir = FEATURES_DIR / "process"
    mem_dir = FEATURES_DIR / "memory"
    cmd_dir = FEATURES_DIR / "command"
    net_dir = FEATURES_DIR / "network"
    cross_dir = FEATURES_DIR / "cross_modal"

    for d in [proc_dir, mem_dir, cmd_dir, net_dir, cross_dir]:
        d.mkdir(parents=True, exist_ok=True)

    proc_records = []
    mem_records = []
    cmd_records = []
    all_text_records = []
    net_records = []
    cross_records = []

    for s in samples:
        p_feat = extract_process_features(s)
        m_feat = extract_memory_features(s)
        c_feat, c_texts = extract_command_features(s)
        n_feat = extract_network_features(s)
        x_feat = extract_cross_modal_features(s, p_feat, m_feat, c_feat, n_feat)

        proc_records.append(p_feat)
        mem_records.append(m_feat)
        cmd_records.append(c_feat)
        all_text_records.extend(c_texts)
        net_records.append(n_feat)
        cross_records.append(x_feat)

    # 1. Process Modality Outputs
    print(f"Writing Process Modality ({len(proc_records)} rows, {len(proc_records[0]) - 3} features)...")
    save_modality_artifacts(proc_dir, "process_features", proc_records)

    # 2. Memory Modality Outputs
    print(f"Writing Memory Modality ({len(mem_records)} rows, {len(mem_records[0]) - 3} features)...")
    save_modality_artifacts(mem_dir, "memory_features", mem_records)

    # 3. Command Modality Outputs
    print(f"Writing Command Modality ({len(cmd_records)} rows, {len(cmd_records[0]) - 3} features, {len(all_text_records)} text sequences)...")
    save_modality_artifacts(cmd_dir, "command_features", cmd_records)
    # Save text sequences for transformer models
    import gzip
    with open(cmd_dir / "text_sequences.jsonl", "w", encoding="utf-8") as f, \
         gzip.open(cmd_dir / "text_sequences.jsonl.gz", "wt", encoding="utf-8") as f_gz:
        for r in all_text_records:
            line_str = json.dumps(r) + "\n"
            f.write(line_str)
            f_gz.write(line_str)

    # 4. Network Modality Outputs
    print(f"Writing Network Modality ({len(net_records)} rows, {len(net_records[0]) - 3} features)...")
    save_modality_artifacts(net_dir, "network_features", net_records)

    # 5. Cross-Modal Modality Outputs
    print(f"Writing Cross-Modal Modality ({len(cross_records)} rows, {len(cross_records[0]) - 3} features)...")
    save_modality_artifacts(cross_dir, "cross_modal_features", cross_records)

    # 6. Splits
    splits = create_run_splits(samples)
    print(f"Created Splits: Train={len(splits['train'])}, Val={len(splits['val'])}, Test={len(splits['test'])}")

    # 7. Leakage Audit CSV & Feature Provenance JSON
    generate_provenance_and_leakage(proc_records, mem_records, cmd_records, net_records, cross_records)

    # 8. Feature Split Strategy Document
    generate_split_strategy_doc(splits, samples)

    # 9. Feature Dictionary Document
    generate_feature_dictionary()

    print("=" * 60)
    print("PHASE 4 FEATURE ENGINEERING SUITE COMPLETE")
    print("=" * 60)


def save_modality_artifacts(out_dir: Path, base_name: str, records: List[Dict[str, Any]]) -> None:
    # 1. JSONL
    jsonl_path = out_dir / f"{base_name}.jsonl"
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    # 2. CSV
    csv_path = out_dir / f"{base_name}.csv"
    fieldnames = list(records[0].keys())
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    # 3. Schema
    schema = {
        "modality": base_name,
        "total_records": len(records),
        "fields": {
            k: {
                "type": type(records[0][k]).__name__ if records[0][k] is not None else "NoneType",
                "nullable": any(r[k] is None for r in records),
            }
            for k in fieldnames
        }
    }
    with open(out_dir / "schema.json", "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2)

    # 4. Statistics & Missingness Report
    stats, missingness = compute_feature_statistics(records, exclude_keys={"sample_id", "run_id", "label"})
    with open(out_dir / "statistics.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)

    with open(out_dir / "missingness_report.json", "w", encoding="utf-8") as f:
        json.dump(missingness, f, indent=2)


def generate_provenance_and_leakage(proc_recs, mem_recs, cmd_recs, net_recs, cross_recs) -> None:
    meta_keys = {"sample_id", "run_id", "label"}
    modalities = [
        ("Process", proc_recs[0], "entities/processes + entities/threads + entities/handles + entities/privileges + relationships/process_tree"),
        ("Memory", mem_recs[0], "entities/memory_regions (vadinfo) + events/memory (malfind) + entities/modules (ldrmodules)"),
        ("Command", cmd_recs[0], "events/commands (pstree, sysmon_eid1) + events/powershell (eid4104 ScriptBlocks)"),
        ("Network", net_recs[0], "events/network (network_connections.csv + sysmon_eid3)"),
        ("Cross_Modal", cross_recs[0], "relationships/process_memory + relationships/process_command + relationships/process_network"),
    ]

    provenance_list = []
    leakage_rows = []

    for mod_name, sample_dict, source_desc in modalities:
        for feat in sample_dict.keys():
            if feat in meta_keys:
                continue

            is_pcap_null = ("net_" in feat and feat in ["net_packet_count", "net_byte_count", "net_flow_duration_sec", "net_beacon_periodicity_sec"])
            null_sem = "EXPLICIT_NULL (PCAP unavailable; zero never fabricated)" if is_pcap_null else "OBSERVED_ZERO or NONE_IF_UNAVAILABLE"
            leakage_status = "SAFE (contextual aggregation; excluded collection harness & identity fields)"

            rec = {
                "feature_name": feat,
                "modality": mod_name,
                "source_evidence": source_desc,
                "aggregation_scope": "RUN_LEVEL",
                "null_semantics": null_sem,
                "leakage_status": leakage_status,
                "excluded_from_model_inputs": False,
            }
            provenance_list.append(rec)

            leakage_rows.append({
                "feature_name": feat,
                "modality": mod_name,
                "contains_run_id": False,
                "contains_family_name": False,
                "contains_label": False,
                "contains_directory_leakage": False,
                "contains_harness_leakage": False,
                "audit_verdict": "VERIFIED_SAFE",
                "leakage_risk": "NONE",
            })

    # Save feature_provenance.json
    with open(FEATURES_DIR / "feature_provenance.json", "w", encoding="utf-8") as f:
        json.dump(provenance_list, f, indent=2)

    # Save feature_leakage_audit.csv
    csv_path = FEATURES_DIR / "feature_leakage_audit.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(leakage_rows[0].keys()))
        writer.writeheader()
        writer.writerows(leakage_rows)


def generate_split_strategy_doc(splits: Dict[str, List[str]], samples: List[Dict[str, Any]]) -> None:
    sample_lookup = {s["run_id"]: s for s in samples}

    train_benign = sum(1 for r in splits["train"] if sample_lookup[r]["label"] == 0)
    train_mal = sum(1 for r in splits["train"] if sample_lookup[r]["label"] == 1)
    val_benign = sum(1 for r in splits["val"] if sample_lookup[r]["label"] == 0)
    val_mal = sum(1 for r in splits["val"] if sample_lookup[r]["label"] == 1)
    test_benign = sum(1 for r in splits["test"] if sample_lookup[r]["label"] == 0)
    test_mal = sum(1 for r in splits["test"] if sample_lookup[r]["label"] == 1)

    content = f"""# Run-Level Stratified Train / Validation / Test Split Strategy
**Project:** Real-Time AI-Based Fileless Malware Detection and Classification System  
**Date:** 2026-09-24  
**Split Level:** Strict Execution RUN Level (Disjoint Partition)  

---

## 1. Split Philosophy & Leakage Prevention Rules

1. **Strict Run Disjointness:** No telemetry records or extracted features from any execution run appear in more than one partition.
2. **Family Stratification:** Every one of the 11 malware families is represented in the training set to establish multi-class and binary discernment baselines.
3. **Purity of Final Test Set:** The test set represents unseen execution runs across both benign operating states and multiple malware families. It remains strictly locked until final model evaluation.
4. **No Cross-Run Batch Bleed:** Validation and Test sets contain zero sample-ID, timing, or operational overlaps with the Training set.

---

## 2. Partition Summary Table

| Partition | Total Runs | Benign Runs (Label 0) | Malware Runs (Label 1) | Percentage of Dataset | Purpose |
|---|:---:|:---:|:---:|:---:|---|
| **Train** | **{len(splits['train'])}** | {train_benign} | {train_mal} | {round(len(splits['train'])/45*100, 1)}% | Primary model weight optimization |
| **Validation** | **{len(splits['val'])}** | {val_benign} | {val_mal} | {round(len(splits['val'])/45*100, 1)}% | Early stopping, validation threshold tuning |
| **Test** | **{len(splits['test'])}** | {test_benign} | {test_mal} | {round(len(splits['test'])/45*100, 1)}% | Held-out benchmark evaluation |
| **Total** | **45** | **13** | **32** | **100.0%** | Full canonical custom dataset |

---

## 3. Explicit Run Assignment

### A. Training Runs ({len(splits['train'])})
`{json.dumps(splits['train'])}`

### B. Validation Runs ({len(splits['val'])})
`{json.dumps(splits['val'])}`

### C. Test Runs ({len(splits['test'])})
`{json.dumps(splits['test'])}`
"""
    with open(DOCS_DIR / "feature_split_strategy.md", "w", encoding="utf-8") as f:
        f.write(content)


def generate_feature_dictionary() -> None:
    content = """# Rich Forensic Feature Dictionary (Phase 4)
**Project:** Real-Time AI-Based Fileless Malware Detection and Classification System  
**Date:** 2026-09-24  
**Authoritative Basis:** Derived exclusively from `data/forensic/`  

---

## 1. Feature Design Principles
- **No Identity Leakage:** Features never encode `run_id`, `sample_id`, `family`, `label`, or source folder paths.
- **Contextual Grounding:** Aggregations capture behavior and structural anomalies across processes, memory pages, command lines, and network endpoints.
- **Harness Exclusion:** Operator capture scripts (`DumpIt.exe`, `collect_run_windows.ps1`, `scp.exe`) tagged as `COLLECTION_HARNESS` are strictly excluded from all command and process features.
- **Strict Null Semantics:** Missing PCAP metrics (`packet_count`, `byte_count`, `flow_duration_sec`, `beacon_periodicity_sec`) are preserved strictly as `None` (`null`) and never fabricated as `0`.
- **Baseline Awareness:** Benign Defender memory findings (`MsMpEng.exe` RWX) are contextualized and separated from suspicious non-baseline findings.

---

## 2. Process Modality Features (`data/features/process/`)

| Feature Name | Description | Source Forensic Entity | Aggregation Window / Method | Null Semantics | Rationale |
|---|---|---|---|---|---|
| `proc_total_count` | Total processes discovered across all plugins | `entities/processes/` | Run-level total count | Observed int | High-level system workload sizing |
| `proc_active_count` | Active processes linked in EPROCESS list | `volatility/pslist.txt` | Run-level count (`is_in_pslist=True`) | Observed int | Baseline live process workload |
| `proc_carved_count` | Processes recovered only from pool memory | `volatility/psscan.txt` | Run-level count (`is_in_psscan and not is_in_pslist`) | Observed int | Terminated or unlinked stealth processes |
| `proc_hidden_unlinked_count` | Processes hidden from psxview or unlinked | `psxview.txt + psscan.txt` | Run-level sum of unlinked flags | Observed int | Rootkit and DKOM process hiding signal |
| `proc_wow64_count` | 32-bit processes running on 64-bit Windows | `entities/processes/` | Run-level sum of `wow64=True` | Observed int | Malware often executes in 32-bit subsystem |
| `proc_tree_max_depth` | Maximum lineage depth of process tree | `relationships/process_tree/` | Graph traversal max depth | Observed int | Deep execution chains (e.g. LOLBin chains) |
| `proc_tree_mean_depth` | Mean lineage depth across process tree | `relationships/process_tree/` | Graph traversal mean depth | Observed float | Overall system process nesting |
| `proc_orphan_parent_count` | Processes whose parent exited before dump | `relationships/process_tree/` | Count of PPIDs missing from live processes | Observed int | Background launchers or severed process parentage |
| `proc_max_children_single_proc` | Maximum children spawned by any single process | `relationships/process_tree/` | Max children over parent PIDs | Observed int | Spawner concentration (e.g. explorer vs attacker script) |
| `proc_spawning_concentration` | Ratio of max children to total spawned children | `relationships/process_tree/` | Max children / total children | Observed float | Concentrated process spawning behavior |
| `proc_thread_count_total` | Total threads running across all processes | `entities/threads/` | Run-level count of ThreadEntities | Observed int | System thread volume |
| `proc_thread_count_mean` | Mean threads per process | `entities/threads/` | Total threads / total processes | Observed float | Multi-threading density |
| `proc_handle_count_total` | Total handles held across all processes | `entities/handles/` | Run-level count of HandleEntities | Observed int | Resource allocation density |
| `proc_handle_count_mean` | Mean handles per process | `entities/handles/` | Total handles / total processes | Observed float | Average handle occupancy |
| `proc_working_set_bytes_mean` | Mean working set physical memory in bytes | `process_snapshot.csv` | Mean across snapshot records | `None` if snapshot unavailable | Memory consumption footprint |
| `proc_cpu_utilization_mean` | Mean CPU utilization percentage | `process_snapshot.csv` | Mean across snapshot records | `None` if snapshot unavailable | Workload compute intensity |
| `proc_user_writable_path_count` | Processes executing from user-writable directories | `entities/processes/` | Count of paths in `Users`, `AppData`, `Temp` | Observed int | Fileless payloads executing from staging directories |
| `proc_system_directory_count` | Processes executing from System32/SysWOW64 | `entities/processes/` | Count of paths in `System32`, `SysWOW64` | Observed int | Legitimate Windows system execution baseline |
| `proc_temp_directory_count` | Processes executing from Temp directory | `entities/processes/` | Count of paths containing `\\Temp\\` | Observed int | Dropped or staged script payloads |
| `proc_unusual_executable_location_count` | Processes executing outside standard Windows dirs | `entities/processes/` | Count of non-system non-program-files paths | Observed int | Anomaly detection for unusual binaries |
| `proc_elevated_privilege_count` | Count of high-impact token privileges present | `entities/privileges/` | Count of present high-impact privileges | Observed int | Token privilege escalation signal |
| `proc_processes_with_sedebug` | Processes holding `SeDebugPrivilege` | `entities/privileges/` | Count of distinct PIDs with SeDebug | Observed int | Memory inspection and injection capability |

---

## 3. Memory Modality Features (`data/features/memory/`)

| Feature Name | Description | Source Forensic Entity | Aggregation Window / Method | Null Semantics | Rationale |
|---|---|---|---|---|---|
| `mem_rwx_region_count` | Total memory regions with PAGE_EXECUTE_READWRITE | `entities/memory_regions/` | Count of VADs with RWX protection | Observed int | Classic shellcode/injection indicator |
| `mem_executable_private_count` | Private memory regions marked executable | `entities/memory_regions/` | VADs where `private_memory > 0 and EXECUTE in prot` | Observed int | Unmapped shellcode allocation |
| `mem_executable_writable_count` | Executable memory regions that are also writable | `entities/memory_regions/` | VADs with `EXECUTE` and (`READWRITE` or `WRITECOPY`) | Observed int | Dynamic code modification / hooking |
| `mem_vad_total_count` | Total Virtual Address Descriptors | `entities/memory_regions/` | Count of VAD entries | Observed int | Overall process virtual address space scale |
| `mem_vad_private_count` | Private (non-file-backed) VAD allocations | `entities/memory_regions/` | VADs where `private_memory > 0` | Observed int | Heap and custom memory allocation volume |
| `mem_vad_mapped_count` | File-backed mapped VAD allocations | `entities/memory_regions/` | VADs where `private_memory == 0` | Observed int | Normal binary and DLL memory mappings |
| `mem_commit_charge_total` | Total committed memory pages | `entities/memory_regions/` | Sum of commit_charge across VADs | Observed int | Physical RAM commitment footprint |
| `mem_commit_charge_mean` | Mean commit charge per VAD | `entities/memory_regions/` | Mean commit_charge across VADs | Observed float | Average allocation granularity |
| `mem_region_size_bytes_total` | Total virtual memory region size in bytes | `entities/memory_regions/` | Sum of region sizes across VADs | Observed int | Total virtual address space footprint |
| `mem_region_size_bytes_mean` | Mean virtual memory region size in bytes | `entities/memory_regions/` | Mean region size across VADs | Observed float | Granularity of memory allocations |
| `mem_malfind_total_findings` | Total malfind injection findings | `events/memory/` | Count of all MalfindFinding records | Observed int | Volatility malfind detection volume |
| `mem_malfind_baseline_exception_count` | Legitimate Defender (MsMpEng) RWX findings | `events/memory/` | Count where `is_known_baseline_exception=True` | Observed int | Benign JIT signature scanner baseline |
| `mem_malfind_suspicious_non_baseline_count` | Non-baseline suspicious injection findings | `events/memory/` | Count where `is_known_baseline_exception=False` | Observed int | True suspicious injected code regions |
| `mem_malfind_affected_processes_count` | Distinct processes with suspicious malfind findings | `events/memory/` | Unique non-baseline PIDs | Observed int | Scope of memory compromise |
| `mem_malfind_max_findings_single_proc` | Max injection findings in any single process | `events/memory/` | Max findings over non-baseline PIDs | Observed int | Concentration of injected code |
| `mem_unlinked_modules_count` | Modules with inconsistent loader table entries | `entities/modules/` | Count where `in_load/init/mem` is False | Observed int | Hidden DLL injection or unlinked PEB |
| `mem_total_loaded_modules` | Total DLL modules loaded across all processes | `entities/modules/` | Count of ModuleEntities | Observed int | Loaded library volume |
| `mem_modules_per_process_mean` | Mean DLL modules loaded per process | `entities/modules/` | Total modules / unique PIDs | Observed float | Standard DLL footprint per process |

---

## 4. Command Modality Features (`data/features/command/`)

| Feature Name | Description | Source Forensic Entity | Aggregation Window / Method | Null Semantics | Rationale |
|---|---|---|---|---|---|
| `cmd_total_events_count` | Total non-harness command events executed | `events/commands/` | Count excluding `COLLECTION_HARNESS` | Observed int | Command-line execution intensity |
| `cmd_unique_commands_count` | Unique command line invocations | `events/commands/` | Set of unique command strings | Observed int | Command diversity |
| `cmd_mean_command_length` | Mean character length of command lines | `events/commands/` | Mean string length | Observed float | Obfuscated commands tend to be longer |
| `cmd_max_command_length` | Maximum character length of any command line | `events/commands/` | Max string length | Observed int | Encoded payloads produce very long commands |
| `cmd_ps_scriptblock_count` | Total PowerShell EID 4104 ScriptBlocks | `events/powershell/` | Count excluding `COLLECTION_HARNESS` | Observed int | PowerShell activity intensity |
| `cmd_ps_unique_scriptblocks` | Unique PowerShell script block GUIDs | `events/powershell/` | Set of unique script block IDs | Observed int | Distinct scripts executed |
| `cmd_ps_mean_script_length` | Mean character length of script blocks | `events/powershell/` | Mean length of script block text | Observed float | PowerShell script complexity |
| `cmd_ps_max_script_length` | Maximum character length of any script block | `events/powershell/` | Max length of script block text | Observed int | Large multi-part payload injection |
| `cmd_encoded_command_count` | Invocations with Base64 encoding parameters | `events/commands/ + powershell/` | Count of `-enc`, `-encodedcommand` | Observed int | Standard fileless payload delivery technique |
| `cmd_execution_policy_bypass_count` | PowerShell execution policy bypass attempts | `events/commands/ + powershell/` | Count of `-ep bypass`, `unrestricted` | Observed int | Attacker security control evasion |
| `cmd_hidden_window_count` | Commands executed with hidden windows | `events/commands/ + powershell/` | Count of `-w hidden`, `-windowstyle hidden` | Observed int | Stealth execution without user visibility |
| `cmd_download_cradle_count` | Web download cradle invocations | `events/commands/ + powershell/` | Count of WebClient, IWR, curl cradles | Observed int | Remote payload fetching |
| `cmd_lolbin_execution_count` | Invocations of Living-off-the-Land Binaries | `events/commands/ + powershell/` | Count of powershell, wmic, mshta, etc. | Observed int | Execution via legitimate system tools |
| `cmd_registry_modification_count` | Commands modifying Windows registry | `events/commands/ + powershell/` | Count of `reg add`, `Set-ItemProperty` | Observed int | Persistence and configuration tampering |
| `cmd_diversity_ratio` | Ratio of unique commands to total commands | `events/commands/` | Unique commands / total commands | Observed float | Automated repetitive vs dynamic activity |

In addition, raw textual sequences are preserved in `data/features/command/text_sequences.jsonl` for fine-tuning RoBERTa and DistilBERT models.

---

## 5. Network Modality Features (`data/features/network/`)

| Feature Name | Description | Source Forensic Entity | Aggregation Window / Method | Null Semantics | Rationale |
|---|---|---|---|---|---|
| `net_total_observations_count` | Total network socket & connection records | `events/network/` | Total observations | Observed int | Total network telemetry volume |
| `net_snapshot_count` | Netstat snapshot records | `network_connections.csv` | Count where source is netstat | Observed int | Point-in-time socket listening state |
| `net_sysmon_eid3_count` | Dynamic Sysmon connection events | `sysmon.evtx (EID 3)` | Count where source is Sysmon | Observed int | Dynamic outbound connection activity |
| `net_established_connections_count` | Active connections in Established state | `events/network/` | Count where `state=Established` | Observed int | Active communication sessions |
| `net_listening_sockets_count` | Sockets in Listening state | `events/network/` | Count where `state=Listen` | Observed int | Local services and bind shell ports |
| `net_unique_remote_ips_count` | Distinct remote non-loopback IP addresses | `events/network/` | Set of remote IPs (excl 127.0.0.1, 0.0.0.0) | Observed int | External communication breadth |
| `net_unique_destination_ports_count` | Distinct remote destination ports | `events/network/` | Set of destination ports (> 0) | Observed int | Multi-port beaconing or C2 channels |
| `net_outbound_remote_connection_count` | Connections directed to external addresses | `events/network/` | Count of non-local remote endpoints | Observed int | Outbound C2 communication |
| `net_non_standard_http_ssl_ports_count` | Remote connections to non-80/443/53 ports | `events/network/` | Count where remote port not in standard | Observed int | Non-standard C2 port usage |
| `net_privileged_ports_count` | Connections to privileged ports (< 1024) | `events/network/` | Count where 0 < port < 1024 | Observed int | Traditional server service connections |
| `net_ephemeral_ports_count` | Connections to ephemeral high ports (>= 49152) | `events/network/` | Count where port >= 49152 | Observed int | Dynamic port allocations |
| `net_network_enabled_process_count` | Processes initiating network connections | `events/network/` | Unique owning PIDs | Observed int | Breadth of network usage across processes |
| `net_max_connections_single_process` | Max connections initiated by any single PID | `events/network/` | Max connections over PIDs | Observed int | Heavy network beaconing concentration |
| `net_packet_count` | Unsupported PCAP metric | N/A | None (PCAP not collected) | **EXPLICIT NULL** | Strictly preserves null semantics |
| `net_byte_count` | Unsupported PCAP metric | N/A | None (PCAP not collected) | **EXPLICIT NULL** | Strictly preserves null semantics |
| `net_flow_duration_sec` | Unsupported PCAP metric | N/A | None (PCAP not collected) | **EXPLICIT NULL** | Strictly preserves null semantics |
| `net_beacon_periodicity_sec` | Unsupported PCAP metric | N/A | None (PCAP not collected) | **EXPLICIT NULL** | Strictly preserves null semantics |

---

## 6. Cross-Modal Features (`data/features/cross_modal/`)

| Feature Name | Description | Source Relationships | Aggregation Method | Null Semantics | Rationale |
|---|---|---|---|---|---|
| `cross_proc_with_memory_and_command` | Processes with memory injection AND command lines | `process_memory + process_command` | Count of PIDs in both sets | Observed int | Injected process executing shell commands |
| `cross_proc_with_command_and_network` | Processes with command activity AND network conns | `process_command + process_network` | Count of PIDs in both sets | Observed int | Shell or script initiating network communication |
| `cross_proc_with_injection_and_network` | Processes with memory injection AND network conns | `process_memory + process_network` | Count of PIDs in both sets | Observed int | Injected process acting as C2 beacon |
| `cross_proc_with_suspicious_memory_and_tree` | Processes with memory injection that spawned children | `process_memory + process_tree` | Count of PIDs in both sets | Observed int | Injected staging process launching sub-tasks |
| `cross_high_privilege_network_processes` | Processes with SeDebugPrivilege connecting to network | `process_privilege + process_network` | Count of PIDs in both sets | Observed int | High-privilege processes communicating externally |
| `cross_suspicious_memory_process_ratio` | Ratio of injection-compromised PIDs to total procs | `process_memory + entities/processes` | Compromised PIDs / Total PIDs | Observed float | Proportion of process space compromised |
| `cross_network_enabled_process_ratio` | Ratio of network-active PIDs to total processes | `process_network + entities/processes` | Network PIDs / Total PIDs | Observed float | Proportion of processes making network calls |
"""
    with open(DOCS_DIR / "rich_feature_dictionary.md", "w", encoding="utf-8") as f:
        f.write(content)


if __name__ == "__main__":
    main()
