"""Process feature extraction engine for Volatility 3 outputs (Track A)."""

from __future__ import annotations

import argparse
import contextlib
import logging
from pathlib import Path
from typing import Any

from forensics.extraction.parser_utils import (
    find_plugin_file,
    parse_ldrmodules_output,
    parse_malfind_output,
    parse_volatility_file,
)
from forensics.schemas.process import ProcessFeatures

logger = logging.getLogger(__name__)

# ==============================================================================
# High-Risk Windows Privileges Allowlist
# ==============================================================================
# Explicit allowlist of privileges considered high-risk for fileless malware:
# - SeDebugPrivilege: Memory injection, process scraping, LSASS dumping (Mimikatz).
# - SeTcbPrivilege: Operating system trusted computer base impersonation.
# - SeLoadDriverPrivilege: Kernel driver loading (BYOVD, rootkits).
# - SeTakeOwnershipPrivilege: Arbitrary object ownership acquisition (DACL bypass).
# - SeAssignPrimaryTokenPrivilege: Primary token replacement on child processes.
# - SeBackupPrivilege: Bypasses read security descriptors (SAM/SYSTEM hive access).
# - SeRestorePrivilege: Bypasses write security descriptors (system binary overwrite).
#
# Deliberately EXCLUDED privileges:
# - SeImpersonatePrivilege: Enabled by default across standard Windows services
#   (NT AUTHORITY\SYSTEM, LocalService, NetworkService). Counting it would falsely
#   flag benign service hosts.
# - SeChangeNotifyPrivilege: Standard user notification privilege.
# - SeCreateGlobalPrivilege: Standard global object privilege.
HIGH_RISK_PRIVILEGES: set[str] = {
    "sedebugprivilege",
    "setcbprivilege",
    "seloaddriverprivilege",
    "setakeownershipprivilege",
    "seassignprimarytokenprivilege",
    "sebackupprivilege",
    "serestoreprivilege",
}

# Suspicious path fragments for loaded modules (staging / user-writable locations)
SUSPICIOUS_PATH_PATTERNS = [
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "\\users\\public\\",
    "\\temp\\",
    "/tmp/",
    "/dev/shm/",
]

# Legitimate system directories where standard Windows DLLs reside
LEGITIMATE_PATH_PATTERNS = [
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
    "\\program files\\",
    "\\program files (x86)\\",
]

# Known script interpreters / interactive shells that should never parent core system daemons
INTERACTIVE_SHELL_NAMES = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
}


def is_terminated_process(record: dict[str, Any]) -> bool:
    """Check if a psscan/psxview record represents a terminated process based on ExitTime."""
    exit_val = str(
        record.get("exittime")
        or record.get("exit time")
        or record.get("exit_time")
        or record.get("time exited")
        or ""
    ).strip()
    # If exit time is present and not N/A / dash, the process is terminated
    return bool(exit_val and exit_val.lower() not in ("n/a", "-", "none", ""))


def extract_process_features(input_dir: Path, sample_id: str) -> ProcessFeatures:
    """Extract ProcessFeatures from Volatility 3 plugin outputs in the specified directory.

    Derives features based on true Volatility 3 output semantics:
    - total_process_count: distinct active PIDs in windows.pslist
    - hidden_process_count: active processes in psscan/psxview missing from pslist without exit time
    - anomalous_ppid_count: violations of legitimate Windows process architecture
    - avg/max_threads_per_process: thread metrics from threads or pslist
    - total_handle_count: handle counts from handles or pslist
    - suspicious_dll_count: DLLs loaded from user-writable/temporary locations
    - malfind_process_count: distinct PIDs with genuine malfind findings
    - elevated_privilege_count: distinct processes with high-risk privileges actively Enabled
    - unlinked_dll_count: modules in ldrmodules unlinked from load order or memory order

    Args:
        input_dir: Directory containing Volatility 3 plugin outputs.
        sample_id: Canonical sample identifier (e.g. 'EXEC_RUN-001').

    Returns:
        ProcessFeatures: Validated Pydantic model.
    """
    # 1. Parse pslist (primary active running processes)
    pslist_file = find_plugin_file(input_dir, "pslist")
    pslist_records = parse_volatility_file(pslist_file) if pslist_file else []

    pslist_pids: set[int] = set()
    process_name_map: dict[int, str] = {}
    ppid_map: dict[int, int] = {}
    threads_from_pslist: dict[int, int] = {}
    handles_from_pslist: dict[int, int] = {}

    for row in pslist_records:
        pid_raw = row.get("pid")
        if pid_raw is not None:
            try:
                pid = int(pid_raw)
                pslist_pids.add(pid)
                name = str(row.get("imagefilename") or row.get("process") or row.get("name") or "")
                process_name_map[pid] = name.lower().strip()

                ppid_raw = row.get("ppid")
                if ppid_raw is not None:
                    ppid_map[pid] = int(ppid_raw)

                # Threads & Handles columns if present in pslist
                threads_raw = row.get("threads")
                if threads_raw is not None:
                    with contextlib.suppress(ValueError, TypeError):
                        threads_from_pslist[pid] = int(threads_raw)

                handles_raw = row.get("handles")
                if handles_raw is not None:
                    with contextlib.suppress(ValueError, TypeError):
                        handles_from_pslist[pid] = int(handles_raw)
            except (ValueError, TypeError):
                continue

    total_process_count = len(pslist_pids)

    # 2. Parse psscan & psxview for genuine hidden/unlinked active processes
    psscan_file = find_plugin_file(input_dir, "psscan")
    psscan_records = parse_volatility_file(psscan_file) if psscan_file else []
    hidden_active_pids: set[int] = set()

    for row in psscan_records:
        pid_raw = row.get("pid")
        if pid_raw is not None:
            try:
                pid = int(pid_raw)
                # If PID is not in pslist AND has not terminated, it is a hidden unlinked process
                if pid not in pslist_pids and not is_terminated_process(row):
                    hidden_active_pids.add(pid)
            except (ValueError, TypeError):
                pass

    psxview_file = find_plugin_file(input_dir, "psxview")
    psxview_records = parse_volatility_file(psxview_file) if psxview_file else []
    for row in psxview_records:
        pid_raw = row.get("pid")
        if pid_raw is not None:
            try:
                pid = int(pid_raw)
                pslist_val = str(row.get("pslist", "")).lower()
                # Hidden if flagged False in pslist and not terminated
                if pslist_val in ("false", "0", "no") and not is_terminated_process(row):
                    hidden_active_pids.add(pid)
            except (ValueError, TypeError):
                pass

    hidden_process_count = len(hidden_active_pids)

    # 3. Parse pstree & analyze parent-child anomalies against Windows architecture rules
    pstree_file = find_plugin_file(input_dir, "pstree")
    pstree_records = parse_volatility_file(pstree_file) if pstree_file else []
    for row in pstree_records:
        pid_raw = row.get("pid")
        ppid_raw = row.get("ppid")
        if pid_raw is not None and ppid_raw is not None:
            try:
                pid = int(pid_raw)
                ppid = int(ppid_raw)
                ppid_map[pid] = ppid
                if pid not in process_name_map:
                    process_name_map[pid] = str(
                        row.get("imagefilename") or row.get("process") or ""
                    ).lower()
            except (ValueError, TypeError):
                pass

    services_pids = [p for p, name in process_name_map.items() if "services.exe" in name]
    wininit_pids = [p for p, name in process_name_map.items() if "wininit.exe" in name]
    lsass_pids = [p for p, name in process_name_map.items() if "lsass.exe" in name]

    anomalous_ppid_count = 0

    for pid, ppid in ppid_map.items():
        if pid in (0, 4):  # Idle and System
            continue

        pname = process_name_map.get(pid, "")

        # System (PID 4) must have PPID 0; no other active process should claim PPID 0
        if ppid == 0 and pid != 4:
            anomalous_ppid_count += 1
            continue

        parent_name = process_name_map.get(ppid, "")

        # Rule: svchost.exe legitimate parent is services.exe (services.exe never exits)
        if "svchost.exe" in pname:
            if services_pids and ppid not in services_pids:
                anomalous_ppid_count += 1
                continue
            if parent_name and "services.exe" not in parent_name:
                anomalous_ppid_count += 1
                continue

        # Rule: lsass.exe legitimate parent is wininit.exe (wininit.exe never exits)
        if "lsass.exe" in pname:
            if wininit_pids and ppid not in wininit_pids:
                anomalous_ppid_count += 1
                continue
            if parent_name and "wininit.exe" not in parent_name:
                anomalous_ppid_count += 1
                continue

        # Rule: services.exe legitimate parent is wininit.exe
        if "services.exe" in pname:
            if wininit_pids and ppid not in wininit_pids:
                anomalous_ppid_count += 1
                continue
            if parent_name and "wininit.exe" not in parent_name:
                anomalous_ppid_count += 1
                continue

        # Rule: smss.exe legitimate parent is System (PID 4)
        if "smss.exe" in pname and ppid != 4:
            anomalous_ppid_count += 1
            continue

        # Rule: Core system processes must never be spawned by interactive shells / script engines
        if (
            any(
                sys_proc in pname
                for sys_proc in (
                    "smss.exe",
                    "csrss.exe",
                    "wininit.exe",
                    "services.exe",
                    "lsass.exe",
                    "svchost.exe",
                )
            )
            and parent_name in INTERACTIVE_SHELL_NAMES
        ):
            anomalous_ppid_count += 1
            continue

    # Additional check: multiple instances of singleton system daemons
    if len(services_pids) > 1:
        anomalous_ppid_count += len(services_pids) - 1
    if len(wininit_pids) > 1:
        anomalous_ppid_count += len(wininit_pids) - 1
    if len(lsass_pids) > 1:
        anomalous_ppid_count += len(lsass_pids) - 1

    # 4. Parse threads
    threads_file = find_plugin_file(input_dir, "threads")
    threads_records = parse_volatility_file(threads_file) if threads_file else []
    thread_counts_per_pid: dict[int, int] = {}
    if threads_records:
        for row in threads_records:
            pid_raw = row.get("pid")
            if pid_raw is not None:
                try:
                    pid = int(pid_raw)
                    thread_counts_per_pid[pid] = thread_counts_per_pid.get(pid, 0) + 1
                except (ValueError, TypeError):
                    pass
    elif threads_from_pslist:
        thread_counts_per_pid = threads_from_pslist

    if thread_counts_per_pid:
        counts = list(thread_counts_per_pid.values())
        avg_threads_per_process = round(sum(counts) / max(len(counts), 1), 2)
        max_threads_in_single_process = max(counts)
    else:
        avg_threads_per_process = 0.0
        max_threads_in_single_process = 0

    # 5. Parse handles
    handles_file = find_plugin_file(input_dir, "handles")
    handles_records = parse_volatility_file(handles_file) if handles_file else []
    if handles_records:
        total_handle_count = len(handles_records)
    elif handles_from_pslist:
        total_handle_count = sum(handles_from_pslist.values())
    else:
        total_handle_count = 0

    # 6. Parse dlllist for genuinely suspicious module paths
    dlllist_file = find_plugin_file(input_dir, "dlllist")
    dlllist_records = parse_volatility_file(dlllist_file) if dlllist_file else []
    suspicious_dll_count = 0
    for row in dlllist_records:
        # Path must be a genuine string from the path/filepath column (never memory address/base)
        path = str(row.get("path") or row.get("filepath") or "").strip().lower()
        if not path or path in ("n/a", "-", "none"):
            continue
        # Check if path is in suspicious user-writable/staging locations
        is_suspicious_location = any(frag in path for frag in SUSPICIOUS_PATH_PATTERNS)
        is_legitimate_location = any(frag in path for frag in LEGITIMATE_PATH_PATTERNS)
        if is_suspicious_location and not is_legitimate_location:
            suspicious_dll_count += 1

    # 7. Parse malfind (distinct processes with actual malfind findings)
    malfind_file = find_plugin_file(input_dir, "malfind")
    malfind_records = parse_malfind_output(malfind_file) if malfind_file else []
    malfind_pids = {r["pid"] for r in malfind_records if isinstance(r.get("pid"), int)}
    malfind_process_count = len(malfind_pids)

    # 8. Parse privileges for elevated/high-risk tokens actively Enabled
    privileges_file = find_plugin_file(input_dir, "privileges")
    privileges_records = parse_volatility_file(privileges_file) if privileges_file else []
    elevated_pids: set[int] = set()
    for row in privileges_records:
        pid_raw = row.get("pid")
        if pid_raw is None:
            continue
        try:
            pid = int(pid_raw)
        except (ValueError, TypeError):
            continue

        priv_name = str(row.get("privilege") or row.get("name") or "").lower().strip()
        if priv_name not in HIGH_RISK_PRIVILEGES:
            continue

        attrs = str(row.get("attributes") or "").lower().strip()
        # In Windows token semantics, a privilege is only elevated if explicitly Enabled
        # Disabled or Disabled by default is the normal un-elevated state
        is_actively_enabled = "enabled" in attrs and "disabled" not in attrs
        if is_actively_enabled:
            # Set ensures duplicate privilege rows for the same PID count as ONE process
            elevated_pids.add(pid)

    elevated_privilege_count = len(elevated_pids)

    # 9. Parse ldrmodules for actual unlinked DLL indicators
    ldrmodules_file = find_plugin_file(input_dir, "ldrmodules")
    ldrmodules_records = parse_ldrmodules_output(ldrmodules_file) if ldrmodules_file else []
    unlinked_dll_count = sum(
        1 for r in ldrmodules_records if (not r.get("inload", True)) or (not r.get("inmem", True))
    )

    return ProcessFeatures(
        sample_id=sample_id,
        total_process_count=total_process_count,
        hidden_process_count=hidden_process_count,
        anomalous_ppid_count=anomalous_ppid_count,
        avg_threads_per_process=avg_threads_per_process,
        max_threads_in_single_process=max_threads_in_single_process,
        total_handle_count=total_handle_count,
        suspicious_dll_count=suspicious_dll_count,
        malfind_process_count=malfind_process_count,
        elevated_privilege_count=elevated_privilege_count,
        unlinked_dll_count=unlinked_dll_count,
    )


def main() -> None:
    """CLI entrypoint for process feature extraction."""
    parser = argparse.ArgumentParser(
        description="Extract Process features from Volatility 3 output"
    )
    parser.add_argument(
        "--input-dir", "-i", type=Path, required=True, help="Input directory of Volatility outputs"
    )
    parser.add_argument(
        "--sample-id", "-s", type=str, required=True, help="Canonical sample identifier"
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=Path("data/interim/process"),
        help="Output directory",
    )
    args = parser.parse_args()

    features = extract_process_features(args.input_dir, args.sample_id)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    out_file = args.output_dir / f"{args.sample_id}.json"
    out_file.write_text(features.model_dump_json(indent=2), encoding="utf-8")
    print(f"Process features extracted successfully to: {out_file}")


if __name__ == "__main__":
    main()
