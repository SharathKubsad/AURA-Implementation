"""Build the Rich Forensic Representation Layer.

Source of Truth: C:\\Users\\Prash\\Desktop\\Real-Time-Fileless-Malware-Detection\\Dataset (IMMUTABLE)
Output Target:   data/forensic/

Extracts:
1. Samples (45 execution runs: 13 Benign, 32 Malware)
2. Entities (processes, threads, handles, modules, memory_regions, privileges, network_endpoints)
3. Events (sysmon, powershell, commands, network, memory/malfind)
4. Relationships (process_tree, process_thread, process_handle, process_module,
                 process_privilege, process_memory, process_command, process_network)
5. Observations & Provenance
"""

from __future__ import annotations

import csv
import json
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    import win32evtlog
except ImportError:
    win32evtlog = None

from data.forensic.schemas.models import (
    CommandEvent,
    HandleEntity,
    MalfindFinding,
    MemoryRegionEntity,
    ModuleEntity,
    NetworkConnection,
    PowerShellEvent,
    PrivilegeEntity,
    ProcessCommandRelationship,
    ProcessEntity,
    ProcessMemoryRelationship,
    ProcessNetworkRelationship,
    ProcessRelationship,
    ProvenanceRecord,
    SampleRecord,
    SysmonEvent,
    ThreadEntity,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DATASET_DIR = REPO_ROOT / "Dataset"
FORENSIC_DIR = REPO_ROOT / "data" / "forensic"

XML_NS = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}


def get_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_dirs() -> None:
    """Ensure all target directories in data/forensic/ exist."""
    subdirs = [
        "schemas",
        "samples",
        "entities/processes",
        "entities/threads",
        "entities/handles",
        "entities/modules",
        "entities/privileges",
        "entities/memory_regions",
        "entities/network_endpoints",
        "events/sysmon",
        "events/powershell",
        "events/commands",
        "events/network",
        "events/memory",
        "relationships/process_tree",
        "relationships/process_thread",
        "relationships/process_handle",
        "relationships/process_module",
        "relationships/process_privilege",
        "relationships/process_memory",
        "relationships/process_command",
        "relationships/process_network",
        "observations",
        "provenance",
        "manifests",
    ]
    for sd in subdirs:
        (FORENSIC_DIR / sd).mkdir(parents=True, exist_ok=True)


def parse_volatility_pslist(file_path: Path, sample_id: str) -> dict[int, dict[str, Any]]:
    """Parse pslist.txt and return a mapping of PID -> process info."""
    procs: dict[int, dict[str, Any]] = {}
    if not file_path.exists():
        return procs

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    header_found = False
    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue
        parts = line_clean.split("\t")
        if len(parts) >= 6 and parts[0] == "PID" and "ImageFileName" in parts[2]:
            header_found = True
            continue
        if not header_found or len(parts) < 3:
            continue

        try:
            pid = int(parts[0].strip())
            ppid = int(parts[1].strip())
            name = parts[2].strip()
            threads = int(parts[4].strip()) if len(parts) > 4 and parts[4].strip().isdigit() else None
            handles = int(parts[5].strip()) if len(parts) > 5 and parts[5].strip().isdigit() else None
            session = parts[6].strip() if len(parts) > 6 else None
            wow64 = parts[7].strip().lower() == "true" if len(parts) > 7 else False
            create_time = parts[8].strip() if len(parts) > 8 and parts[8].strip() != "N/A" else None
            exit_time = parts[9].strip() if len(parts) > 9 and parts[9].strip() != "N/A" else None

            procs[pid] = {
                "pid": pid,
                "ppid": ppid,
                "process_name": name,
                "threads_count": threads,
                "handles_count": handles,
                "session_id": session,
                "wow64": wow64,
                "create_time": create_time,
                "exit_time": exit_time,
                "is_in_pslist": True,
            }
        except Exception:
            continue

    return procs


def parse_volatility_psscan(file_path: Path) -> dict[int, dict[str, Any]]:
    """Parse psscan.txt for pool-scanned processes."""
    scanned: dict[int, dict[str, Any]] = {}
    if not file_path.exists():
        return scanned

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    header_found = False
    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue
        parts = line_clean.split("\t")
        if len(parts) >= 6 and parts[0] == "PID" and "ImageFileName" in parts[2]:
            header_found = True
            continue
        if not header_found or len(parts) < 3:
            continue

        try:
            pid = int(parts[0].strip())
            ppid = int(parts[1].strip())
            name = parts[2].strip()
            threads = int(parts[4].strip()) if len(parts) > 4 and parts[4].strip().isdigit() else None
            create_time = parts[8].strip() if len(parts) > 8 and parts[8].strip() != "N/A" else None
            exit_time = parts[9].strip() if len(parts) > 9 and parts[9].strip() != "N/A" else None

            scanned[pid] = {
                "pid": pid,
                "ppid": ppid,
                "process_name": name,
                "threads_count": threads,
                "create_time": create_time,
                "exit_time": exit_time,
                "is_in_psscan": True,
            }
        except Exception:
            continue

    return scanned


def parse_volatility_psxview(file_path: Path) -> dict[int, bool]:
    """Parse psxview.txt and return mapping of PID -> is_hidden boolean."""
    hidden_map: dict[int, bool] = {}
    if not file_path.exists():
        return hidden_map

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    header_found = False
    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue
        parts = line_clean.split("\t")
        if len(parts) >= 4 and "PID" in parts[2] and "pslist" in parts[3]:
            header_found = True
            continue
        if not header_found or len(parts) < 4:
            continue

        try:
            pid = int(parts[2].strip())
            pslist_vis = parts[3].strip().lower() == "true"
            psscan_vis = parts[4].strip().lower() == "true" if len(parts) > 4 else True
            # Hidden if in psscan but not in pslist
            is_hidden = psscan_vis and not pslist_vis
            hidden_map[pid] = is_hidden
        except Exception:
            continue

    return hidden_map


def parse_volatility_pstree(file_path: Path) -> tuple[dict[int, dict[str, Any]], list[dict[str, Any]]]:
    """Parse pstree.txt to extract command lines, executable paths, and parent-child tree edges."""
    proc_details: dict[int, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    if not file_path.exists():
        return proc_details, edges

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    header_found = False
    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue
        parts = line_clean.split("\t")
        if len(parts) >= 4 and ("PID" in parts[0] or "PID" in parts[1]):
            header_found = True
            continue
        if not header_found:
            continue

        try:
            # PID may have leading asterisks indicating tree depth
            raw_pid_field = parts[0].strip()
            depth = raw_pid_field.count("*")
            pid_str = raw_pid_field.lstrip("*").strip()
            if not pid_str.isdigit():
                continue
            pid = int(pid_str)
            ppid = int(parts[1].strip()) if parts[1].strip().isdigit() else 0
            img_name = parts[2].strip()

            cmd = parts[11].strip() if len(parts) > 11 and parts[11].strip() != "-" else None
            path = parts[12].strip() if len(parts) > 12 and parts[12].strip() != "-" else None

            proc_details[pid] = {
                "pid": pid,
                "ppid": ppid,
                "process_name": img_name,
                "command_line": cmd,
                "image_path": path,
                "tree_depth": depth,
            }

            if ppid > 0:
                edges.append({
                    "parent_pid": ppid,
                    "child_pid": pid,
                    "child_image": img_name,
                    "depth": depth,
                })
        except Exception:
            continue

    return proc_details, edges


def parse_volatility_threads(file_path: Path, sample_id: str) -> list[ThreadEntity]:
    """Parse threads.txt and return ThreadEntity records."""
    entities: list[ThreadEntity] = []
    if not file_path.exists():
        return entities

    provenance = ProvenanceRecord(
        sample_id=sample_id,
        source_file=file_path.name,
        source_type="VOLATILITY",
        source_plugin="windows.threads",
        extraction_timestamp=get_timestamp(),
    )

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    header_found = False
    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue
        parts = line_clean.split("\t")
        if len(parts) >= 3 and parts[1] == "PID" and parts[2] == "TID":
            header_found = True
            continue
        if not header_found or len(parts) < 3:
            continue

        try:
            pid = int(parts[1].strip())
            tid = int(parts[2].strip())
            start_addr = parts[3].strip() if len(parts) > 3 and parts[3].strip() != "-" else None
            start_path = parts[4].strip() if len(parts) > 4 and parts[4].strip() != "-" else None
            win32_addr = parts[5].strip() if len(parts) > 5 and parts[5].strip() != "-" else None
            win32_path = parts[6].strip() if len(parts) > 6 and parts[6].strip() != "-" else None
            create_time = parts[7].strip() if len(parts) > 7 and parts[7].strip() != "N/A" else None
            exit_time = parts[8].strip() if len(parts) > 8 and parts[8].strip() != "N/A" else None

            entities.append(
                ThreadEntity(
                    sample_id=sample_id,
                    pid=pid,
                    tid=tid,
                    start_address=start_addr,
                    start_path=start_path,
                    win32_start_address=win32_addr,
                    win32_start_path=win32_path,
                    create_time=create_time,
                    exit_time=exit_time,
                    provenance=provenance,
                )
            )
        except Exception:
            continue

    return entities


def parse_volatility_handles(file_path: Path, sample_id: str) -> list[HandleEntity]:
    """Parse handles.txt and return HandleEntity records."""
    entities: list[HandleEntity] = []
    if not file_path.exists():
        return entities

    provenance = ProvenanceRecord(
        sample_id=sample_id,
        source_file=file_path.name,
        source_type="VOLATILITY",
        source_plugin="windows.handles",
        extraction_timestamp=get_timestamp(),
    )

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    header_found = False
    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue
        parts = line_clean.split("\t")
        if len(parts) >= 5 and parts[0] == "PID" and parts[4] == "Type":
            header_found = True
            continue
        if not header_found or len(parts) < 6:
            continue

        try:
            pid = int(parts[0].strip())
            proc = parts[1].strip()
            offset = parts[2].strip() if len(parts) > 2 else None
            hval = parts[3].strip()
            obj_type = parts[4].strip()
            access = parts[5].strip()
            name = parts[6].strip() if len(parts) > 6 else ""

            entities.append(
                HandleEntity(
                    sample_id=sample_id,
                    pid=pid,
                    process=proc,
                    handle_value=hval,
                    object_type=obj_type,
                    granted_access=access,
                    object_name=name,
                    offset=offset,
                    provenance=provenance,
                )
            )
        except Exception:
            continue

    return entities


def parse_volatility_modules(dll_file: Path, ldr_file: Path, sample_id: str) -> list[ModuleEntity]:
    """Parse dlllist.txt and cross-reference with ldrmodules.txt."""
    ldr_info: dict[tuple[int, str], dict[str, Any]] = {}
    if ldr_file.exists():
        with open(ldr_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.strip().split("\t")
                if len(parts) >= 7 and parts[0].isdigit():
                    try:
                        pid = int(parts[0])
                        base = parts[2].lower()
                        in_load = parts[3].strip().lower() == "true"
                        in_init = parts[4].strip().lower() == "true"
                        in_mem = parts[5].strip().lower() == "true"
                        mapped = parts[6].strip()
                        ldr_info[(pid, base)] = {
                            "in_load": in_load,
                            "in_init": in_init,
                            "in_mem": in_mem,
                            "mapped_path": mapped,
                        }
                    except Exception:
                        continue

    entities: list[ModuleEntity] = []
    if not dll_file.exists():
        return entities

    provenance = ProvenanceRecord(
        sample_id=sample_id,
        source_file=dll_file.name,
        source_type="VOLATILITY",
        source_plugin="windows.dlllist+ldrmodules",
        extraction_timestamp=get_timestamp(),
    )

    with open(dll_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    header_found = False
    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue
        parts = line_clean.split("\t")
        if len(parts) >= 5 and parts[0] == "PID" and "Base" in parts[2]:
            header_found = True
            continue
        if not header_found or len(parts) < 5:
            continue

        try:
            pid = int(parts[0].strip())
            proc = parts[1].strip()
            base = parts[2].strip()
            size = parts[3].strip() if len(parts) > 3 else None
            name = parts[4].strip() if len(parts) > 4 else ""
            path = parts[5].strip() if len(parts) > 5 else None
            load_count = int(parts[6].strip()) if len(parts) > 6 and parts[6].strip().lstrip("-").isdigit() else None
            load_time = parts[7].strip() if len(parts) > 7 and parts[7].strip() != "N/A" else None

            extra = ldr_info.get((pid, base.lower()), {})

            entities.append(
                ModuleEntity(
                    sample_id=sample_id,
                    pid=pid,
                    process=proc,
                    base=base,
                    size=size,
                    name=name,
                    path=path,
                    load_count=load_count,
                    load_time=load_time,
                    in_load=extra.get("in_load"),
                    in_init=extra.get("in_init"),
                    in_mem=extra.get("in_mem"),
                    mapped_path=extra.get("mapped_path"),
                    provenance=provenance,
                )
            )
        except Exception:
            continue

    return entities


def parse_volatility_vads(file_path: Path, sample_id: str) -> list[MemoryRegionEntity]:
    """Parse vadinfo.txt and return MemoryRegionEntity records."""
    entities: list[MemoryRegionEntity] = []
    if not file_path.exists():
        return entities

    provenance = ProvenanceRecord(
        sample_id=sample_id,
        source_file=file_path.name,
        source_type="VOLATILITY",
        source_plugin="windows.vadinfo",
        extraction_timestamp=get_timestamp(),
    )

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    header_found = False
    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue
        parts = line_clean.split("\t")
        if len(parts) >= 6 and parts[0] == "PID" and "Protection" in parts[6]:
            header_found = True
            continue
        if not header_found or len(parts) < 7:
            continue

        try:
            pid = int(parts[0].strip())
            proc = parts[1].strip()
            offset = parts[2].strip()
            start_vpn = parts[3].strip()
            end_vpn = parts[4].strip()
            tag = parts[5].strip()
            protection = parts[6].strip()
            commit = int(parts[7].strip()) if len(parts) > 7 and parts[7].strip().isdigit() else 0
            priv = int(parts[8].strip()) if len(parts) > 8 and parts[8].strip().isdigit() else 0
            parent = parts[9].strip() if len(parts) > 9 and parts[9].strip() != "0x0" else None
            mapped_file = parts[10].strip() if len(parts) > 10 and parts[10].strip() != "N/A" else None

            # Calculate region size if hex VPNs can be converted
            reg_size = None
            try:
                start_int = int(start_vpn, 16)
                end_int = int(end_vpn, 16)
                reg_size = end_int - start_int + 1
            except Exception:
                pass

            entities.append(
                MemoryRegionEntity(
                    sample_id=sample_id,
                    pid=pid,
                    process=proc,
                    start_vpn=start_vpn,
                    end_vpn=end_vpn,
                    tag=tag,
                    protection=protection,
                    commit_charge=commit,
                    private_memory=priv,
                    parent=parent,
                    file_path=mapped_file,
                    offset=offset,
                    region_size_bytes=reg_size,
                    provenance=provenance,
                )
            )
        except Exception:
            continue

    return entities


def parse_volatility_malfind(file_path: Path, sample_id: str) -> list[MalfindFinding]:
    """Parse malfind.txt extracting findings, hexdumps, and disassembly blocks."""
    findings: list[MalfindFinding] = []
    if not file_path.exists():
        return findings

    provenance = ProvenanceRecord(
        sample_id=sample_id,
        source_file=file_path.name,
        source_type="VOLATILITY",
        source_plugin="windows.malfind",
        extraction_timestamp=get_timestamp(),
    )

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    current_finding: Optional[dict[str, Any]] = None
    hexdump_lines: list[str] = []
    disasm_lines: list[str] = []

    def commit_current():
        nonlocal current_finding, hexdump_lines, disasm_lines
        if current_finding:
            is_baseline_exc = "msmpeng.exe" in current_finding["process"].lower()
            findings.append(
                MalfindFinding(
                    sample_id=sample_id,
                    pid=current_finding["pid"],
                    process=current_finding["process"],
                    start_vpn=current_finding["start_vpn"],
                    end_vpn=current_finding["end_vpn"],
                    tag=current_finding["tag"],
                    protection=current_finding["protection"],
                    commit_charge=current_finding["commit_charge"],
                    private_memory=current_finding["private_memory"],
                    hexdump="\n".join(hexdump_lines),
                    disassembly="\n".join(disasm_lines),
                    is_known_baseline_exception=is_baseline_exc,
                    provenance=provenance,
                )
            )
            current_finding = None
            hexdump_lines = []
            disasm_lines = []

    for line in lines:
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("Volatility") or "CommitCharge" in line_clean:
            continue

        parts = line_clean.split("\t")
        # Check if line is a finding header: numeric PID followed by process name and start VPN
        if len(parts) >= 8 and parts[0].isdigit() and ("0x" in parts[2] or "0x" in parts[3]):
            commit_current()
            try:
                current_finding = {
                    "pid": int(parts[0]),
                    "process": parts[1].strip(),
                    "start_vpn": parts[2].strip(),
                    "end_vpn": parts[3].strip(),
                    "tag": parts[4].strip(),
                    "protection": parts[5].strip(),
                    "commit_charge": int(parts[6].strip()) if parts[6].strip().isdigit() else 0,
                    "private_memory": int(parts[7].strip()) if parts[7].strip().isdigit() else 0,
                }
            except Exception:
                current_finding = None
        elif current_finding:
            if ":" in line_clean and ("\t" in line_clean or " " in line_clean):
                disasm_lines.append(line_clean)
            elif len(line_clean) > 20 and any(c in "0123456789abcdef" for c in line_clean[:10].lower()):
                hexdump_lines.append(line_clean)

    commit_current()
    return findings


def parse_volatility_privileges(file_path: Path, sample_id: str) -> list[PrivilegeEntity]:
    """Parse privileges.txt for token privileges."""
    entities: list[PrivilegeEntity] = []
    if not file_path.exists():
        return entities

    provenance = ProvenanceRecord(
        sample_id=sample_id,
        source_file=file_path.name,
        source_type="VOLATILITY",
        source_plugin="windows.privileges",
        extraction_timestamp=get_timestamp(),
    )

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    header_found = False
    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue
        parts = line_clean.split("\t")
        if len(parts) >= 4 and parts[0] == "PID" and "Privilege" in parts[3]:
            header_found = True
            continue
        if not header_found or len(parts) < 4:
            continue

        try:
            pid = int(parts[0].strip())
            proc = parts[1].strip()
            val = int(parts[2].strip()) if parts[2].strip().isdigit() else 0
            priv_name = parts[3].strip()
            attrs = parts[4].strip() if len(parts) > 4 else ""
            desc = parts[5].strip() if len(parts) > 5 else ""

            is_present = "present" in attrs.lower()
            is_enabled = "enabled" in attrs.lower()
            is_default = "default" in attrs.lower()

            entities.append(
                PrivilegeEntity(
                    sample_id=sample_id,
                    pid=pid,
                    process=proc,
                    privilege_value=val,
                    privilege_name=priv_name,
                    attributes=attrs,
                    description=desc,
                    is_present=is_present,
                    is_enabled=is_enabled,
                    is_default=is_default,
                    provenance=provenance,
                )
            )
        except Exception:
            continue

    return entities


def parse_network_csv(file_path: Path, sample_id: str) -> list[NetworkConnection]:
    """Parse network_connections.csv."""
    conns: list[NetworkConnection] = []
    if not file_path.exists():
        return conns

    provenance = ProvenanceRecord(
        sample_id=sample_id,
        source_file=file_path.name,
        source_type="NETSTAT",
        source_plugin="network_connections.csv",
        extraction_timestamp=get_timestamp(),
    )

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                local_addr = row.get("LocalAddress", "") or "0.0.0.0"
                local_port = int(row.get("LocalPort", 0) or 0)
                remote_addr = row.get("RemoteAddress", "") or "0.0.0.0"
                remote_port = int(row.get("RemotePort", 0) or 0)
                state = row.get("State", "Unknown") or "Unknown"
                owning_pid = int(row.get("OwningProcess", 0) or 0)

                conns.append(
                    NetworkConnection(
                        sample_id=sample_id,
                        local_address=local_addr,
                        local_port=local_port,
                        remote_address=remote_addr,
                        remote_port=remote_port,
                        state=state,
                        protocol="tcp",
                        owning_pid=owning_pid,
                        source="network_connections.csv",
                        provenance=provenance,
                    )
                )
            except Exception:
                continue

    return conns


def parse_process_snapshot(file_path: Path) -> dict[int, dict[str, Any]]:
    """Parse process_snapshot.csv and return mapping of PID -> snapshot metrics."""
    snap: dict[int, dict[str, Any]] = {}
    if not file_path.exists():
        return snap

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                pid = int(row.get("Id", 0) or 0)
                name = row.get("ProcessName", "")
                path = row.get("Path", "")
                start_time = row.get("StartTime", "")
                cpu_str = row.get("CPU", "")
                cpu = float(cpu_str) if cpu_str else None
                ws_str = row.get("WorkingSet64", "")
                ws = int(ws_str) if ws_str and ws_str.isdigit() else None

                snap[pid] = {
                    "process_name": name,
                    "image_path": path,
                    "create_time": start_time,
                    "cpu_utilization": cpu,
                    "working_set_bytes": ws,
                }
            except Exception:
                continue

    return snap


def parse_sysmon_events(file_path: Path, sample_id: str) -> tuple[list[SysmonEvent], list[CommandEvent], list[NetworkConnection]]:
    """Parse Sysmon EVTX file extracting EID 1, 3, 5, etc."""
    sys_events: list[SysmonEvent] = []
    cmd_events: list[CommandEvent] = []
    net_conns: list[NetworkConnection] = []

    if not file_path.exists() or win32evtlog is None:
        return sys_events, cmd_events, net_conns

    provenance = ProvenanceRecord(
        sample_id=sample_id,
        source_file=file_path.name,
        source_type="SYSMON",
        source_plugin="sysmon.evtx",
        extraction_timestamp=get_timestamp(),
    )

    try:
        q = win32evtlog.EvtQuery(str(file_path.resolve()), win32evtlog.EvtQueryFilePath)
        batch = win32evtlog.EvtNext(q, 100)
        while batch:
            for ev in batch:
                try:
                    xml_str = win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)
                    root = ET.fromstring(xml_str)
                    eid_node = root.find("ns:System/ns:EventID", XML_NS)
                    eid = eid_node.text if eid_node is not None else "0"

                    time_node = root.find("ns:System/ns:TimeCreated", XML_NS)
                    utc_time = time_node.attrib.get("SystemTime") if time_node is not None else None

                    data_dict: dict[str, str] = {}
                    for d in root.findall(".//ns:Data", XML_NS):
                        k = d.attrib.get("Name")
                        if k and d.text:
                            data_dict[k] = d.text

                    pid = int(data_dict.get("ProcessId", 0)) if data_dict.get("ProcessId", "").isdigit() else None
                    ppid = int(data_dict.get("ParentProcessId", 0)) if data_dict.get("ParentProcessId", "").isdigit() else None
                    img = data_dict.get("Image")
                    parent_img = data_dict.get("ParentImage")
                    cmd = data_dict.get("CommandLine")
                    parent_cmd = data_dict.get("ParentCommandLine")
                    user = data_dict.get("User")
                    integrity = data_dict.get("IntegrityLevel")
                    hashes = data_dict.get("Hashes")
                    p_guid = data_dict.get("ProcessGuid")
                    parent_p_guid = data_dict.get("ParentProcessGuid")

                    sys_events.append(
                        SysmonEvent(
                            sample_id=sample_id,
                            event_id=eid,
                            timestamp=utc_time,
                            process_id=pid,
                            process_guid=p_guid,
                            parent_process_id=ppid,
                            parent_process_guid=parent_p_guid,
                            image=img,
                            parent_image=parent_img,
                            command_line=cmd,
                            parent_command_line=parent_cmd,
                            user=user,
                            integrity_level=integrity,
                            destination_ip=data_dict.get("DestinationIp"),
                            destination_port=int(data_dict.get("DestinationPort")) if data_dict.get("DestinationPort", "").isdigit() else None,
                            hashes=hashes,
                            details=data_dict,
                            provenance=provenance,
                        )
                    )

                    # Extract CommandEvent from EID 1
                    if eid == "1" and cmd and pid:
                        # Determine attribution
                        img_lower = (img or "").lower()
                        cmd_lower = cmd.lower()
                        if any(x in img_lower for x in ["sysmon64.exe", "audiodg.exe", "searchfilterhost.exe", "backgroundtaskhost.exe"]):
                            attr = "SYSTEM_ACTIVITY"
                        elif any(x in img_lower or x in cmd_lower for x in ["dumpit.exe", "collect_run", "scp.exe"]):
                            attr = "COLLECTION_HARNESS"
                        elif any(x in cmd_lower for x in ["-enc", "downloadstring", "invoke-", "bypass", "mimikatz", "beacon"]):
                            attr = "SAMPLE_ACTIVITY"
                        else:
                            attr = "UNKNOWN"

                        cmd_events.append(
                            CommandEvent(
                                sample_id=sample_id,
                                timestamp=utc_time,
                                event_id="1",
                                process_id=pid,
                                parent_process_id=ppid,
                                image=img or "",
                                parent_image=parent_img,
                                command_line=cmd,
                                user=user,
                                current_directory=data_dict.get("CurrentDirectory"),
                                source="sysmon_eid1",
                                attribution_status=attr,
                                provenance=provenance,
                            )
                        )

                    # Extract NetworkConnection from EID 3
                    if eid == "3" and pid:
                        dst_ip = data_dict.get("DestinationIp", "")
                        dst_port = int(data_dict.get("DestinationPort", 0)) if data_dict.get("DestinationPort", "").isdigit() else 0
                        src_ip = data_dict.get("SourceIp", "")
                        src_port = int(data_dict.get("SourcePort", 0)) if data_dict.get("SourcePort", "").isdigit() else 0
                        proto = data_dict.get("Protocol", "tcp")

                        net_conns.append(
                            NetworkConnection(
                                sample_id=sample_id,
                                timestamp=utc_time,
                                local_address=src_ip,
                                local_port=src_port,
                                remote_address=dst_ip,
                                remote_port=dst_port,
                                state="Established",
                                protocol=proto,
                                owning_pid=pid,
                                owning_process=img,
                                user=user,
                                source="sysmon_eid3",
                                provenance=provenance,
                            )
                        )

                except Exception:
                    continue
            batch = win32evtlog.EvtNext(q, 100)
    except Exception as e:
        print(f"Warning: error reading Sysmon EVTX {file_path}: {e}")

    return sys_events, cmd_events, net_conns


def parse_powershell_events(file_path: Path, sample_id: str) -> tuple[list[PowerShellEvent], list[CommandEvent]]:
    """Parse PowerShell EVTX file extracting EID 4104."""
    ps_events: list[PowerShellEvent] = []
    cmd_events: list[CommandEvent] = []

    if not file_path.exists() or win32evtlog is None:
        return ps_events, cmd_events

    provenance = ProvenanceRecord(
        sample_id=sample_id,
        source_file=file_path.name,
        source_type="POWERSHELL",
        source_plugin="powershell.evtx",
        extraction_timestamp=get_timestamp(),
    )

    try:
        q = win32evtlog.EvtQuery(str(file_path.resolve()), win32evtlog.EvtQueryFilePath)
        batch = win32evtlog.EvtNext(q, 100)
        while batch:
            for ev in batch:
                try:
                    xml_str = win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)
                    root = ET.fromstring(xml_str)
                    eid_node = root.find("ns:System/ns:EventID", XML_NS)
                    eid = eid_node.text if eid_node is not None else "0"

                    if eid != "4104":
                        continue

                    time_node = root.find("ns:System/ns:TimeCreated", XML_NS)
                    utc_time = time_node.attrib.get("SystemTime") if time_node is not None else None

                    data_dict: dict[str, str] = {}
                    for d in root.findall(".//ns:Data", XML_NS):
                        k = d.attrib.get("Name")
                        if k and d.text:
                            data_dict[k] = d.text

                    txt = data_dict.get("ScriptBlockText", "") or ""
                    sb_id = data_dict.get("ScriptBlockId")
                    path = data_dict.get("Path")
                    user = data_dict.get("UserId")
                    msg_num = int(data_dict.get("MessageNumber")) if data_dict.get("MessageNumber", "").isdigit() else None
                    msg_tot = int(data_dict.get("MessageTotal")) if data_dict.get("MessageTotal", "").isdigit() else None

                    # Attribution
                    txt_lower = txt.lower()
                    if any(x in txt_lower for x in ["get-netstat", "get-process", "fmd-collector", "dumpit"]):
                        attr = "COLLECTION_HARNESS"
                    elif any(x in txt_lower for x in ["frombase64string", "downloadstring", "invoke-expression", "iex", "system.reflection"]):
                        attr = "SAMPLE_ACTIVITY"
                    elif any(x in txt_lower for x in ["prompt", "tabexpansion", "microsoft.powershell"]):
                        attr = "SYSTEM_ACTIVITY"
                    else:
                        attr = "UNKNOWN"

                    ps_events.append(
                        PowerShellEvent(
                            sample_id=sample_id,
                            timestamp=utc_time,
                            event_id="4104",
                            script_block_id=sb_id,
                            script_block_text=txt,
                            path=path,
                            message_number=msg_num,
                            message_total=msg_tot,
                            user=user,
                            attribution_status=attr,
                            provenance=provenance,
                        )
                    )

                    # Also create a CommandEvent for ScriptBlocks
                    cmd_events.append(
                        CommandEvent(
                            sample_id=sample_id,
                            timestamp=utc_time,
                            event_id="4104",
                            process_id=0,  # ScriptBlock parent process not in 4104 payload
                            image="powershell.exe",
                            command_line=txt[:500],  # preview
                            script_block_text=txt,
                            user=user,
                            source="powershell_eid4104",
                            attribution_status=attr,
                            provenance=provenance,
                        )
                    )

                except Exception:
                    continue
            batch = win32evtlog.EvtNext(q, 100)
    except Exception as e:
        print(f"Warning: error reading PowerShell EVTX {file_path}: {e}")

    return ps_events, cmd_events


def write_jsonl(path: Path, items: list[BaseModel]) -> None:
    """Write list of Pydantic models to a JSONL file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for item in items:
            f.write(item.model_dump_json() + "\n")


def process_single_run(
    cat_dir: Path,
    run_id: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    """Extract and write rich forensic representation for a single run."""
    sample_id = f"EXEC_{run_id}"

    # Enforce canonical label rule for RUN-001
    if run_id == "RUN-001":
        label = 0
        family = "benign"
        track = "BENIGN"
    else:
        label = int(metadata.get("label", 0))
        family = str(metadata.get("family", "benign"))
        track = str(metadata.get("track", "BENIGN"))

    prov_meta = ProvenanceRecord(
        sample_id=sample_id,
        source_file=f"metadata/{run_id}.json",
        source_type="METADATA",
        source_plugin="sample_metadata",
        extraction_timestamp=get_timestamp(),
    )

    vol_dir = cat_dir / "volatility" / run_id
    src_dir = cat_dir / "source_evidence" / run_id

    # 1. Parse Volatility
    pslist_map = parse_volatility_pslist(vol_dir / "pslist.txt", sample_id)
    psscan_map = parse_volatility_psscan(vol_dir / "psscan.txt")
    psxview_map = parse_volatility_psxview(vol_dir / "psxview.txt")
    pstree_details, pstree_edges = parse_volatility_pstree(vol_dir / "pstree.txt")
    threads_list = parse_volatility_threads(vol_dir / "threads.txt", sample_id)
    handles_list = parse_volatility_handles(vol_dir / "handles.txt", sample_id)
    modules_list = parse_volatility_modules(vol_dir / "dlllist.txt", vol_dir / "ldrmodules.txt", sample_id)
    vads_list = parse_volatility_vads(vol_dir / "vadinfo.txt", sample_id)
    malfind_list = parse_volatility_malfind(vol_dir / "malfind.txt", sample_id)
    privs_list = parse_volatility_privileges(vol_dir / "privileges.txt", sample_id)

    # 2. Parse Source Evidence
    net_conns = parse_network_csv(src_dir / "network_connections.csv", sample_id)
    snap_map = parse_process_snapshot(src_dir / "process_snapshot.csv")
    sys_events, sys_cmds, sys_nets = parse_sysmon_events(src_dir / "sysmon.evtx", sample_id)
    ps_events, ps_cmds = parse_powershell_events(src_dir / "powershell.evtx", sample_id)

    all_net_conns = net_conns + sys_nets
    all_cmd_events = sys_cmds + ps_cmds

    # 3. Fuse Process Entities across pslist, psscan, pstree, and snapshot
    all_pids = set(pslist_map.keys()) | set(psscan_map.keys()) | set(pstree_details.keys()) | set(snap_map.keys())
    process_entities: list[ProcessEntity] = []

    prov_proc = ProvenanceRecord(
        sample_id=sample_id,
        source_file="volatility+source_evidence",
        source_type="VOLATILITY+SNAPSHOT",
        source_plugin="fused_process_record",
        extraction_timestamp=get_timestamp(),
    )

    for pid in sorted(all_pids):
        pl = pslist_map.get(pid, {})
        ps = psscan_map.get(pid, {})
        pt = pstree_details.get(pid, {})
        sn = snap_map.get(pid, {})

        name = pl.get("process_name") or pt.get("process_name") or ps.get("process_name") or sn.get("process_name") or "unknown"
        ppid = pl.get("ppid") if pl.get("ppid") is not None else (pt.get("ppid") if pt.get("ppid") is not None else ps.get("ppid", 0))

        cmd = pt.get("command_line")
        path = pt.get("image_path") or sn.get("image_path")
        threads = pl.get("threads_count") or ps.get("threads_count")
        handles = pl.get("handles_count")
        session = pl.get("session_id")
        wow64 = pl.get("wow64", False)
        create_time = pl.get("create_time") or ps.get("create_time") or sn.get("create_time")
        exit_time = pl.get("exit_time") or ps.get("exit_time")
        cpu = sn.get("cpu_utilization")
        ws = sn.get("working_set_bytes")
        is_hidden = psxview_map.get(pid, False)

        process_entities.append(
            ProcessEntity(
                sample_id=sample_id,
                pid=pid,
                ppid=ppid or 0,
                process_name=name,
                image_path=path,
                command_line=cmd,
                threads_count=threads,
                handles_count=handles,
                session_id=session,
                wow64=wow64,
                create_time=create_time,
                exit_time=exit_time,
                cpu_utilization=cpu,
                working_set_bytes=ws,
                is_hidden_psxview=is_hidden,
                is_in_pslist=pid in pslist_map,
                is_in_psscan=pid in psscan_map,
                provenance=prov_proc,
            )
        )

    # 4. Construct Relationships
    known_proc_names = {p.pid: p.process_name for p in process_entities}

    # Process -> Process Tree
    tree_rels: list[ProcessRelationship] = []
    for edge in pstree_edges:
        tree_rels.append(
            ProcessRelationship(
                sample_id=sample_id,
                relationship_type="PARENT_CHILD",
                parent_pid=edge["parent_pid"],
                child_pid=edge["child_pid"],
                parent_image=known_proc_names.get(edge["parent_pid"]),
                child_image=edge.get("child_image") or known_proc_names.get(edge["child_pid"]),
                provenance=prov_proc,
            )
        )

    # Process -> Network
    net_rels: list[ProcessNetworkRelationship] = []
    for nc in all_net_conns:
        if nc.owning_pid and nc.owning_pid in known_proc_names:
            net_rels.append(
                ProcessNetworkRelationship(
                    sample_id=sample_id,
                    pid=nc.owning_pid,
                    process_name=known_proc_names[nc.owning_pid],
                    local_port=nc.local_port,
                    remote_address=nc.remote_address,
                    remote_port=nc.remote_port,
                    protocol=nc.protocol,
                    state=nc.state,
                    provenance=nc.provenance,
                )
            )

    # Process -> Command
    cmd_rels: list[ProcessCommandRelationship] = []
    for ce in all_cmd_events:
        if ce.process_id and ce.process_id in known_proc_names:
            cmd_rels.append(
                ProcessCommandRelationship(
                    sample_id=sample_id,
                    pid=ce.process_id,
                    process_name=known_proc_names[ce.process_id],
                    command_line=ce.command_line,
                    event_source=ce.source,
                    timestamp=ce.timestamp,
                    provenance=ce.provenance,
                )
            )

    # Process -> Memory (Malfind)
    mem_rels: list[ProcessMemoryRelationship] = []
    for mf in malfind_list:
        mem_rels.append(
            ProcessMemoryRelationship(
                sample_id=sample_id,
                pid=mf.pid,
                process_name=mf.process,
                region_start=mf.start_vpn,
                region_end=mf.end_vpn,
                protection=mf.protection,
                is_injected=not mf.is_known_baseline_exception,
                commit_charge=mf.commit_charge,
                provenance=mf.provenance,
            )
        )

    # 5. Write to data/forensic/
    sample_rec = SampleRecord(
        sample_id=sample_id,
        run_id=run_id,
        label=label,
        family=family,
        track=track,
        os=metadata.get("os", "microsoft_windows_11_home"),
        execution_timestamp=metadata.get("execution_timestamp"),
        source_category=cat_dir.name,
        metadata_source=str(cat_dir / "metadata" / f"{run_id}.json"),
        evidence_availability={
            "volatility": vol_dir.exists(),
            "sysmon": (src_dir / "sysmon.evtx").exists(),
            "powershell": (src_dir / "powershell.evtx").exists(),
            "network_connections": (src_dir / "network_connections.csv").exists(),
            "process_snapshot": (src_dir / "process_snapshot.csv").exists(),
        },
        provenance=prov_meta,
    )

    write_jsonl(FORENSIC_DIR / "entities" / "processes" / f"{run_id}.jsonl", process_entities)
    write_jsonl(FORENSIC_DIR / "entities" / "threads" / f"{run_id}.jsonl", threads_list)
    write_jsonl(FORENSIC_DIR / "entities" / "handles" / f"{run_id}.jsonl", handles_list)
    write_jsonl(FORENSIC_DIR / "entities" / "modules" / f"{run_id}.jsonl", modules_list)
    write_jsonl(FORENSIC_DIR / "entities" / "privileges" / f"{run_id}.jsonl", privs_list)
    write_jsonl(FORENSIC_DIR / "entities" / "memory_regions" / f"{run_id}.jsonl", vads_list)
    write_jsonl(FORENSIC_DIR / "events" / "memory" / f"{run_id}.jsonl", malfind_list)
    write_jsonl(FORENSIC_DIR / "events" / "network" / f"{run_id}.jsonl", all_net_conns)
    write_jsonl(FORENSIC_DIR / "events" / "commands" / f"{run_id}.jsonl", all_cmd_events)
    write_jsonl(FORENSIC_DIR / "events" / "powershell" / f"{run_id}.jsonl", ps_events)
    write_jsonl(FORENSIC_DIR / "events" / "sysmon" / f"{run_id}.jsonl", sys_events)
    write_jsonl(FORENSIC_DIR / "relationships" / "process_tree" / f"{run_id}.jsonl", tree_rels)
    write_jsonl(FORENSIC_DIR / "relationships" / "process_network" / f"{run_id}.jsonl", net_rels)
    write_jsonl(FORENSIC_DIR / "relationships" / "process_command" / f"{run_id}.jsonl", cmd_rels)
    write_jsonl(FORENSIC_DIR / "relationships" / "process_memory" / f"{run_id}.jsonl", mem_rels)

    # Write individual sample JSON
    with open(FORENSIC_DIR / "samples" / f"{run_id}.json", "w", encoding="utf-8") as f:
        f.write(sample_rec.model_dump_json(indent=2))

    # Observations & summary
    obs = {
        "run_id": run_id,
        "sample_id": sample_id,
        "label": label,
        "family": family,
        "counts": {
            "processes": len(process_entities),
            "threads": len(threads_list),
            "handles": len(handles_list),
            "modules": len(modules_list),
            "privileges": len(privs_list),
            "vads": len(vads_list),
            "malfind_findings": len(malfind_list),
            "network_connections": len(all_net_conns),
            "sysmon_events": len(sys_events),
            "powershell_events": len(ps_events),
            "command_events": len(all_cmd_events),
            "relationships_tree": len(tree_rels),
            "relationships_network": len(net_rels),
            "relationships_command": len(cmd_rels),
            "relationships_memory": len(mem_rels),
        },
        "malfind_baseline_exceptions": sum(1 for m in malfind_list if m.is_known_baseline_exception),
        "hidden_processes_psxview": sum(1 for p in process_entities if p.is_hidden_psxview),
    }
    with open(FORENSIC_DIR / "observations" / f"{run_id}.json", "w", encoding="utf-8") as f:
        json.dump(obs, f, indent=2)

    return {
        "sample_record": sample_rec,
        "observations": obs,
    }


def main() -> None:
    print("=" * 60)
    print("PHASE 2: BUILDING RICH FORENSIC REPRESENTATION")
    print(f"Source: {DATASET_DIR}")
    print(f"Target: {FORENSIC_DIR}")
    print("=" * 60)

    ensure_dirs()

    categories = sorted([d for d in DATASET_DIR.iterdir() if d.is_dir()])
    print(f"Found {len(categories)} batch directories.")

    all_samples: list[SampleRecord] = []
    total_counts: dict[str, int] = {
        "processes": 0,
        "threads": 0,
        "handles": 0,
        "modules": 0,
        "privileges": 0,
        "vads": 0,
        "malfind": 0,
        "network": 0,
        "sysmon": 0,
        "powershell": 0,
        "commands": 0,
        "tree_relationships": 0,
    }

    benign_count = 0
    malware_count = 0

    for cat_dir in categories:
        meta_dir = cat_dir / "metadata"
        if not meta_dir.exists():
            continue

        meta_files = sorted(meta_dir.glob("*.json"))
        for mf in meta_files:
            run_id = mf.stem
            with open(mf, "r", encoding="utf-8-sig") as f:
                metadata = json.load(f)

            res = process_single_run(cat_dir, run_id, metadata)
            srec = res["sample_record"]
            all_samples.append(srec)

            if srec.label == 0:
                benign_count += 1
            else:
                malware_count += 1

            c = res["observations"]["counts"]
            total_counts["processes"] += c["processes"]
            total_counts["threads"] += c["threads"]
            total_counts["handles"] += c["handles"]
            total_counts["modules"] += c["modules"]
            total_counts["privileges"] += c["privileges"]
            total_counts["vads"] += c["vads"]
            total_counts["malfind"] += c["malfind_findings"]
            total_counts["network"] += c["network_connections"]
            total_counts["sysmon"] += c["sysmon_events"]
            total_counts["powershell"] += c["powershell_events"]
            total_counts["commands"] += c["command_events"]
            total_counts["tree_relationships"] += c["relationships_tree"]

            print(f"[{srec.run_id}] {cat_dir.name} | Label: {srec.label} ({srec.family}) | Procs: {c['processes']} | Handles: {c['handles']} | VADs: {c['vads']}")

    # Write aggregated samples.jsonl
    write_jsonl(FORENSIC_DIR / "samples" / "samples.jsonl", all_samples)

    # Write dataset manifest
    manifest = {
        "dataset_name": "Real-Time Fileless Malware Detection - Rich Forensic Representation",
        "generated_timestamp": get_timestamp(),
        "total_runs": len(all_samples),
        "label_distribution": {
            "benign": benign_count,
            "malware": malware_count,
        },
        "canonical_check": {
            "expected_benign": 13,
            "expected_malware": 32,
            "is_canonical": (benign_count == 13 and malware_count == 32),
        },
        "entity_totals": total_counts,
    }

    with open(FORENSIC_DIR / "manifests" / "dataset_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print("\n" + "=" * 60)
    print("PHASE 2 EXTRACTION COMPLETE")
    print(f"Total Runs: {len(all_samples)}")
    print(f"Benign:     {benign_count} (Expected: 13)")
    print(f"Malware:    {malware_count} (Expected: 32)")
    print(f"Total Processes Reconstructed: {total_counts['processes']:,}")
    print(f"Total Threads Reconstructed:   {total_counts['threads']:,}")
    print(f"Total Handles Preserved:       {total_counts['handles']:,}")
    print(f"Total Modules (DLLs):          {total_counts['modules']:,}")
    print(f"Total Privileges:              {total_counts['privileges']:,}")
    print(f"Total VAD Memory Regions:      {total_counts['vads']:,}")
    print(f"Total Malfind Findings:        {total_counts['malfind']:,}")
    print(f"Total Sysmon Events:           {total_counts['sysmon']:,}")
    print(f"Total PowerShell Events:       {total_counts['powershell']:,}")
    print(f"Total Network Connections:     {total_counts['network']:,}")
    print("=" * 60)


if __name__ == "__main__":
    main()
