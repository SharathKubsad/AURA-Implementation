"""Pydantic schemas for the rich forensic representation layer.

Preserves entity-level, event-level, and relationship structures extracted from:
- Volatility 3 plugins
- Windows Sysmon EVTX
- PowerShell operational EVTX
- Network connection tables
- Process snapshot telemetry
"""

from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field


class ProvenanceRecord(BaseModel):
    """Provenance tracking for any forensic entity, event, or relationship."""
    sample_id: str
    source_file: str
    source_type: str = Field(description="VOLATILITY, SYSMON, POWERSHELL, NETSTAT, SNAPSHOT, METADATA")
    source_plugin: str = Field(description="e.g. windows.pslist, EID_1, EID_4104, network_connections.csv")
    extraction_timestamp: str
    extractor_version: str = "2.0.0-rich-forensic"


class SampleRecord(BaseModel):
    """Authoritative sample-level metadata and canonical execution parameters."""
    sample_id: str
    run_id: str
    label: int = Field(description="0 for benign, 1 for malware")
    family: str = Field(description="benign or specific malware family name")
    track: str = Field(description="BENIGN, TRACK_A, TRACK_B")
    os: str = "microsoft_windows_11_home"
    execution_timestamp: Optional[str] = None
    source_category: str
    metadata_source: str
    evidence_availability: dict[str, bool] = Field(default_factory=dict)
    provenance: ProvenanceRecord


class ProcessEntity(BaseModel):
    """Individual process entity reconstructed from Volatility, snapshot, and Sysmon."""
    sample_id: str
    pid: int
    ppid: int
    process_name: str
    image_path: Optional[str] = None
    command_line: Optional[str] = None
    threads_count: Optional[int] = None
    handles_count: Optional[int] = None
    session_id: Optional[str] = None
    wow64: bool = False
    create_time: Optional[str] = None
    exit_time: Optional[str] = None
    cpu_utilization: Optional[float] = None
    working_set_bytes: Optional[int] = None
    user: Optional[str] = None
    integrity_level: Optional[str] = None
    process_guid: Optional[str] = None
    parent_process_guid: Optional[str] = None
    is_hidden_psxview: bool = False
    is_in_pslist: bool = True
    is_in_psscan: bool = True
    provenance: ProvenanceRecord


class ThreadEntity(BaseModel):
    """Thread entity with kernel and Win32 start addresses."""
    sample_id: str
    pid: int
    tid: int
    start_address: Optional[str] = None
    start_path: Optional[str] = None
    win32_start_address: Optional[str] = None
    win32_start_path: Optional[str] = None
    create_time: Optional[str] = None
    exit_time: Optional[str] = None
    provenance: ProvenanceRecord


class HandleEntity(BaseModel):
    """Object handle entity extracted from Volatility handles plugin."""
    sample_id: str
    pid: int
    process: str
    handle_value: str
    object_type: str = Field(description="Process, Thread, Mutant, Key, File, Section, etc.")
    granted_access: str
    object_name: str
    offset: Optional[str] = None
    provenance: ProvenanceRecord


class ModuleEntity(BaseModel):
    """Loaded DLL or executable module record with loader table verification."""
    sample_id: str
    pid: int
    process: str
    base: str
    size: Optional[str] = None
    name: str
    path: Optional[str] = None
    load_count: Optional[int] = None
    load_time: Optional[str] = None
    in_load: Optional[bool] = None
    in_init: Optional[bool] = None
    in_mem: Optional[bool] = None
    mapped_path: Optional[str] = None
    provenance: ProvenanceRecord


class MemoryRegionEntity(BaseModel):
    """Virtual Address Descriptor (VAD) memory region record."""
    sample_id: str
    pid: int
    process: str
    start_vpn: str
    end_vpn: str
    tag: str
    protection: str
    initial_protection: Optional[str] = None
    commit_charge: int = 0
    private_memory: int = 0
    parent: Optional[str] = None
    file_path: Optional[str] = None
    offset: Optional[str] = None
    region_size_bytes: Optional[int] = None
    provenance: ProvenanceRecord


class MalfindFinding(BaseModel):
    """Suspicious injected or RWX memory region finding with disassembly."""
    sample_id: str
    pid: int
    process: str
    start_vpn: str
    end_vpn: str
    tag: str
    protection: str
    commit_charge: int
    private_memory: int
    hexdump: str = ""
    disassembly: str = ""
    is_known_baseline_exception: bool = Field(
        default=False, 
        description="True for legitimate Defender/OS RWX allocations such as MsMpEng.exe"
    )
    provenance: ProvenanceRecord


class PrivilegeEntity(BaseModel):
    """Process token privilege entity."""
    sample_id: str
    pid: int
    process: str
    privilege_value: int
    privilege_name: str
    attributes: str
    description: str
    is_present: bool = True
    is_enabled: bool = False
    is_default: bool = False
    provenance: ProvenanceRecord


class CommandEvent(BaseModel):
    """Command event from pstree, Sysmon EID 1, or process snapshot."""
    sample_id: str
    timestamp: Optional[str] = None
    event_id: Optional[str] = None
    process_id: int
    parent_process_id: Optional[int] = None
    image: str
    parent_image: Optional[str] = None
    command_line: str
    script_block_text: Optional[str] = None
    user: Optional[str] = None
    current_directory: Optional[str] = None
    source: str = Field(description="pstree, sysmon_eid1, powershell_eid4104, snapshot")
    attribution_status: str = Field(
        default="UNKNOWN", 
        description="SYSTEM_ACTIVITY, COLLECTION_HARNESS, USER_ACTIVITY, SAMPLE_ACTIVITY, UNKNOWN"
    )
    provenance: ProvenanceRecord


class PowerShellEvent(BaseModel):
    """PowerShell ScriptBlock logging event (EID 4104)."""
    sample_id: str
    timestamp: Optional[str] = None
    event_id: str = "4104"
    script_block_id: Optional[str] = None
    script_block_text: str
    path: Optional[str] = None
    message_number: Optional[int] = None
    message_total: Optional[int] = None
    user: Optional[str] = None
    attribution_status: str = Field(
        default="UNKNOWN",
        description="SYSTEM_ACTIVITY, COLLECTION_HARNESS, USER_ACTIVITY, SAMPLE_ACTIVITY, UNKNOWN"
    )
    provenance: ProvenanceRecord


class NetworkConnection(BaseModel):
    """Network connection record from netstat or Sysmon EID 3."""
    sample_id: str
    timestamp: Optional[str] = None
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str = "Unknown"
    protocol: str = "tcp"
    owning_pid: int
    owning_process: Optional[str] = None
    user: Optional[str] = None
    source: str = Field(description="network_connections.csv, sysmon_eid3")
    provenance: ProvenanceRecord


class SysmonEvent(BaseModel):
    """Parsed Sysmon event retaining structured fields."""
    sample_id: str
    event_id: str
    timestamp: Optional[str] = None
    process_id: Optional[int] = None
    process_guid: Optional[str] = None
    parent_process_id: Optional[int] = None
    parent_process_guid: Optional[str] = None
    image: Optional[str] = None
    parent_image: Optional[str] = None
    command_line: Optional[str] = None
    parent_command_line: Optional[str] = None
    user: Optional[str] = None
    integrity_level: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    hashes: Optional[str] = None
    details: dict[str, Any] = Field(default_factory=dict)
    provenance: ProvenanceRecord


class ProcessRelationship(BaseModel):
    """Process parent-child relationship record."""
    sample_id: str
    relationship_type: str = "PARENT_CHILD"
    parent_pid: int
    child_pid: int
    parent_image: Optional[str] = None
    child_image: Optional[str] = None
    timestamp: Optional[str] = None
    provenance: ProvenanceRecord


class ProcessNetworkRelationship(BaseModel):
    """Process to network socket relationship."""
    sample_id: str
    pid: int
    process_name: str
    local_port: int
    remote_address: str
    remote_port: int
    protocol: str
    state: str
    provenance: ProvenanceRecord


class ProcessCommandRelationship(BaseModel):
    """Process to command execution relationship."""
    sample_id: str
    pid: int
    process_name: str
    command_line: str
    event_source: str
    timestamp: Optional[str] = None
    provenance: ProvenanceRecord


class ProcessMemoryRelationship(BaseModel):
    """Process to memory region or malfind injection relationship."""
    sample_id: str
    pid: int
    process_name: str
    region_start: str
    region_end: str
    protection: str
    is_injected: bool
    commit_charge: int
    provenance: ProvenanceRecord
