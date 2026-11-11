"""Cross-Dataset Feature Compatibility Audit Generator.

Audits feature semantics, units, extraction methods, and distribution shifts across:
1. Custom 45-sample VM dataset
2. CIC-MalMem-2022
3. Candidate CAPE/Any.Run sandbox telemetry (conceptual/schema level)
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from preprocessing.pipeline import (
    COMMAND_FEATURE_COLS,
    MEMORY_FEATURE_COLS,
    NETWORK_FEATURE_COLS,
    PROCESS_FEATURE_COLS,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_PUBLIC_DIR = REPO_ROOT / "data" / "processed" / "public"
DOCS_DIR = REPO_ROOT / "docs"

# ---------------------------------------------------------------------------
# Feature Audit Records
# ---------------------------------------------------------------------------

PROCESS_AUDIT: dict[str, dict[str, Any]] = {
    "total_process_count": {
        "feature_name": "total_process_count",
        "modality": "PROCESS",
        "our_definition": "Count of unique active processes present in pslist at volatile memory acquisition / snapshot freeze.",
        "public_dataset_definition": "Count of processes in pslist (MalMem: pslist.nproc; CAPE: len(behavior.processes)).",
        "source_field": "pslist.nproc (MalMem) / behavior.processes (CAPE)",
        "extraction_method": "Volatility 3 windows.pslist (Custom) vs Volatility 2 pslist (MalMem) vs API Hooking (CAPE)",
        "units": "Integer count of active processes",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows 10 x64 VirtualBox (MalMem) vs Windows 7/10 x64 (CAPE)",
        "volatility_plugin_version": "Volatility 3 v2.x (Custom) vs Volatility 2.6 (MalMem) vs N/A (CAPE)",
        "comparable": "YES",
        "classification": "DIRECTLY_COMPARABLE",
        "transformation_required": "None for MalMem (pslist.nproc). For CAPE, count distinct spawned process objects.",
        "distribution_shift_risk": "Moderate. Clean Windows baseline process count varies: Win 11/10 22H2 clean baseline has 70-110 processes; MalMem baseline is ~40-50 processes. Normalization/scaling without shift correction may bias tree split thresholds.",
        "explanation": "Both capture the count of enumerated OS processes. Semantic intent is identical, but differences in baseline Windows service footprint cause an additive shift in the distribution.",
    },
    "hidden_process_count": {
        "feature_name": "hidden_process_count",
        "modality": "PROCESS",
        "our_definition": "Processes found in psscan/psxview that are missing from pslist active process list AND have NOT terminated (ExitTime is None).",
        "public_dataset_definition": "Processes where psxview flags pslist or csrss handles as False (MalMem: psxview.not_in_pslist, psxview.not_in_csrss_handles).",
        "source_field": "psxview.not_in_pslist, psxview.not_in_csrss_handles (MalMem)",
        "extraction_method": "Volatility 3 psscan/psxview with termination filtering (Custom) vs Volatility 2 psxview raw boolean false counts (MalMem)",
        "units": "Integer count of hidden/unlinked processes",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows 10 x64 (MalMem)",
        "volatility_plugin_version": "Volatility 3 (Custom) vs Volatility 2.6 (MalMem)",
        "comparable": "PARTIAL",
        "classification": "COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION",
        "transformation_required": "max(psxview.not_in_pslist, psxview.not_in_csrss_handles)",
        "distribution_shift_risk": "High. Volatility 2 psxview frequently flags normal terminated processes as 'not_in_pslist' before their kernel pool memory is freed, creating artificial false-positive hidden processes in MalMem that our custom pipeline explicitly filters out.",
        "explanation": "Our pipeline performs explicit zombie/terminated filtering (ExitTime check) to eliminate dead process artifacts. MalMem raw psxview includes dead processes, inflating hidden process counts.",
    },
    "anomalous_ppid_count": {
        "feature_name": "anomalous_ppid_count",
        "modality": "PROCESS",
        "our_definition": "Count of processes violating core Windows architecture parent-child rules (e.g., svchost not spawned by services.exe, duplicate singletons, interactive shell parenting system daemons).",
        "public_dataset_definition": "NOT AVAILABLE in MalMem. In CAPE, derivable by parsing behavior.processes parent_id hierarchy.",
        "source_field": "None (MalMem) / behavior.processes.parent_id (CAPE)",
        "extraction_method": "Volatility 3 pstree graph traversal against architecture rules (Custom) vs None (MalMem) vs API monitoring (CAPE)",
        "units": "Integer count of lineage violations",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows 10 x64 (MalMem) vs Win 7/10 (CAPE)",
        "volatility_plugin_version": "Volatility 3 (Custom) vs Unsupported (MalMem)",
        "comparable": "NO",
        "classification": "NOT_COMPARABLE",
        "transformation_required": "Cannot be derived from MalMem. Must be preserved as null (missing). For CAPE, apply our lineage rule engine to process tree.",
        "distribution_shift_risk": "Severe. 100% missing in MalMem. Attempting to pool MalMem into training forces either dropping this crucial fileless detector feature or imputing zeros, crippling model sensitivity to process hollowing/spoofing.",
        "explanation": "MalMem authors did not extract structural parent-child tree relationship semantics. This is a foundational fileless feature present in our custom pipeline but completely absent in MalMem.",
    },
    "avg_threads_per_process": {
        "feature_name": "avg_threads_per_process",
        "modality": "PROCESS",
        "our_definition": "Mean thread count across all enumerated processes (sum(threads) / total_processes).",
        "public_dataset_definition": "Mean thread count across pslist (MalMem: pslist.avg_threads).",
        "source_field": "pslist.avg_threads (MalMem) / behavior.processes[].threads (CAPE)",
        "extraction_method": "Volatility 3 windows.threads / pslist (Custom) vs Volatility 2 pslist (MalMem)",
        "units": "Float (average threads per process)",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows 10 x64 (MalMem)",
        "volatility_plugin_version": "Volatility 3 (Custom) vs Volatility 2.6 (MalMem)",
        "comparable": "YES",
        "classification": "DIRECTLY_COMPARABLE",
        "transformation_required": "Direct mapping from pslist.avg_threads.",
        "distribution_shift_risk": "Low. Threads per process has consistent statistical range (typically 8.0 to 35.0) across Windows builds.",
        "explanation": "Direct mathematical match. Both represent average concurrency per process.",
    },
    "max_threads_in_single_process": {
        "feature_name": "max_threads_in_single_process",
        "modality": "PROCESS",
        "our_definition": "Maximum thread count observed in any single individual process (flags high-concurrency cryptominers, thread pools, or port scanners).",
        "public_dataset_definition": "NOT AVAILABLE in MalMem (only mean was recorded). In CAPE, derivable as max(len(p['threads'])).",
        "source_field": "None (MalMem) / behavior.processes[].threads (CAPE)",
        "extraction_method": "Volatility 3 windows.threads per-PID aggregation (Custom) vs None (MalMem)",
        "units": "Integer thread count",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows 10 x64 (MalMem)",
        "volatility_plugin_version": "Volatility 3 (Custom) vs Unsupported (MalMem)",
        "comparable": "NO",
        "classification": "NOT_COMPARABLE",
        "transformation_required": "Preserve as None for MalMem. For CAPE, take max thread array length.",
        "distribution_shift_risk": "High. 100% missing in MalMem. Models trained on MalMem cannot learn thresholds on peak single-process thread concurrency.",
        "explanation": "MalMem aggregated all thread data into a single dataset-wide column (avg_threads), losing the distribution tail (maximum).",
    },
    "total_handle_count": {
        "feature_name": "total_handle_count",
        "modality": "PROCESS",
        "our_definition": "Total count of active Windows kernel object handles open across all processes (files, keys, mutants, ports, sections, threads).",
        "public_dataset_definition": "Total handles open across all processes (MalMem: handles.nhandles).",
        "source_field": "handles.nhandles (MalMem)",
        "extraction_method": "Volatility 3 windows.handles (Custom) vs Volatility 2 handles (MalMem)",
        "units": "Integer count of open kernel handles",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows 10 x64 (MalMem)",
        "volatility_plugin_version": "Volatility 3 (Custom) vs Volatility 2.6 (MalMem)",
        "comparable": "YES",
        "classification": "DIRECTLY_COMPARABLE",
        "transformation_required": "Direct mapping from handles.nhandles.",
        "distribution_shift_risk": "Moderate. Handle counts scale with baseline process count and VM uptime. Clean Windows 11 systems have ~25,000-45,000 handles; MalMem records ~8,000-15,000 handles.",
        "explanation": "Semantically identical metric, but baseline magnitude differs between lightweight test VM and fully provisioned target endpoint.",
    },
    "suspicious_dll_count": {
        "feature_name": "suspicious_dll_count",
        "modality": "PROCESS",
        "our_definition": "Count of loaded DLLs located in user-writable, staging, or temporary file system locations (e.g. \\AppData\\Local\\Temp\\, \\Users\\Public\\).",
        "public_dataset_definition": "NOT AVAILABLE in MalMem. MalMem recorded total DLL count (dlllist.ndlls) but performed no path classification.",
        "source_field": "None (MalMem) / behavior.processes[].modules (CAPE)",
        "extraction_method": "Volatility 3 windows.dlllist with path allowlist/blocklist filtering (Custom) vs None (MalMem)",
        "units": "Integer count of suspicious DLL paths",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows 10 x64 (MalMem)",
        "volatility_plugin_version": "Volatility 3 (Custom) vs Unsupported (MalMem)",
        "comparable": "NO",
        "classification": "NOT_COMPARABLE",
        "transformation_required": "Preserve as None for MalMem. For CAPE, apply path pattern matching to loaded module paths.",
        "distribution_shift_risk": "Severe. 100% missing in MalMem. Staging-directory DLL loads are a primary indicator of DLL sideloading and reflective injection.",
        "explanation": "Total DLL count is not a proxy for suspicious DLL locations; mapping dlllist.ndlls would corrupt the semantic feature space.",
    },
    "malfind_process_count": {
        "feature_name": "malfind_process_count",
        "modality": "PROCESS",
        "our_definition": "Count of unique processes containing suspicious executable memory allocations flagged by malfind.",
        "public_dataset_definition": "Total number of injected memory regions flagged by malfind across all processes (MalMem: malfind.ninjections).",
        "source_field": "malfind.ninjections (MalMem)",
        "extraction_method": "Volatility 3 windows.malfind distinct PID count (Custom) vs Volatility 2 malfind total injection count (MalMem)",
        "units": "Unique process count (Custom) vs Total injection regions count (MalMem)",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows 10 x64 (MalMem)",
        "volatility_plugin_version": "Volatility 3 (Custom) vs Volatility 2.6 (MalMem)",
        "comparable": "PARTIAL",
        "classification": "COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION",
        "transformation_required": "Use malfind.ninjections as an upper-bound proxy for malfind_process_count. Document that 1 process with 4 injections yields value 4 in MalMem but 1 in Custom.",
        "distribution_shift_risk": "Moderate. Value in MalMem is >= true unique process count. For multi-stage injections, MalMem values will be systematically higher.",
        "explanation": "Units differ: count of unique PIDs vs count of injected memory regions. They are monotonically correlated but numerically divergent.",
    },
    "elevated_privilege_count": {
        "feature_name": "elevated_privilege_count",
        "modality": "PROCESS",
        "our_definition": "Count of processes holding high-risk administrative tokens (SeDebugPrivilege, SeLoadDriverPrivilege, SeTcbPrivilege) actively in Enabled state.",
        "public_dataset_definition": "NOT AVAILABLE in MalMem. In CAPE, derivable from token privilege API calls (AdjustTokenPrivileges).",
        "source_field": "None (MalMem) / behavior.processes[].calls (CAPE)",
        "extraction_method": "Volatility 3 windows.privileges filtering for actively Enabled high-risk tokens (Custom) vs None (MalMem)",
        "units": "Integer count of elevated processes",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows 10 x64 (MalMem)",
        "volatility_plugin_version": "Volatility 3 (Custom) vs Unsupported (MalMem)",
        "comparable": "NO",
        "classification": "NOT_COMPARABLE",
        "transformation_required": "Preserve as None for MalMem. For CAPE, parse AdjustTokenPrivileges API calls.",
        "distribution_shift_risk": "Severe. 100% missing in MalMem. Token privilege abuse (SeDebugPrivilege for LSASS dumping) cannot be learned from MalMem.",
        "explanation": "Volatility privileges plugin was not run by the MalMem authors. Feature must remain missing.",
    },
    "unlinked_dll_count": {
        "feature_name": "unlinked_dll_count",
        "modality": "PROCESS",
        "our_definition": "Count of modules in ldrmodules where InLoadOrder or InMemoryOrder list integrity check fails.",
        "public_dataset_definition": "Count of modules not in load list (MalMem: ldrmodules.not_in_load).",
        "source_field": "ldrmodules.not_in_load (MalMem)",
        "extraction_method": "Volatility 3 windows.ldrmodules (Custom) vs Volatility 2 ldrmodules (MalMem)",
        "units": "Integer count of unlinked modules",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows 10 x64 (MalMem)",
        "volatility_plugin_version": "Volatility 3 (Custom) vs Volatility 2.6 (MalMem)",
        "comparable": "YES",
        "classification": "DIRECTLY_COMPARABLE",
        "transformation_required": "Direct mapping from ldrmodules.not_in_load.",
        "distribution_shift_risk": "Low to Moderate. Minor difference between Volatility 2 and 3 handling of .NET assembly load lists.",
        "explanation": "Both capture reflective DLL loading unlinking from the InLoadOrderModuleList.",
    },
}

MEMORY_AUDIT: dict[str, dict[str, Any]] = {
    "rwx_page_count": {
        "feature_name": "rwx_page_count",
        "modality": "MEMORY",
        "our_definition": "Count of committed memory Virtual Address Descriptor (VAD) regions configured with PAGE_EXECUTE_READWRITE permissions across the entire memory dump.",
        "public_dataset_definition": "Count of memory regions flagged with PAGE_EXECUTE_READWRITE in suspicious allocations (MalMem: malfind.protection).",
        "source_field": "malfind.protection (MalMem)",
        "extraction_method": "Volatility 3 windows.vadinfo full VAD tree parse (Custom) vs Volatility 2 malfind protection filter (MalMem)",
        "units": "Count of RWX memory allocations",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows 10 x64 (MalMem)",
        "volatility_plugin_version": "Volatility 3 (Custom) vs Volatility 2.6 (MalMem)",
        "comparable": "PARTIAL",
        "classification": "COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION",
        "transformation_required": "Direct mapping from malfind.protection. Document that vadinfo (Custom) scans all processes/regions, whereas malfind.protection (MalMem) inspects only candidate injected regions.",
        "distribution_shift_risk": "Moderate. MalMem value is a lower bound of total system RWX allocations because malfind filters candidate regions prior to evaluating protection.",
        "explanation": "Strong semantic overlap, but our pipeline scans the complete VAD tree (vadinfo) while MalMem records RWX allocations discovered by malfind.",
    },
    "injected_code_regions": {
        "feature_name": "injected_code_regions",
        "modality": "MEMORY",
        "our_definition": "Total count of suspicious injected code regions detected across memory by malfind.",
        "public_dataset_definition": "Total injected regions identified by malfind (MalMem: malfind.ninjections).",
        "source_field": "malfind.ninjections (MalMem)",
        "extraction_method": "Volatility 3 windows.malfind (Custom) vs Volatility 2 malfind (MalMem)",
        "units": "Integer count of injected code regions",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows 10 x64 (MalMem)",
        "volatility_plugin_version": "Volatility 3 (Custom) vs Volatility 2.6 (MalMem)",
        "comparable": "YES",
        "classification": "DIRECTLY_COMPARABLE",
        "transformation_required": "Direct mapping from malfind.ninjections.",
        "distribution_shift_risk": "Low. Plugin logic for identifying private executable allocations containing non-zero code bytes is functionally identical in Volatility 2 and 3.",
        "explanation": "Exact semantic and algorithmic correspondence between custom and public extraction.",
    },
    "unmapped_executable_pages": {
        "feature_name": "unmapped_executable_pages",
        "modality": "MEMORY",
        "our_definition": "Executable memory regions (PAGE_EXECUTE*) that have no backing file on the disk image (Vad tag != VadImageMap, private memory).",
        "public_dataset_definition": "Unique injected executable memory addresses (MalMem: malfind.uniqueInjections).",
        "source_field": "malfind.uniqueInjections (MalMem)",
        "extraction_method": "Volatility 3 windows.vadinfo unmapped page parse (Custom) vs Volatility 2 malfind.uniqueInjections (MalMem)",
        "units": "Count of unmapped executable memory regions",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows 10 x64 (MalMem)",
        "volatility_plugin_version": "Volatility 3 (Custom) vs Volatility 2.6 (MalMem)",
        "comparable": "PARTIAL",
        "classification": "COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION",
        "transformation_required": "Map from malfind.uniqueInjections as integer count.",
        "distribution_shift_risk": "Moderate. Custom counts all unmapped executable VADs (including JIT heaps, trampolines); MalMem counts unique malfind injection points.",
        "explanation": "Both capture executable code running in anonymous/private memory without an on-disk image file, but scope of discovery differs slightly.",
    },
    "vad_protection_anomaly_count": {
        "feature_name": "vad_protection_anomaly_count",
        "modality": "MEMORY",
        "our_definition": "Count of VAD allocations where current protection differs from initial allocation protection (InitProtection != Protection, e.g. VirtualProtect PAGE_READWRITE -> PAGE_EXECUTE_READWRITE).",
        "public_dataset_definition": "Commit charge in injected regions (MalMem: malfind.commitCharge proxy).",
        "source_field": "malfind.commitCharge, malfind.ninjections (MalMem)",
        "extraction_method": "Volatility 3 vadinfo initial vs current protection comparison (Custom) vs MalMem commitCharge heuristic proxy",
        "units": "Count of altered protection regions (Custom) vs Binary presence of commit charge in injections (MalMem)",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows 10 x64 (MalMem)",
        "volatility_plugin_version": "Volatility 3 (Custom) vs Volatility 2.6 (MalMem)",
        "comparable": "NO",
        "classification": "MALMEM_SPECIFIC_PROXY",
        "transformation_required": "Preserved only as dataset-specific proxy for reproducing public MalMem baseline. Strictly excluded from zero-shot cross-domain evaluation.",
        "distribution_shift_risk": "Severe. Incompatible semantic definitions. Custom feature detects true VirtualProtect state modification; MalMem proxies commit charge on injected pages. Must not be treated as a shared cross-domain feature.",
        "explanation": "Severe semantic divergence. Custom domain measures InitProtection != Protection (allocation mutation); MalMem measures whether malfind regions have non-zero commit charge. Explicitly classified as MALMEM_SPECIFIC_PROXY and strictly removed from the zero-shot shared feature vector.",
    },
    "ldrmodules_inconsistencies": {
        "feature_name": "ldrmodules_inconsistencies",
        "modality": "MEMORY",
        "our_definition": "Sum of discrepancies across PEB module lists (InLoadOrder, InMemoryOrder, InInitializationOrder) flagging reflective DLL injection.",
        "public_dataset_definition": "Sum of not_in_load, not_in_init, and not_in_mem discrepancies (MalMem: ldrmodules.not_in_load + not_in_init + not_in_mem).",
        "source_field": "ldrmodules.not_in_load, not_in_init, not_in_mem (MalMem)",
        "extraction_method": "Volatility 3 windows.ldrmodules (Custom) vs Volatility 2 ldrmodules (MalMem)",
        "units": "Integer count of module list inconsistencies",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows 10 x64 (MalMem)",
        "volatility_plugin_version": "Volatility 3 (Custom) vs Volatility 2.6 (MalMem)",
        "comparable": "YES",
        "classification": "DIRECTLY_COMPARABLE",
        "transformation_required": "Sum: ldrmodules.not_in_load + ldrmodules.not_in_init + ldrmodules.not_in_mem.",
        "distribution_shift_risk": "Low. Both measure reflective DLL injection bypassing standard loader tables.",
        "explanation": "Exact semantic parity. Captures hidden DLLs unhooked from PEB linked lists.",
    },
    "yara_shellcode_matches": {
        "feature_name": "yara_shellcode_matches",
        "modality": "MEMORY",
        "our_definition": "Count of YARA rule hits on memory VAD allocations using fileless shellcode signature sets (yarascan/vadyarascan).",
        "public_dataset_definition": "NOT AVAILABLE in MalMem. No YARA scans were executed.",
        "source_field": "None (MalMem)",
        "extraction_method": "Volatility 3 windows.vadyarascan (Custom) vs None (MalMem)",
        "units": "Integer rule match count",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows 10 x64 (MalMem)",
        "volatility_plugin_version": "Volatility 3 (Custom) vs Unsupported (MalMem)",
        "comparable": "NO",
        "classification": "NOT_COMPARABLE",
        "transformation_required": "Preserve as None for MalMem.",
        "distribution_shift_risk": "Severe. 100% missing in MalMem.",
        "explanation": "MalMem features do not contain any YARA signature matching telemetry.",
    },
    "mean_memory_entropy": {
        "feature_name": "mean_memory_entropy",
        "modality": "MEMORY",
        "our_definition": "Average Shannon entropy computed over dumped raw bytes of injected memory regions (scale: 0.0 - 8.0).",
        "public_dataset_definition": "NOT AVAILABLE in MalMem. Raw memory dumps were not preserved in the CSV; entropy was not calculated.",
        "source_field": "None (MalMem)",
        "extraction_method": "Shannon entropy on raw dumped memory bytes (Custom) vs None (MalMem)",
        "units": "Float (bits per byte, 0.0 to 8.0)",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows 10 x64 (MalMem)",
        "volatility_plugin_version": "Custom byte entropy calculator (Custom) vs Unsupported (MalMem)",
        "comparable": "NO",
        "classification": "NOT_COMPARABLE",
        "transformation_required": "Preserve as None for MalMem.",
        "distribution_shift_risk": "Severe. 100% missing in MalMem. High entropy (>7.2) is the primary signal for encrypted/packed fileless payloads.",
        "explanation": "MalMem CSV contains only high-level Volatility counts, not raw payload bytes. Entropy cannot be computed.",
    },
    "max_memory_entropy": {
        "feature_name": "max_memory_entropy",
        "modality": "MEMORY",
        "our_definition": "Maximum Shannon entropy observed across any single injected memory page.",
        "public_dataset_definition": "NOT AVAILABLE in MalMem.",
        "source_field": "None (MalMem)",
        "extraction_method": "Shannon entropy on raw dumped memory bytes (Custom) vs None (MalMem)",
        "units": "Float (bits per byte, 0.0 to 8.0)",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows 10 x64 (MalMem)",
        "volatility_plugin_version": "Custom byte entropy calculator (Custom) vs Unsupported (MalMem)",
        "comparable": "NO",
        "classification": "NOT_COMPARABLE",
        "transformation_required": "Preserve as None for MalMem.",
        "distribution_shift_risk": "Severe. 100% missing in MalMem.",
        "explanation": "Entropy cannot be derived from MalMem metadata.",
    },
}

COMMAND_AUDIT: dict[str, dict[str, Any]] = {
    "raw_command_text": {
        "feature_name": "raw_command_text",
        "modality": "COMMAND",
        "our_definition": "The authentic string of the command line or PowerShell script block executed during the workload.",
        "public_dataset_definition": "NOT AVAILABLE in MalMem (0% present). In CAPE/Any.Run, available in behavior.processes[].command_line or info.command_line.",
        "source_field": "None (MalMem) / behavior.processes[].command_line (CAPE)",
        "extraction_method": "Sysmon Event ID 1 / PowerShell ScriptBlock Event ID 4104 (Custom) vs API Hooking (CAPE)",
        "units": "Raw UTF-8 string",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows 7/10 x64 (CAPE)",
        "volatility_plugin_version": "N/A",
        "comparable": "YES (CAPE) / NO (MalMem)",
        "classification": "DIRECTLY_COMPARABLE",
        "transformation_required": "None for CAPE. Extract primary executed command line. For MalMem, entire command modality is unavailable.",
        "distribution_shift_risk": "Moderate. Sandbox command lines often include automation harness artifacts (e.g. sample path C:\\tmp\\xyz.exe) requiring harness stripping.",
        "explanation": "CAPE authentic execution strings map directly into DistilBERT tokenizer.",
    },
    "command_length": {
        "feature_name": "command_length",
        "modality": "COMMAND",
        "our_definition": "Character length of the primary sanitized command string (len(raw_command_text)).",
        "public_dataset_definition": "Derived from command line string length.",
        "source_field": "len(raw_command_text)",
        "extraction_method": "Deterministic string length calculation",
        "units": "Integer character count",
        "os_environment": "Language/OS agnostic",
        "volatility_plugin_version": "N/A",
        "comparable": "YES",
        "classification": "DIRECTLY_COMPARABLE",
        "transformation_required": "len(raw_command_text)",
        "distribution_shift_risk": "Low. Obfuscated PowerShell cradles exhibit character lengths 10x-50x larger than benign command lines across both environments.",
        "explanation": "Exact mathematical derivation from raw command string.",
    },
    "shannon_entropy": {
        "feature_name": "shannon_entropy",
        "modality": "COMMAND",
        "our_definition": "Shannon entropy of characters within the command line string (scale: 0.0 - 8.0).",
        "public_dataset_definition": "Derived from character frequency distribution of command string.",
        "source_field": "calculate_shannon_entropy(raw_command_text)",
        "extraction_method": "Deterministic character entropy calculation",
        "units": "Float (bits per character, 0.0 to 8.0)",
        "os_environment": "Language/OS agnostic",
        "volatility_plugin_version": "N/A",
        "comparable": "YES",
        "classification": "DIRECTLY_COMPARABLE",
        "transformation_required": "calculate_shannon_entropy(raw_command_text)",
        "distribution_shift_risk": "Low. Base64 and XOR encoded commands consistently exhibit entropy > 4.5 across all sources.",
        "explanation": "Deterministic calculation directly comparable.",
    },
    "is_base64_encoded": {
        "feature_name": "is_base64_encoded",
        "modality": "COMMAND",
        "our_definition": "Boolean indicator (0 or 1) indicating PowerShell base64 execution flags (-e, -enc, -encodedcommand) or high-density base64 regex patterns.",
        "public_dataset_definition": "Derived by regex search across command line string.",
        "source_field": "Regex matching on command string",
        "extraction_method": "BASE64_COMMAND_FLAGS regex matching",
        "units": "Binary indicator (0 or 1)",
        "os_environment": "Windows PowerShell / cmd.exe",
        "volatility_plugin_version": "N/A",
        "comparable": "YES",
        "classification": "DIRECTLY_COMPARABLE",
        "transformation_required": "Run standard regex rules against sandbox command string.",
        "distribution_shift_risk": "Low. Standard PowerShell parameter syntax is uniform across all Windows environments.",
        "explanation": "Deterministic regex pattern matching.",
    },
    "has_download_cradle": {
        "feature_name": "has_download_cradle",
        "modality": "COMMAND",
        "our_definition": "Boolean indicator (0 or 1) detecting web download cradles (e.g. DownloadString, IWR, Net.WebClient, Invoke-WebRequest, bitsadmin, certutil -urlcache).",
        "public_dataset_definition": "Derived by regex search across command line string.",
        "source_field": "Regex matching on command string",
        "extraction_method": "DOWNLOAD_CRADLE_PATTERNS regex matching",
        "units": "Binary indicator (0 or 1)",
        "os_environment": "Windows PowerShell / cmd.exe",
        "volatility_plugin_version": "N/A",
        "comparable": "YES",
        "classification": "DIRECTLY_COMPARABLE",
        "transformation_required": "Apply DOWNLOAD_CRADLE_PATTERNS to sandbox command string.",
        "distribution_shift_risk": "Low. Fileless staging payloads universally utilize these cradle APIs.",
        "explanation": "Deterministic regex pattern matching.",
    },
    "has_bypass_execution_policy": {
        "feature_name": "has_bypass_execution_policy",
        "modality": "COMMAND",
        "our_definition": "Boolean indicator (0 or 1) detecting PowerShell execution policy bypass flags (-executionpolicy bypass, -ep bypass, -exec bypass).",
        "public_dataset_definition": "Derived by regex search across command line string.",
        "source_field": "Regex matching on command string",
        "extraction_method": "BYPASS_POLICY_PATTERNS regex matching",
        "units": "Binary indicator (0 or 1)",
        "os_environment": "Windows PowerShell",
        "volatility_plugin_version": "N/A",
        "comparable": "YES",
        "classification": "DIRECTLY_COMPARABLE",
        "transformation_required": "Apply BYPASS_POLICY_PATTERNS to sandbox command string.",
        "distribution_shift_risk": "Low. Uniform PowerShell command flag.",
        "explanation": "Deterministic regex pattern matching.",
    },
    "has_hidden_window": {
        "feature_name": "has_hidden_window",
        "modality": "COMMAND",
        "our_definition": "Boolean indicator (0 or 1) detecting stealth window flags (-windowstyle hidden, -w hidden, -noninteractive).",
        "public_dataset_definition": "Derived by regex search across command line string.",
        "source_field": "Regex matching on command string",
        "extraction_method": "HIDDEN_WINDOW_PATTERNS regex matching",
        "units": "Binary indicator (0 or 1)",
        "os_environment": "Windows PowerShell / cmd.exe",
        "volatility_plugin_version": "N/A",
        "comparable": "YES",
        "classification": "DIRECTLY_COMPARABLE",
        "transformation_required": "Apply HIDDEN_WINDOW_PATTERNS to sandbox command string.",
        "distribution_shift_risk": "Low. Standard stealth invocation syntax.",
        "explanation": "Deterministic regex pattern matching.",
    },
    "uses_lolbins": {
        "feature_name": "uses_lolbins",
        "modality": "COMMAND",
        "our_definition": "Boolean indicator (0 or 1) detecting execution of Living-off-the-Land binaries (certutil, mshta, rundll32, regsvr32, wmic, cscript, powershell, vssadmin).",
        "public_dataset_definition": "Derived by checking executed process binary against LOLBins dictionary.",
        "source_field": "Process name / command line binary token",
        "extraction_method": "LOLBINS_HIGH_RISK keyword matching",
        "units": "Binary indicator (0 or 1)",
        "os_environment": "Windows",
        "volatility_plugin_version": "N/A",
        "comparable": "YES",
        "classification": "DIRECTLY_COMPARABLE",
        "transformation_required": "Apply LOLBINS_HIGH_RISK dictionary to sandbox command string.",
        "distribution_shift_risk": "Low. LOLBin binary names are fixed Windows utilities.",
        "explanation": "Exact semantic and dictionary match.",
    },
    "registry_persistence_count": {
        "feature_name": "registry_persistence_count",
        "modality": "COMMAND",
        "our_definition": "Count of registry modifications targeting persistence keys (CurrentVersion\\Run, RunOnce, Winlogon, Services, IFEO) derived from Sysmon Event 12/13/14 and command patterns.",
        "public_dataset_definition": "Registry keys created/modified in sandbox behavior summary (CAPE: behavior.summary.keys).",
        "source_field": "Sysmon Event 12/13/14 (Custom) vs behavior.summary.keys (CAPE)",
        "extraction_method": "Sysmon registry auditing + command regex (Custom) vs Sandbox API hooking of RegSetValueEx (CAPE)",
        "units": "Integer count of persistence registry modifications",
        "os_environment": "Windows",
        "volatility_plugin_version": "N/A",
        "comparable": "PARTIAL",
        "classification": "COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION",
        "transformation_required": "Filter CAPE behavior.summary.keys using REGISTRY_PERSISTENCE_PATTERNS allowlist.",
        "distribution_shift_risk": "Moderate. Sandboxes hook all registry API calls, including benign application configs; filtering must strictly target persistence hives to prevent false-positive inflation.",
        "explanation": "Semantics align when CAPE registry keys are filtered through our exact persistence regex allowlist.",
    },
}

NETWORK_AUDIT: dict[str, dict[str, Any]] = {
    "active_connection_count": {
        "feature_name": "active_connection_count",
        "modality": "NETWORK",
        "our_definition": "Count of active TCP sockets in ESTABLISHED/SYN_SENT state observed at instantaneous live telemetry snapshot freeze time.",
        "public_dataset_definition": "Count of cumulative TCP connections opened during the 60-120s sandbox run (CAPE: len(network.tcp)).",
        "source_field": "network_connections.csv (Custom) vs network.tcp (CAPE)",
        "extraction_method": "Instantaneous socket table snapshot (Custom) vs Cumulative network packet/socket hook logging (CAPE)",
        "units": "Integer count of connections",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows sandbox environment (CAPE)",
        "volatility_plugin_version": "N/A",
        "comparable": "PARTIAL",
        "classification": "COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION",
        "transformation_required": "Document that CAPE reports cumulative connections over time, whereas Custom captures an instantaneous point-in-time snapshot.",
        "distribution_shift_risk": "High. Cumulative connection counts over 2 minutes are systematically higher than instantaneous snapshot counts for noisy samples.",
        "explanation": "Temporal measurement discrepancy: cumulative duration vs instantaneous freeze.",
    },
    "listening_port_count": {
        "feature_name": "listening_port_count",
        "modality": "NETWORK",
        "our_definition": "Count of unique local TCP/UDP ports open in LISTEN/LISTENING state at snapshot time.",
        "public_dataset_definition": "NOT RELIABLY RECORDED in sandbox summaries. Sandboxes focus on outbound connections; bind()/listen() calls are rarely indexed in network summary JSON.",
        "source_field": "network_connections.csv (Custom) vs None / API bind calls (CAPE)",
        "extraction_method": "netstat / Get-NetTCPConnection snapshot (Custom) vs Missing or API parse (CAPE)",
        "units": "Integer count of listening ports",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows sandbox environment (CAPE)",
        "volatility_plugin_version": "N/A",
        "comparable": "NO",
        "classification": "NOT_COMPARABLE",
        "transformation_required": "Preserve as None if sandbox report lacks explicit listening port/netstat table. Do not fabricate 0.",
        "distribution_shift_risk": "High. Defaulting missing listening ports to 0 creates an artificial negative bias against server/backdoor listeners.",
        "explanation": "Sandbox JSON reports generally omit local server socket tables.",
    },
    "outbound_connection_count": {
        "feature_name": "outbound_connection_count",
        "modality": "NETWORK",
        "our_definition": "Count of network connections directed to remote IP addresses outside private IPv4 address blocks.",
        "public_dataset_definition": "Count of external outbound TCP/UDP connections (CAPE: len([c for c in network.tcp if is_external(c)]).",
        "source_field": "network_connections.csv (Custom) vs network.tcp / network.udp (CAPE)",
        "extraction_method": "Socket remote address inspection (Custom) vs Sandbox packet capture flow analysis (CAPE)",
        "units": "Integer count of external connections",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows sandbox environment (CAPE)",
        "volatility_plugin_version": "N/A",
        "comparable": "PARTIAL",
        "classification": "COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION",
        "transformation_required": "Filter CAPE network flows for external destination IPs.",
        "distribution_shift_risk": "Moderate. Cumulative sandbox execution may record retried C2 connect attempts, elevating counts.",
        "explanation": "Good semantic agreement when external IP filters are identically applied.",
    },
    "dns_query_count": {
        "feature_name": "dns_query_count",
        "modality": "NETWORK",
        "our_definition": "Count of DNS query resolution events (Sysmon Event ID 22 or PCAP DNS frame count).",
        "public_dataset_definition": "Count of DNS queries resolved during analysis (CAPE: len(network.dns)).",
        "source_field": "Sysmon Event ID 22 (Custom) vs network.dns (CAPE)",
        "extraction_method": "Sysmon DNS logging (Custom) vs Sandbox internal DNS server resolver log (CAPE)",
        "units": "Integer count of DNS queries",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows sandbox environment (CAPE)",
        "volatility_plugin_version": "N/A",
        "comparable": "YES",
        "classification": "DIRECTLY_COMPARABLE",
        "transformation_required": "Direct count: len(network.dns).",
        "distribution_shift_risk": "Low. DNS query count ranges are comparable.",
        "explanation": "Exact semantic match between Sysmon Event ID 22 and sandbox DNS query logs.",
    },
    "unique_remote_ips": {
        "feature_name": "unique_remote_ips",
        "modality": "NETWORK",
        "our_definition": "Count of distinct external remote IP addresses contacted by the workload.",
        "public_dataset_definition": "Count of distinct external IP addresses in network summary (CAPE: len(set(network.hosts))).",
        "source_field": "network_connections.csv (Custom) vs network.hosts (CAPE)",
        "extraction_method": "Set of external remote IPs from socket table (Custom) vs Set of remote IPs from pcap/flows (CAPE)",
        "units": "Integer count of unique external IPs",
        "os_environment": "Windows 11 / 10 22H2 x64 (Custom) vs Windows sandbox environment (CAPE)",
        "volatility_plugin_version": "N/A",
        "comparable": "YES",
        "classification": "DIRECTLY_COMPARABLE",
        "transformation_required": "len(set(network.hosts)) excluding RFC1918 private subnets.",
        "distribution_shift_risk": "Low. External IP cardinality is consistent.",
        "explanation": "Identical semantic meaning and cardinality calculation.",
    },
    "avg_interpacket_interval_ms": {
        "feature_name": "avg_interpacket_interval_ms",
        "modality": "NETWORK",
        "our_definition": "Mean time interval in milliseconds between consecutive network packets on C2 channels derived from pcap packet timestamps.",
        "public_dataset_definition": "NOT AVAILABLE in summary JSON. Requires downloading and parsing raw .pcap artifact.",
        "source_field": "PCAP packet timestamp deltas",
        "extraction_method": "pyshark / scapy PCAP timing analysis (Custom) vs Unsupported in JSON summary (CAPE)",
        "units": "Float (milliseconds)",
        "os_environment": "Network capture",
        "volatility_plugin_version": "N/A",
        "comparable": "NO (JSON) / YES (with raw PCAP)",
        "classification": "NOT_COMPARABLE",
        "transformation_required": "Preserve as None if raw PCAP is not downloaded and parsed. Never impute 0.0.",
        "distribution_shift_risk": "Severe. 100% missing from JSON sandbox reports.",
        "explanation": "Timing metrics require raw packet capture files; high-level sandbox JSON reports do not preserve packet arrival delta timestamps.",
    },
    "beacon_regularity_score": {
        "feature_name": "beacon_regularity_score",
        "modality": "NETWORK",
        "our_definition": "Score between 0.0 and 1.0 measuring the regularity of periodic C2 beaconing pulses (inverse variance of inter-packet deltas).",
        "public_dataset_definition": "NOT AVAILABLE in summary JSON. Requires raw .pcap packet stream analysis.",
        "source_field": "PCAP inter-packet variance",
        "extraction_method": "Timing variance analysis on packet timestamps (Custom) vs Unsupported in JSON (CAPE)",
        "units": "Float normalized score [0.0, 1.0]",
        "os_environment": "Network capture",
        "volatility_plugin_version": "N/A",
        "comparable": "NO (JSON) / YES (with raw PCAP)",
        "classification": "NOT_COMPARABLE",
        "transformation_required": "Preserve as None without raw PCAP.",
        "distribution_shift_risk": "Severe. 100% missing from JSON reports.",
        "explanation": "Beaconing regularity is a micro-timing feature requiring full packet capture pcap.",
    },
    "total_bytes_sent": {
        "feature_name": "total_bytes_sent",
        "modality": "NETWORK",
        "our_definition": "Total bytes transmitted outbound by workload processes.",
        "public_dataset_definition": "Cumulative bytes transmitted (CAPE: available if NetFlow summary present; otherwise in PCAP).",
        "source_field": "network_connections / pcap (Custom) vs network.netflow[].bytes (CAPE)",
        "extraction_method": "PCAP byte count / interface counters (Custom) vs NetFlow byte summary (CAPE)",
        "units": "Integer byte count",
        "os_environment": "Network interface",
        "volatility_plugin_version": "N/A",
        "comparable": "PARTIAL",
        "classification": "COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION",
        "transformation_required": "Map from NetFlow if present, else preserve as None.",
        "distribution_shift_risk": "Moderate. Depends on sandbox run duration (30s vs 120s).",
        "explanation": "Comparable only when sandbox reports include byte-level flow telemetry; otherwise null.",
    },
    "total_bytes_received": {
        "feature_name": "total_bytes_received",
        "modality": "NETWORK",
        "our_definition": "Total bytes received inbound across workload network connections.",
        "public_dataset_definition": "Cumulative bytes received (CAPE: available if NetFlow summary present; otherwise in PCAP).",
        "source_field": "network_connections / pcap (Custom) vs network.netflow[].bytes (CAPE)",
        "extraction_method": "PCAP byte count / interface counters (Custom) vs NetFlow byte summary (CAPE)",
        "units": "Integer byte count",
        "os_environment": "Network interface",
        "volatility_plugin_version": "N/A",
        "comparable": "PARTIAL",
        "classification": "COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION",
        "transformation_required": "Map from NetFlow if present, else preserve as None.",
        "distribution_shift_risk": "Moderate. Scaled by payload download size and duration.",
        "explanation": "Comparable only when sandbox reports include byte-level flow telemetry; otherwise null.",
    },
    "suspicious_port_usage": {
        "feature_name": "suspicious_port_usage",
        "modality": "NETWORK",
        "our_definition": "Boolean indicator (0 or 1) indicating connection activity on known fileless/C2 ports (4444, 1337, 8888, 6667, 4443, etc.).",
        "public_dataset_definition": "Traffic targeting known suspicious ports in network.tcp/network.udp.",
        "source_field": "SUSPICIOUS_PORTS set lookup on local and remote ports",
        "extraction_method": "Port membership check against SUSPICIOUS_PORTS allowlist",
        "units": "Binary indicator (0 or 1)",
        "os_environment": "Network sockets",
        "volatility_plugin_version": "N/A",
        "comparable": "YES",
        "classification": "DIRECTLY_COMPARABLE",
        "transformation_required": "1 if any port in SUSPICIOUS_PORTS else 0.",
        "distribution_shift_risk": "Low. Port numbers are RFC standards and protocol identifiers.",
        "explanation": "Deterministic port membership check directly comparable.",
    },
}

ALL_FEATURE_AUDITS = {
    **PROCESS_AUDIT,
    **MEMORY_AUDIT,
    **COMMAND_AUDIT,
    **NETWORK_AUDIT,
}


def verify_feature_completeness() -> None:
    """Verify that all features in the pipeline schemas are present in the audit dictionary."""
    expected_process = set(PROCESS_FEATURE_COLS)
    expected_memory = set(MEMORY_FEATURE_COLS)
    expected_command = set(COMMAND_FEATURE_COLS)
    expected_network = set(NETWORK_FEATURE_COLS)

    audit_process = {k for k, v in ALL_FEATURE_AUDITS.items() if v["modality"] == "PROCESS"}
    audit_memory = {k for k, v in ALL_FEATURE_AUDITS.items() if v["modality"] == "MEMORY"}
    audit_command = {
        k
        for k, v in ALL_FEATURE_AUDITS.items()
        if v["modality"] == "COMMAND" and k != "raw_command_text"
    }
    audit_network = {k for k, v in ALL_FEATURE_AUDITS.items() if v["modality"] == "NETWORK"}

    assert (
        expected_process == audit_process
    ), f"Process mismatch: {expected_process ^ audit_process}"
    assert expected_memory == audit_memory, f"Memory mismatch: {expected_memory ^ audit_memory}"
    assert (
        expected_command == audit_command
    ), f"Command mismatch: {expected_command ^ audit_command}"
    assert (
        expected_network == audit_network
    ), f"Network mismatch: {expected_network ^ audit_network}"


def generate_json_audit() -> dict[str, Any]:
    """Generate the structured JSON audit artifact."""
    verify_feature_completeness()

    # Classification tallies
    classifications = {
        "DIRECTLY_COMPARABLE": 0,
        "COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION": 0,
        "NOT_COMPARABLE": 0,
        "MALMEM_SPECIFIC_PROXY": 0,
    }
    modality_classifications = {
        "PROCESS": "CONDITIONAL",
        "MEMORY": "CONDITIONAL",
        "COMMAND": "CONDITIONAL",
        "NETWORK": "CONDITIONAL",
    }

    per_modality_counts: dict[str, dict[str, int]] = {
        "PROCESS": {
            "DIRECTLY_COMPARABLE": 0,
            "COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION": 0,
            "NOT_COMPARABLE": 0,
            "MALMEM_SPECIFIC_PROXY": 0,
        },
        "MEMORY": {
            "DIRECTLY_COMPARABLE": 0,
            "COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION": 0,
            "NOT_COMPARABLE": 0,
            "MALMEM_SPECIFIC_PROXY": 0,
        },
        "COMMAND": {
            "DIRECTLY_COMPARABLE": 0,
            "COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION": 0,
            "NOT_COMPARABLE": 0,
            "MALMEM_SPECIFIC_PROXY": 0,
        },
        "NETWORK": {
            "DIRECTLY_COMPARABLE": 0,
            "COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION": 0,
            "NOT_COMPARABLE": 0,
            "MALMEM_SPECIFIC_PROXY": 0,
        },
    }

    for feat in ALL_FEATURE_AUDITS.values():
        c = feat["classification"]
        m = feat["modality"]
        classifications[c] += 1
        per_modality_counts[m][c] += 1

    audit_payload = {
        "audit_version": "1.0.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "summary": {
            "total_features_audited": len(ALL_FEATURE_AUDITS),
            "classification_totals": classifications,
            "modality_verdicts": modality_classifications,
            "recommended_strategy": "C",
            "recommended_strategy_name": "Separate domain-specific models (with Strategy B for public-benchmark baseline reporting)",
        },
        "modality_breakdowns": per_modality_counts,
        "features": ALL_FEATURE_AUDITS,
        "training_strategy_evaluation": {
            "Strategy_A": {
                "name": "Same-model training on public + custom data (Joint pooled training)",
                "verdict": "REJECTED",
                "rationale": "Severe sample size imbalance (58,596 MalMem vs 45 Custom = 1,300:1 ratio). MalMem has 100% missing values for key fileless features (anomalous_ppid, elevated_privilege, suspicious_dll, entropy, shellcode). Joint training would cause zero-variance removal to permanently drop these fileless features, blinding the model to the primary attack techniques our system was designed to detect.",
            },
            "Strategy_B": {
                "name": "Public-data training -> custom-data held-out evaluation (Zero-shot domain transfer)",
                "verdict": "ACCEPTED_AS_AUXILIARY_BENCHMARK",
                "rationale": "Valid as an out-of-distribution transfer test for the shared feature subset (6 Process features, 5 Memory features). Proves whether academic public models transfer to modern Windows 11 live environments. However, cannot serve as the primary fileless detector because it is restricted to coarse counts and blind to advanced memory entropy and lineage features.",
            },
            "Strategy_C": {
                "name": "Separate domain-specific models",
                "verdict": "RECOMMENDED",
                "rationale": "Maintains strict scientific integrity. Model 1 (Public Benchmark Baseline): Trained on CIC-MalMem-2022 to publish benchmark parity against the literature. Model 2 (Real-Time Fileless Hybrid Detector): Trained on custom VM telemetry utilizing the full 4-modality feature vector. Neither dataset pollutes or constrains the feature space of the other.",
            },
            "Strategy_D": {
                "name": "Public data used only for auxiliary/pretraining purposes",
                "verdict": "CONDITIONALLY_ACCEPTABLE",
                "rationale": "Viable for tabular embedding pretraining or weight warm-starting on the shared subset, but provides minimal gain for GBDTs (XGBoost/CatBoost) compared to separate models, while risking negative transfer from MalMem's zombie-process psxview artifacts.",
            },
        },
    }

    json_path = PROCESSED_PUBLIC_DIR / "cross_dataset_compatibility.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(audit_payload, f, indent=2)

    return audit_payload


def generate_markdown_report(audit_payload: dict[str, Any]) -> None:
    """Generate docs/cross_dataset_feature_compatibility.md."""
    lines: list[str] = [
        "# Cross-Dataset Feature Compatibility Audit & Semantics Report",
        "",
        "## 1. Executive Summary",
        "",
        "Before expanding training sets across heterogeneous sources, this audit determines whether public datasets "
        "can legitimately train models whose final evaluation is performed on our custom VM telemetry.",
        "",
        "### Key Forensic Findings:",
        "1. **Semantic Divergence Beyond Column Names**: Matching column names frequently conceal profound algorithmic discrepancies. "
        "For example, Volatility 2's `psxview` in CIC-MalMem-2022 flags normal terminated/dead processes as 'hidden', "
        "whereas our Volatility 3 pipeline explicitly checks `ExitTime` to filter terminated threads.",
        "2. **Unmeasured Feature Gaps**: CIC-MalMem-2022 provides **0% coverage** for parent-child lineage anomalies, token privileges, "
        "DLL staging paths, YARA shellcode matches, and page Shannon entropy. Pooling public and custom data would cause zero-variance "
        "filtering to drop these exact high-value fileless indicators.",
        "3. **Temporal Mismatch in Sandbox Telemetry (CAPE/Any.Run)**: Sandbox reports record *cumulative* connections and processes over "
        "60-120 seconds, whereas our live framework evaluates *instantaneous* point-in-time system state.",
        "",
        "---",
        "",
        "## 2. Modality-Level Compatibility Verdicts",
        "",
        "| Modality | Verdict | Directly Comparable | Comparable w/ Transform | Proxy / Not Comparable | Critical Forensic Bottleneck |",
        "| :--- | :---: | :---: | :---: | :---: | :--- |",
        f"| **PROCESS** | **{audit_payload['summary']['modality_verdicts']['PROCESS']}** | {audit_payload['modality_breakdowns']['PROCESS']['DIRECTLY_COMPARABLE']} | {audit_payload['modality_breakdowns']['PROCESS']['COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION']} | {audit_payload['modality_breakdowns']['PROCESS']['NOT_COMPARABLE']} | MalMem lacks lineage (`anomalous_ppid`), privileges, DLL paths (4/10 features missing). |",
        f"| **MEMORY** | **{audit_payload['summary']['modality_verdicts']['MEMORY']}** | {audit_payload['modality_breakdowns']['MEMORY']['DIRECTLY_COMPARABLE']} | {audit_payload['modality_breakdowns']['MEMORY']['COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION']} | {audit_payload['modality_breakdowns']['MEMORY']['NOT_COMPARABLE'] + audit_payload['modality_breakdowns']['MEMORY']['MALMEM_SPECIFIC_PROXY']} ({audit_payload['modality_breakdowns']['MEMORY']['MALMEM_SPECIFIC_PROXY']} Proxy, {audit_payload['modality_breakdowns']['MEMORY']['NOT_COMPARABLE']} Missing) | MalMem lacks raw bytes/entropy and YARA rules (3/8 missing); `vad_protection_anomaly_count` is a `MALMEM_SPECIFIC_PROXY` strictly excluded from zero-shot. |",
        f"| **COMMAND** | **{audit_payload['summary']['modality_verdicts']['COMMAND']}** | {audit_payload['modality_breakdowns']['COMMAND']['DIRECTLY_COMPARABLE']} | {audit_payload['modality_breakdowns']['COMMAND']['COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION']} | {audit_payload['modality_breakdowns']['COMMAND']['NOT_COMPARABLE']} | MalMem has 0% command telemetry. CAPE behavioral reports provide authentic strings. |",
        f"| **NETWORK** | **{audit_payload['summary']['modality_verdicts']['NETWORK']}** | {audit_payload['modality_breakdowns']['NETWORK']['DIRECTLY_COMPARABLE']} | {audit_payload['modality_breakdowns']['NETWORK']['COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION']} | {audit_payload['modality_breakdowns']['NETWORK']['NOT_COMPARABLE']} | Timing features (`interpacket`, `beacon`) require raw PCAP; JSON summaries omit them. |",
        "",
        "---",
        "",
        "## 3. Comprehensive Feature Compatibility Matrix (All 36 Features)",
        "",
    ]

    for mod in ["PROCESS", "MEMORY", "COMMAND", "NETWORK"]:
        lines.append(f"### {mod} Modality Features")
        lines.append("")
        lines.append(
            "| Feature | Status | Our Definition | Public Definition | Extraction Method & Tool | Units | Shift Risk |"
        )
        lines.append("| :--- | :---: | :--- | :--- | :--- | :--- | :---: |")

        for feat_name, feat in ALL_FEATURE_AUDITS.items():
            if feat["modality"] != mod:
                continue
            lines.append(
                f"| `{feat_name}` | **{feat['classification']}** | {feat['our_definition'][:65]}... | "
                f"{feat['public_dataset_definition'][:65]}... | {feat['extraction_method'][:45]}... | "
                f"{feat['units']} | {feat['distribution_shift_risk'][:15]} |"
            )
        lines.append("")

    lines.extend(
        [
            "---",
            "",
            "## 4. In-Depth Semantic Analysis by Modality",
            "",
            "### 4.1 Process Modality (Custom vs CIC-MalMem-2022 vs CAPE)",
            "- **`total_process_count`**: Directly comparable. However, clean Windows 11 22H2 endpoints maintain 70-110 baseline processes due to modern service decoupling (`svchost` per service), whereas MalMem's VirtualBox Windows 10 baseline shows 40-50 processes. A tree model trained on MalMem will learn low process count cutoffs that misclassify clean Windows 11 as anomalous.",
            "- **`hidden_process_count`**: Partial compatibility. In Volatility 2 (`psxview`), deallocated processes that linger in memory pools show as `not_in_pslist=True`. Custom pipeline uses `is_terminated_process(ExitTime)` to eliminate dead processes. MalMem exhibits false-positive hidden processes.",
            "- **`anomalous_ppid_count`, `suspicious_dll_count`, `elevated_privilege_count`**: **Completely unmeasured in MalMem (100% missing)**. In CAPE, these can be derived from process tree and API logs.",
            "- **`malfind_process_count`**: MalMem records `malfind.ninjections` (count of injected regions), whereas custom measures distinct PIDs. Monotonically correlated but MalMem values are an upper bound.",
            "",
            "### 4.2 Memory Modality (Custom vs CIC-MalMem-2022)",
            "- **`injected_code_regions` & `ldrmodules_inconsistencies`**: Direct semantic parity. Algorithmically identical across Volatility 2 and Volatility 3.",
            "- **`rwx_page_count` & `unmapped_executable_pages`**: Comparable with documented transformation.",
            "- **`vad_protection_anomaly_count`**: **MALMEM_SPECIFIC_PROXY**. Incompatible semantic definitions. Custom calculates `InitProtection != Protection` (e.g. `VirtualProtect` RW -> RWX). MalMem proxies this via `commitCharge > 0` on injected pages. Strictly excluded from the zero-shot shared feature vector.",
            "- **`mean_memory_entropy`, `max_memory_entropy`, `yara_shellcode_matches`**: **Completely unmeasured in MalMem**. MalMem preserved no raw RAM bytes or YARA scan outputs.",
            "",
            "### 4.3 Command Modality (Custom vs CAPE/Any.Run vs MalMem)",
            "- **CIC-MalMem-2022**: Contains **0% command telemetry**. Zero command lines, zero script blocks.",
            "- **CAPE / Any.Run**: Authentic `command_line` strings are recorded in behavioral execution trees. All derived lexical and regex features (`command_length`, `shannon_entropy`, `is_base64_encoded`, `has_download_cradle`, `has_bypass_execution_policy`, `has_hidden_window`, `uses_lolbins`) are **100% directly comparable** via `CommandAdapter.from_raw_command`.",
            "- **`registry_persistence_count`**: Sandbox reports capture API-level `RegSetValueEx` calls. Applying `REGISTRY_PERSISTENCE_PATTERNS` regex filter achieves direct alignment.",
            "",
            "### 4.4 Network Modality (Custom vs CAPE/Any.Run)",
            "- **Snapshot vs Cumulative Temporal Divergence**: Custom live collector captures an instantaneous point-in-time socket table snapshot. Sandbox reports aggregate cumulative network activity over the entire 60-120s run.",
            "- **`dns_query_count`, `unique_remote_ips`, `suspicious_port_usage`**: Directly comparable.",
            "- **`listening_port_count`**: Sandboxes rarely record server listening sockets; typically missing or zero in JSON reports.",
            "- **Timing Features (`avg_interpacket_interval_ms`, `beacon_regularity_score`)**: **Not comparable from summary JSON**. Micro-timing calculations require raw `.pcap` packet streams.",
            "",
            "---",
            "",
            "## 5. Training Strategy Recommendation",
            "",
            "### Evaluation of Candidate Strategies:",
            "",
            "#### Strategy A: Same-model training on public + custom data (Joint pooled training)",
            "- **Verdict**: **REJECTED**.",
            "- **Rationale**: MalMem contains 58,596 samples; our custom dataset contains 45 samples (ratio > 1,300 : 1). Merging them into a single training matrix forces imputation or dropping of the 4 process features and 3 memory features absent in MalMem. The resulting model would be 99.9% dominated by MalMem's older Windows 10 VirtualBox distribution, discarding the very fileless attack indicators our project is engineered to detect.",
            "",
            "#### Strategy B: Public-data training -> custom-data held-out evaluation (Zero-shot domain transfer)",
            "- **Verdict**: **ACCEPTED AS AUXILIARY BENCHMARK**.",
            "- **Rationale**: Legitimate scientific experiment to evaluate out-of-distribution transfer for the shared feature subset (6 Process features, 5 Memory features). However, it cannot serve as the primary fileless detector because it is restricted to coarse counts and blind to memory entropy, privileges, and lineage.",
            "",
            "#### Strategy C: Separate domain-specific models",
            "- **Verdict**: **RECOMMENDED**.",
            "- **Rationale**: Maintains complete scientific and forensic integrity:",
            "  1. **Public Benchmark Models**: Trained on public data (CIC-MalMem for Process/Memory; CAPE for Command/Network) and reported against academic literature.",
            "  2. **Real-Time Hybrid Detector**: Trained on our high-fidelity custom VM telemetry with full 4-modality feature vectors.",
            "  3. Neither dataset compromises the feature schema or distribution of the other.",
            "",
            "#### Strategy D: Public data used only for auxiliary/pretraining purposes",
            "- **Verdict**: **CONDITIONALLY ACCEPTABLE**.",
            "- **Rationale**: Useful for tabular representations or neural networks (e.g. DistilBERT command pretraining), but offers minimal benefit for gradient boosted trees (XGBoost/CatBoost) compared to clean model separation.",
            "",
            "---",
            "",
            "## 6. Identified Risks & Mitigation Protocols",
            "",
            "1. **Risk: Volatility 2 Dead Process Inversion**: MalMem's `psxview.not_in_pslist` includes terminated dead processes.",
            "   - *Mitigation*: Never evaluate a model trained on MalMem against custom data without documenting this bias.",
            "2. **Risk: Missing Feature Dropping**: Zero-variance filtering on pooled data would delete `anomalous_ppid_count` and `mean_memory_entropy`.",
            "   - *Mitigation*: Keep public and custom training pipelines strictly separated (Strategy C).",
            "3. **Risk: Cumulative Sandbox Bias**: CAPE network counts exceed snapshot counts.",
            "   - *Mitigation*: When ingesting sandbox telemetry, apply duration-normalized rates rather than raw counts.",
        ]
    )

    md_path = DOCS_DIR / "cross_dataset_feature_compatibility.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main() -> None:
    """Run generation and verification."""
    audit = generate_json_audit()
    generate_markdown_report(audit)
    print("Cross-dataset compatibility audit generated successfully.")
    print(f"Total features audited: {audit['summary']['total_features_audited']}")
    print(
        f"Directly Comparable: {audit['summary']['classification_totals']['DIRECTLY_COMPARABLE']}"
    )
    print(
        f"Comparable with Transform: {audit['summary']['classification_totals']['COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION']}"
    )
    print(f"Not Comparable: {audit['summary']['classification_totals']['NOT_COMPARABLE']}")


if __name__ == "__main__":
    main()
