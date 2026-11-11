# Cross-Modality Data Map & Feature Quality Inventory

**Date:** 2026-09-22  
**Purpose:** Comprehensive field-by-field mapping from raw/forensic evidence to derived features, target models, and data quality classifications.  
**Status:** COMPLETE — EMPIRICALLY VERIFIED AGAINST `Dataset/` FILES.

---

## 1. Cross-Modality Lineage Map

The table below traces every candidate input field from its exact physical source in `Dataset/` to the derived feature, destination model, and aggregation level:

| Evidence Source | Source Field / Column | Derived Feature | Target Model | Aggregation Level | Data Quality Flag | Quality Rationale / Notes |
|---|---|---|---|---|---|---|
| `sysmon.evtx` (EID 1) | `CommandLine` | `raw_command_text` | Command (NLP) | Session / Run | **VALID** | Real command arguments. Must be parsed with binary EVTX parser. |
| `sysmon.evtx` (EID 1) | `CommandLine` | `shannon_entropy` | Command (Tabular) | Run | **VALID** | High entropy detects base64 payloads and obfuscated scripts. |
| `sysmon.evtx` (EID 1) | `CommandLine` | `has_download_cradle` | Command, Multiclass | Run | **VALID** | Boolean regex match for `Net.WebClient`, `IWR`, `curl`, `DownloadString`. |
| `sysmon.evtx` (EID 1) | `CommandLine` | `uses_lolbins` | Command, Multiclass | Run | **VALID** | Detects living-off-the-land execution (`certutil`, `mshta`, `rundll32`). |
| `sysmon.evtx` (EID 1) | `ParentImage` + `Image` | `anomalous_ppid_count` | Process | Run | **VALID** | Detects abnormal execution lineages (e.g. `services.exe` -> `powershell.exe`). |
| `powershell.evtx` (EID 4104)| `ScriptBlockText` | `raw_command_text` | Command (NLP) | Session / Run | **VALID** | De-obfuscated script blocks evaluated dynamically in RAM. |
| `sysmon.evtx` (EID 3) | `DestinationIp` | `unique_remote_ips` | Network | Run | **VALID** | Number of distinct external/sandbox IPs contacted. |
| `sysmon.evtx` (EID 3) | `DestinationPort` | `suspicious_port_usage` | Network, Multiclass | Run | **VALID** | Flags non-standard C2 listener ports (4444, 8000, 8080). |
| `sysmon.evtx` (EID 3) | `Image` | `scripting_proc_net_count`| Network | Run | **VALID** | Connections initiated by `powershell.exe`, `cmd.exe`, `rundll32.exe`. |
| `network_connections.csv` | `LocalPort` | `listening_port_count` | Network | Run | **CONSTANT** | Exactly 10 ports in all 45 runs (Windows 11 baseline RPC/SMB). Zero variance! |
| `network_connections.csv` | `RemoteAddress` | `active_connection_count`| Network | Run | **UNUSABLE / CONSTANT**| 99.5% of rows are `::` or `0.0.0.0` in `Listen` state. Outbound traffic missing here. |
| `volatility/pslist.txt` | `PID` | `total_process_count` | Process | Run | **VALID** | Total processes linked in OS active process list. |
| `volatility/psscan.txt` | `PID` vs `pslist.PID` | `hidden_process_count` | Process | Run | **VALID** | Processes unlinked via DKOM or unlinked from ActiveProcessLinks. |
| `volatility/threads.txt` | `Threads` / `PID` | `avg_threads_per_process`| Process | Run | **QUESTIONABLE** | Heavily influenced by multi-threaded background daemons. |
| `volatility/handles.txt` | `Handles` / `PID` | `total_handle_count` | Process | Run | **CONTAMINATED** | Windows Defender (`MsMpEng.exe`) holds 12,000+ handles. Must filter Defender! |
| `volatility/privileges.txt`| `Privilege`, `Attributes`| `elevated_privilege_count`| Process | Run | **CONTAMINATED** | System daemons hold elevated tokens by default. Filter by non-system PIDs. |
| `volatility/dlllist.txt` | `Path` | `suspicious_dll_count` | Process | Run | **VALID** | Flags DLLs loaded from `\Temp\` or unbacked memory. |
| `volatility/malfind.txt` | `Process`, `Protection` | `rwx_page_count` | Memory | Run | **CONTAMINATED** | 14-15 RWX regions belong to `MsMpEng.exe` in EVERY run. Must filter Defender! |
| `volatility/malfind.txt` | `Hexdump`, `Disasm` | `shellcode_preamble_matches`| Memory | Run | **VALID** | Detects `\xFC\xE8` (cld; call) and `MZ` headers in private memory. |
| `volatility/vadinfo.txt` | `Protection`, `File` | `unmapped_executable_pages`| Memory | Run | **VALID** | Executable memory regions with no backing file on disk (excluding Defender). |
| `volatility/vadinfo.txt` | `Protection`, `OriginalProt`| `vad_protection_anomalies`| Memory | Run | **VALID** | Detects VirtualProtect memory permission changes (RW -> RX/RWX). |
| `volatility/ldrmodules.txt`| `InLoad`, `InInit`, `InMem`| `unlinked_dll_count` | Memory, Multiclass | Run | **VALID** | Detects Reflective DLL injection (`InLoad = False, InMem = True`). |
| PCAP Packet Timestamps | Timestamp deltas | `avg_interpacket_interval`| Network | Run | **MISSING / UNSUPPORTED** | No PCAP files exist in `Dataset/`. Must NOT be imputed with 0. |
| PCAP Payload Bytes | Packet payload size | `total_bytes_sent` | Network | Run | **MISSING / UNSUPPORTED** | No PCAP files exist in `Dataset/`. Must NOT be imputed with 0. |
| Memory Dump Binary | Raw byte dump | `mean_memory_entropy` | Memory | Run | **MISSING / UNSUPPORTED** | Memory dumps were not distributed in archive. Must NOT be imputed. |
| `metadata/RUN-001.json` | `label`, `family` | Ground truth target | All Models | Run | **VALID (CORRECTED)** | Previously misassigned as benign in interim report; true label is malware (1). |

---

## 2. Comprehensive Data Quality Flag Definitions & Detailed Analysis

### 2.1 CONTAMINATED Features
- **Unfiltered Total Handles (`total_handle_count`):**  
  In `handles.txt`, Windows Defender (`MsMpEng.exe`) opens 11,000 to 14,000 handles scanning filesystem and registry objects across the VM. Background services (`svchost.exe`, `lsass.exe`) open another 20,000 handles. Raw handle counts measure the duration and aggressiveness of Windows Defender rather than malware behavior.  
  *Fix:* Subtract handles belonging to `MsMpEng.exe`, `System`, and `lsass.exe`.
- **Unfiltered Memory RWX Pages (`rwx_page_count`):**  
  In `malfind.txt` and `vadinfo.txt`, `MsMpEng.exe` consistently accounts for 14 to 15 RWX regions in both benign and malware runs due to its dynamic emulation engine.  
  *Fix:* Exclude `MsMpEng.exe` from memory region counts.

### 2.2 CONSTANT / ZERO-VARIANCE Features
- **Socket Baseline Listening Ports (`listening_port_count`):**  
  In `network_connections.csv`, all 45 runs contain exactly 10 listening ports (135, 445, 5040, 7680, 49664-49669). The feature has zero variance across classes.  
  *Fix:* Retire from the feature schema. Replace with outbound connection counts from Sysmon Event ID 3.

### 2.3 MISSING / UNSUPPORTED Features
- **PCAP Flow Metrics (`avg_interpacket_interval_ms`, `beacon_regularity_score`, `total_bytes_sent`, `total_bytes_received`, `dns_query_count`):**  
  Zero PCAP files were collected. Previous models imputed these with `0.0` and appended missingness indicator columns that were identical constants across all samples.  
  *Fix:* Formally remove all 5 PCAP-dependent features from the network schema.

### 2.4 LEAKAGE-RISK & PROVENANCE DISCREPANCIES
- **`RUN-001` Label Override:**  
  `Dataset/custom_powershell_fileless/metadata/RUN-001.json` explicitly states `"family": "powershell_fileless", "label": 1`. In `data/interim/dataset_audit_report.json`, this was recorded as `family: "benign", label: 0`. This discrepancy contaminated the class distributions (13 benign / 32 malware instead of 12 benign / 33 malware).  
  *Fix:* Ground truth must be read directly from `Dataset/` metadata JSON files.
- **Process `StartTime`:**  
  Absolute execution timestamps reflect the time of day the VM test harness executed rather than intrinsic malware behavior. Evaluating raw timestamps introduces temporal leakage.
