# Rich Forensic Dataset Inventory Report
**Project:** Real-Time AI-Based Fileless Malware Detection and Classification System  
**Primary Source of Truth Location:** `C:\Users\Prash\Desktop\Real-Time-Fileless-Malware-Detection\Dataset`  
**Date of Inspection:** 2026-09-24  
**Audit Status:** PHASE 1 COMPLETE — Forensic Evidence Inspected & Cataloged  

---

## 1. Executive Summary

This report establishes the baseline inventory of the authoritative custom forensic dataset located strictly at:
`C:\Users\Prash\Desktop\Real-Time-Fileless-Malware-Detection\Dataset`

All findings are grounded directly in the physical directories, forensic plugin outputs, and Windows source telemetry present on disk. No data has been modified, fabricated, or deleted.

```
============================================================
DATASET SUMMARY
============================================================
Total Categories:       12
Total Execution Runs:   45
Total Benign Runs:      13 (RUN-001 + RUN-1100 through RUN-1111)
Total Malware Runs:     32 (RUN-002, RUN-003 + 30 runs across 10 families)
Total Malware Families: 11
Operating System:       Microsoft Windows 11 Home (64-bit)
Environment:            Isolated host-only VM sandbox
```

---

## 2. Directory Layout & Layer Architecture

The dataset is organized into 12 batch directories. Every batch maintains an identical, disciplined subfolder layout:

```
Dataset/<category_name>/
├── batch_summary.csv           # Batch-level execution and artifact manifest
├── checksums.sha256            # SHA-256 cryptographic hashes for integrity
├── manifest.json               # Package manifest with run IDs and operator metadata
├── metadata/                   # Sample-level execution metadata (.json)
│   └── <RUN-ID>.json
├── process/                    # LEGACY DERIVED compact process features (to be superseded)
│   └── <RUN-ID>.json
├── memory/                     # LEGACY DERIVED compact memory features (to be superseded)
│   └── <RUN-ID>.json
├── source_evidence/            # RAW WINDOWS SOURCE TELEMETRY
│   └── <RUN-ID>/
│       ├── network_connections.csv   # Netstat/TCP socket telemetry
│       ├── process_snapshot.csv      # Live process execution snapshot
│       ├── powershell.evtx           # PowerShell operational event log (EID 4104, etc.)
│       └── sysmon.evtx               # Microsoft Sysmon event log (EID 1, 3, 5, etc.)
└── volatility/                 # RICH MEMORY FORENSIC EVIDENCE (Volatility 3)
    └── <RUN-ID>/
        ├── pslist.txt          # Active process list
        ├── psscan.txt          # Pool-scanned processes (including unlinked/terminated)
        ├── psxview.txt         # Cross-view process discrepancy matrix
        ├── pstree.txt          # Hierarchical process tree with command-line arguments
        ├── threads.txt         # Thread start addresses, paths, and Win32 entry points
        ├── handles.txt         # Object handles (Process, Thread, Mutant, Key, File)
        ├── dlllist.txt         # Loaded modules with base addresses, sizes, and paths
        ├── malfind.txt         # Injected / RWX memory regions with disassembly & hexdumps
        ├── privileges.txt      # Process token privileges and assigned states
        ├── ldrmodules.txt      # DLL loader list integrity (InLoad, InInit, InMem)
        └── vadinfo.txt         # Virtual Address Descriptors (protections, tags, commit)
```

---

## 3. Category & Run Inventory

| # | Category Directory | Runs | Canonical Label | Family | Track | OS Platform |
|---|---|---|---|---|---|---|
| 1 | `custom_benign_batch` | RUN-1100 to RUN-1111 (12 runs) | 0 (Benign) | `benign` | BENIGN | Win11 Home 64-bit |
| 2 | `custom_powershell_fileless` | RUN-001 | 0 (Benign) | `benign` | BENIGN | Win11 Home 64-bit |
| | | RUN-002, RUN-003 (2 runs) | 1 (Malware) | `powershell_fileless` | TRACK_A | Win11 Home 64-bit |
| 3 | `custom_process_hollowing` | RUN-100, RUN-101, RUN-102 (3 runs) | 1 (Malware) | `process_hollowing` | TRACK_A | Win11 Home 64-bit |
| 4 | `custom_memory_only_rat` | RUN-200, RUN-201, RUN-202 (3 runs) | 1 (Malware) | `memory_only_rat` | TRACK_A | Win11 Home 64-bit |
| 5 | `custom_registry_resident_malware` | RUN-300, RUN-301, RUN-302 (3 runs) | 1 (Malware) | `registry_resident_malware` | TRACK_A | Win11 Home 64-bit |
| 6 | `custom_cobalt_strike_beacon` | RUN-400, RUN-401, RUN-402 (3 runs) | 1 (Malware) | `cobalt_strike_beacon` | TRACK_A | Win11 Home 64-bit |
| 7 | `custom_metasploit_memory_payloads` | RUN-500, RUN-501, RUN-502 (3 runs) | 1 (Malware) | `metasploit_memory_payloads` | TRACK_A | Win11 Home 64-bit |
| 8 | `custom_wmi_malware` | RUN-600, RUN-601, RUN-602 (3 runs) | 1 (Malware) | `wmi_malware` | TRACK_B | Win11 Home 64-bit |
| 9 | `custom_reflective_dll_injection` | RUN-700, RUN-701, RUN-702 (3 runs) | 1 (Malware) | `reflective_dll_injection` | TRACK_B | Win11 Home 64-bit |
| 10 | `custom_lolbins_abuse` | RUN-800, RUN-801, RUN-802 (3 runs) | 1 (Malware) | `lolbins_abuse` | TRACK_B | Win11 Home 64-bit |
| 11 | `custom_fileless_ransomware` | RUN-900, RUN-901, RUN-902 (3 runs) | 1 (Malware) | `fileless_ransomware` | TRACK_B | Win11 Home 64-bit |
| 12 | `custom_empire_framework` | RUN-1000, RUN-1001, RUN-1002 (3 runs) | 1 (Malware) | `empire_framework` | TRACK_B | Win11 Home 64-bit |

> [!IMPORTANT]
> **Canonical Ground-Truth Resolution for RUN-001:**  
> In `Dataset/custom_powershell_fileless/metadata/RUN-001.json`, the sample was recorded with a duplicate identifier `EXEC_RUN-003` and label 1 due to an initial operator script template artifact. However, authoritative run manifests (`batch_summary.csv`), operator logs, and the canonical dataset audit establish that `RUN-001` was the clean baseline/validation run for Track A, while `RUN-002` and `RUN-003` executed actual PowerShell fileless attack payloads.  
> Therefore, the true dataset distribution is strictly: **13 Benign, 32 Malware**.

---

## 4. Evidence Matrix (All 45 Runs)

| Run ID | Process Evidence | Command Evidence | Network Evidence | Memory Evidence | Sysmon EVTX | PowerShell EVTX | Volatility 3 | PCAP |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **RUN-1100** | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-1101** | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-1102** | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-1103** | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-1104** | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-1105** | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-1106** | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-1107** | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-1108** | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-1109** | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-1110** | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-1111** | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-001**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-002**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-003**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-100**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-101**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-102**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-200**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-201**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-202**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-300**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-301**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-302**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-400**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-401**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-402**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-500**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-501**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-502**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-600**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-601**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-602**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-700**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-701**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-702**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-800**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-801**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-802**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-900**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-901**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-902**  | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-1000** | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-1001** | YES | YES | YES | YES | YES | YES | YES | NO |
| **RUN-1002** | YES | YES | YES | YES | YES | YES | YES | NO |

*Legend: YES = Complete evidence present on disk; PARTIAL = Incomplete or proxy; NO = Telemetry not collected.*

---

## 5. Rich Forensic Content vs. Legacy Compact ML Features

### 5.1 Volatility 3 Plugin Evidence Analysis

| Plugin File | Records / Run (Typical) | Fields Available in Raw Evidence | What the Old Pipeline Kept | What the Rich Representation Retains |
|---|---|---|---|---|
| `pslist.txt` | 130 – 155 | `PID`, `PPID`, `ImageFileName`, `Offset(V)`, `Threads`, `Handles`, `SessionId`, `Wow64`, `CreateTime`, `ExitTime` | `total_process_count` (1 scalar) | Process identity, execution timelines, 32-bit (Wow64) indicators, process lifetime |
| `psscan.txt` | 135 – 160 | `PID`, `PPID`, `ImageFileName`, `Offset(V)`, `Threads`, `Handles`, `SessionId`, `Wow64`, `CreateTime`, `ExitTime` | Discarded entirely | Pool-carved unlinked processes, terminated process remnants, memory offset mapping |
| `psxview.txt` | 125 – 145 | `Offset(Virtual)`, `Name`, `PID`, `pslist`, `psscan`, `thrdscan`, `csrss`, `Exit Time` | `hidden_process_count` (1 scalar) | Discrepancy booleans across 4 independent OS discovery mechanisms |
| `pstree.txt` | 130 – 155 | Tree Depth (asterisks), `PID`, `PPID`, `ImageFileName`, `Offset(V)`, `Threads`, `Handles`, `SessionId`, `Wow64`, `CreateTime`, `ExitTime`, `Audit`, `Cmd`, `Path` | `anomalous_ppid_count` (1 scalar) | Complete parent-child lineage, command line invocations (`Cmd`), image paths (`Path`) |
| `threads.txt` | 1,400 – 1,950 | `Offset`, `PID`, `TID`, `StartAddress`, `StartPath`, `Win32StartAddress`, `Win32StartPath`, `CreateTime`, `ExitTime` | `avg_threads_per_process`, `max_threads_in_single_process` | Per-process thread distributions, execution entry points (kernel vs unmapped memory) |
| `handles.txt` | 45,000 – 58,000 | `PID`, `Process`, `Offset`, `HandleValue`, `Type`, `GrantedAccess`, `Name` | `total_handle_count` (1 scalar) | Object handle types (`Mutant`, `Key`, `Section`, `Process`, `File`), access masks, named pipes |
| `dlllist.txt` | 6,000 – 7,300 | `PID`, `Process`, `Base`, `Size`, `Name`, `Path`, `LoadCount`, `LoadTime` | `suspicious_dll_count` (1 scalar) | Loaded module paths, base addresses, virtual sizes, execution timestamps, load counts |
| `malfind.txt` | 700 – 900 lines (15–25 findings) | `PID`, `Process`, `Start VPN`, `End VPN`, `Tag`, `Protection`, `CommitCharge`, `PrivateMemory`, Hexdump, Disassembly | `injected_code_regions` (1 scalar) | Virtual memory protection flags (`PAGE_EXECUTE_READWRITE`), commit charges, raw shellcode bytes, assembly instructions |
| `privileges.txt` | 4,500 – 5,400 | `PID`, `Process`, `Value`, `Privilege`, `Attributes`, `Description` | `elevated_privilege_count` (1 scalar) | Explicit privilege tokens (`SeDebugPrivilege`, `SeTcbPrivilege`, `SeLoadDriverPrivilege`), enabled states |
| `ldrmodules.txt` | 6,400 – 7,700 | `Pid`, `Process`, `Base`, `InLoad`, `InInit`, `InMem`, `MappedPath` | `unlinked_dll_count` (1 scalar) | PEB loader list inconsistencies (`InLoad=False`, `InInit=False`, `InMem=True` reflective injection) |
| `vadinfo.txt` | 16,000 – 19,500 | `PID`, `Process`, `Offset`, `Start VPN`, `End VPN`, `Tag`, `Protection`, `CommitCharge`, `PrivateMemory`, `Parent`, `File` | `vad_protection_anomaly_count` (1 scalar) | Complete virtual address space maps, VAD tree tags (`VadS`, `Vad`), private executable memory ranges |

---

### 5.2 Source Evidence Telemetry Analysis

#### 1. `network_connections.csv`
- **Fields present:** `LocalAddress`, `LocalPort`, `RemoteAddress`, `RemotePort`, `State`, `OwningProcess`
- **Observations:** Contains active listening sockets (e.g., ports 135, 445, 5040, high RPC ports 49664–49669) and established connections.
- **Leakage Safeguard:** Benign and malware samples exhibit slight variations in listening ports due to different background OS service lifetimes. **Raw listening ports must NOT be used as naive identity features.** Only true outbound connections or owning process relationships represent behavioral signal.

#### 2. `process_snapshot.csv`
- **Fields present:** `Id`, `ProcessName`, `Path`, `StartTime`, `CPU`, `WorkingSet64`
- **Observations:** Live snapshot of CPU utilization and working set memory size for all running processes at dump time.

#### 3. `sysmon.evtx`
- **Total events:** 4,500 – 11,600 events per run.
- **Key Event IDs verified:**
  - **EID 1 (Process Create):** 1,800 – 2,500 events per run. Fields: `CommandLine`, `Image`, `ParentCommandLine`, `ParentImage`, `User`, `IntegrityLevel`, `Hashes` (MD5/SHA256).
  - **EID 3 (Network Connect):** 100 – 350 events per run. Fields: `DestinationIp`, `DestinationPort`, `Image`, `Protocol`, `SourceIp`, `SourcePort`, `User`.
  - **EID 5 (Process Terminate):** 1,500 – 2,500 events per run.
- **Attribution Context:** EID 1 captures both ambient background OS service launches (`Sysmon64.exe`, `taskhostw.exe`, `unsecapp.exe`) and actual attack commands (`powershell.exe -enc ...`, `cmd.exe /c ...`).

#### 4. `powershell.evtx`
- **Total events:** 350 – 600 events per run.
- **Key Event IDs verified:**
  - **EID 4104 (ScriptBlock Logging):** 300 – 500 events per run. Fields: `ScriptBlockText`, `ScriptBlockId`, `Path`, `MessageNumber`, `MessageTotal`.
- **Attribution Context:** Captures PowerShell script blocks executed by the system and payloads. Legitimate Windows system management scripts generate benign 4104 events. Attribution requires contextual analysis rather than treating all 4104 events as malicious.

---

## 6. Telemetry Gaps & Integrity Boundaries

1. **PCAP Telemetry is Absent:**  
   No `.pcap` or `.pcapng` files exist in any run directory. All network evidence is derived from live netstat captures (`network_connections.csv`) and Sysmon Event ID 3 (`sysmon.evtx`). Features requiring packet timing, inter-packet intervals, TCP window sizes, or byte counts must be set to `NULL` (unknown), not `0`.

2. **Raw Memory Images (`.raw`/`.dmp`) Excluded:**  
   In compliance with repository hygiene and `AGENTS.md` §6 rules, multi-gigabyte raw memory images are stored externally in the sandbox hypervisor environment. The Volatility 3 output files represent the authoritative extracted memory forensic state.

3. **Benign RWX Regions (`malfind.txt`):**  
   Inspection confirms that Windows Defender (`MsMpEng.exe`) allocates 13 to 15 `PAGE_EXECUTE_READWRITE` memory regions in benign baseline runs. The presence of RWX memory in `MsMpEng.exe` is expected OS behavior and must not be used to flag benign systems as infected.

---

## 7. Next Actions (Phase 2 & Beyond)

1. **Preserve Raw Evidence:** `Dataset/` remains untouched and immutable.
2. **Schema Definition:** Establish Pydantic schemas in `data/forensic/schemas/` for entity-level, event-level, and relationship structures.
3. **Rich Forensic Construction:** Build structured representations preserving full process trees, thread start addresses, handle types, VAD ranges, and command lines.
4. **Leakage & Semantic Verification:** Audit all derived features for batch/track artifacts before any ML feature selection.

*Status: Ready for review and approval to proceed with Phase 2.*
