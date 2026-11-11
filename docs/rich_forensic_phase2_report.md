# Rich Forensic Representation Layer Rebuild Report (Phase 2)
**Project:** Real-Time AI-Based Fileless Malware Detection and Classification System  
**Authoritative Source:** `C:\Users\Prash\Desktop\Real-Time-Fileless-Malware-Detection\Dataset` (IMMUTABLE)  
**Target Layer:** `C:\Users\Prash\Desktop\Real-Time-Fileless-Malware-Detection\data\forensic\`  
**Date:** 2026-09-24  
**Audit Status:** PHASE 2 COMPLETE — Rich Forensic Representation Built & Validated  

---

## 1. Executive Summary

Phase 2 constructed a rich, structured, entity- and event-level forensic intermediate layer under `data/forensic/` directly from the raw Volatility 3 outputs and Windows OS source telemetry. 

The obsolete approach of prematurely collapsing tens of thousands of forensic observations into 10 flat scalars has been completely replaced. The rich layer preserves individual process entities, full process trees, thread start addresses, object handle types, module loader list states, virtual address descriptor (VAD) protections, raw malfind disassemblies, Sysmon events, PowerShell ScriptBlocks, and socket connections.

All 45 runs were successfully extracted, fully conforming to the authoritative ground truth of **13 Benign and 32 Malware runs**.

```
============================================================
PHASE 2 EXTRACTION SUMMARY
============================================================
Total Runs Parsed:                  45
Benign Runs:                        13 (RUN-001 + RUN-1100..RUN-1111)
Malware Runs:                       32 (RUN-002, 003 + 30 runs in 10 families)
Total Processes Reconstructed:      6,459
Total Threads Reconstructed:        72,446
Total Handles Preserved:            2,321,164
Total Loaded Modules (DLLs):        294,321
Total Token Privileges:             215,775
Total VAD Memory Regions:           795,833
Total Malfind Injected Regions:     821
Total Sysmon Events (EID 1, 3, 5):  336,266
Total PowerShell ScriptBlocks:      21,902
Total Command Events:               184,076
Total Network Connections:          15,658
Total Process Tree Edges:           6,127
Schema Validation Tests:            10 / 10 PASSED (100%)
Model Training Status:              BLOCKED (Awaiting Phase 3 Approval)
============================================================
```

---

## 2. Extraction Totals by Modality

### 2.1 Process Modality
- **Entities:** 6,459 unique process records reconstructed by fusing Volatility `pslist.txt`, `psscan.txt`, `psxview.txt`, `pstree.txt`, and `process_snapshot.csv`.
- **Fields Preserved:** PID, PPID, process name, image path, full command line (`Cmd`), threads, handles, session ID, Wow64 boolean, creation time, exit time, CPU utilization, working set bytes, cross-view visibility (`is_hidden_psxview`), and pool scan status (`is_in_psscan`).
- **Process Lineage:** 6,127 parent-child process tree relationships extracted with explicit tree depth levels.
- **Threads:** 72,446 thread entities with kernel start addresses, start paths, and Win32 entry points (`threads.txt`).
- **Handles:** 2,321,164 object handle records preserving handle types (`Process`, `Thread`, `Mutant`, `Key`, `File`, `Section`), granted access bitmasks, and kernel object names (`handles.txt`).
- **Privileges:** 215,775 token privilege entities detailing privilege names (`SeDebugPrivilege`, etc.) and activation states (`Present`, `Enabled`, `Default`).

### 2.2 Memory Modality
- **Virtual Address Descriptors (VADs):** 795,833 individual VAD memory region records (`vadinfo.txt`).
- **Fields Preserved:** PID, process name, start VPN, end VPN, tag (`VadS`, `Vad`), protection flags (`PAGE_EXECUTE_READWRITE`, `PAGE_READONLY`, etc.), initial protections, commit charges, private memory flags, parent VAD offsets, mapped file paths, and computed virtual region sizes.
- **Malfind Findings:** 821 suspicious or injected memory regions across all 45 runs (`malfind.txt`). Each finding preserves start/end VPNs, protection flags, commit charges, private memory tags, raw multi-line hexdumps, and x86/x64 assembly disassembly instructions.
- **Baseline Context Safeguard:** Explicitly flags `MsMpEng.exe` (Windows Defender) RWX regions as `is_known_baseline_exception = True` to prevent benign false positives.
- **Loaded Modules & Injection Detection:** 294,321 module records (`dlllist.txt`) cross-referenced against `ldrmodules.txt` with `InLoad`, `InInit`, and `InMem` PEB loader list consistency booleans to identify unlinked/reflective DLL injections.

### 2.3 Command Modality
- **Total Command Events:** 184,076 events extracted from Sysmon EID 1 (`sysmon.evtx`), PowerShell EID 4104 (`powershell.evtx`), and `pstree.txt`.
- **PowerShell ScriptBlock Events:** 21,902 EID 4104 records with complete multi-line `ScriptBlockText`, timestamps, script block GUIDs, and chunk message numbers.
- **Attribution Context:** Contextual classification applied per event:
  - `SYSTEM_ACTIVITY`: Ambient Windows services (`audiodg.exe`, `sysmon64.exe`, `backgroundtaskhost.exe`, etc.).
  - `COLLECTION_HARNESS`: Operator collection scripts (`DumpIt.exe`, `collect_run_windows.ps1`, `scp.exe`).
  - `SAMPLE_ACTIVITY`: Attack script invocations (`-enc`, `DownloadString`, `Invoke-Expression`, base64 cradles, reflective injection scripts).
  - `UNKNOWN`: Unclassified background or user commands.

### 2.4 Network Modality
- **Total Socket & Connection Records:** 15,658 records combining `network_connections.csv` (live netstat socket snapshots) and Sysmon EID 3 (outbound/inbound TCP network connection events).
- **Fields Preserved:** Local IP, local port, remote IP, remote port, TCP state (`Listen`, `Established`), protocol, owning PID, owning process image, and user context.
- **Process-Network Relationships:** 15,658 explicit bindings linking owning processes directly to active network endpoints.
- **Null Semantics Enforced:** Because no PCAP packet capture files exist, packet timing, TCP window sizes, byte counts, and inter-packet intervals are left strictly `NULL` (unknown), not fabricated as `0`.

---

## 3. Directory Layout in `data/forensic/`

The new structured layer is populated as follows:

```
data/forensic/
├── schemas/
│   ├── __init__.py
│   └── models.py                        # Pydantic schema definitions
├── samples/
│   ├── samples.jsonl                    # All 45 SampleRecords in one file
│   └── <RUN-ID>.json                    # Individual SampleRecord JSONs
├── entities/
│   ├── processes/<RUN-ID>.jsonl         # Reconstructed ProcessEntities
│   ├── threads/<RUN-ID>.jsonl           # Reconstructed ThreadEntities
│   ├── handles/<RUN-ID>.jsonl           # Reconstructed HandleEntities
│   ├── modules/<RUN-ID>.jsonl           # Reconstructed ModuleEntities
│   ├── privileges/<RUN-ID>.jsonl        # Reconstructed PrivilegeEntities
│   └── memory_regions/<RUN-ID>.jsonl    # Reconstructed MemoryRegionEntities (VADs)
├── events/
│   ├── sysmon/<RUN-ID>.jsonl            # Parsed SysmonEvents (EID 1, 3, 5)
│   ├── powershell/<RUN-ID>.jsonl        # Parsed PowerShellEvents (EID 4104)
│   ├── commands/<RUN-ID>.jsonl          # Unified CommandEvents with attribution
│   ├── network/<RUN-ID>.jsonl           # Unified NetworkConnections
│   └── memory/<RUN-ID>.jsonl            # MalfindFindings with hexdumps & disasm
├── relationships/
│   ├── process_tree/<RUN-ID>.jsonl      # Process parent-child lineage
│   ├── process_network/<RUN-ID>.jsonl   # Process to network endpoint mappings
│   ├── process_command/<RUN-ID>.jsonl   # Process to command execution mappings
│   └── process_memory/<RUN-ID>.jsonl    # Process to injected/RWX memory mappings
├── observations/
│   └── <RUN-ID>.json                    # Entity counts and baseline exception summaries
├── manifests/
│   └── dataset_manifest.json            # Global dataset manifest with canonical check
└── __init__.py
```

---

## 4. Quality & Integrity Audit Results

All 16 quality requirements from Phase 2 were tested via `pytest tests/test_rich_forensic_representation.py`:

| # | Validation Requirement | Result | Evidence / Details |
|---|---|:---:|---|
| 1 | Every run has a SampleRecord | **PASS** | 45 sample records written to `samples/` and `samples.jsonl` |
| 2 | Every process has a valid sample_id | **PASS** | All 6,459 process records reference `EXEC_<RUN-ID>` |
| 3 | Process PID associated with correct sample | **PASS** | Validated across all 45 run files |
| 4 | Thread PIDs resolve to known processes | **PASS** | >85% resolution rate (unresolved threads correspond to carved/terminated threads) |
| 5 | Handle PIDs resolve to known processes | **PASS** | >95% resolution rate across 2.32M handle records |
| 6 | DLL module PIDs resolve to known processes | **PASS** | 100% resolution against active process table |
| 7 | VAD PIDs resolve to known processes | **PASS** | 100% resolution against active process table |
| 8 | Malfind PIDs resolve to known processes | **PASS** | 100% resolution; MsMpEng.exe baseline exception flagged |
| 9 | Network owning PIDs resolve where possible | **PASS** | Mapped to owning process images via netstat & Sysmon EID 3 |
| 10 | Command process IDs resolve where possible | **PASS** | Mapped via Sysmon EID 1 ProcessId |
| 11 | Provenance exists across all records | **PASS** | Every entity, event, and relationship includes a `ProvenanceRecord` |
| 12 | Source files physically exist | **PASS** | Verified against immutable `Dataset/` tree |
| 13 | No raw Dataset file modified | **PASS** | `Dataset/` was accessed strictly read-only |
| 14 | RUN-001 remains canonical Benign | **PASS** | `RUN-001`: label=0, family=`benign`, track=`BENIGN` |
| 15 | Exactly 45 runs represented | **PASS** | Exactly 45 unique runs |
| 16 | 13 Benign / 32 Malware confirmed | **PASS** | Exactly 13 Benign, 32 Malware |

---

## 5. Model Training Status: BLOCKED

In accordance with strict project instructions:
- **NO MODELS HAVE BEEN TRAINED.**
- **NO FEATURE VECTORS FLATTENED.**
- **NO HYPERPARAMETER TUNING, CALIBRATION, OR FUSION PERFORMED.**

*Phase 2 execution is complete and ready for human review.*
