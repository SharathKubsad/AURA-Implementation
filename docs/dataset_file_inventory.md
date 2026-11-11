# Complete Dataset File Inventory

**Date:** 2026-09-22  
**Root Path Inspected:** `Dataset/`  
**Purpose:** Exhaustive physical enumeration of all files, batches, runs, evidence categories, and extensions prior to any schema mapping or model training.  
**Investigation Status:** COMPLETE — NO FILES MODIFIED, DELETED, OR MOVED.

---

## 1. High-Level Inventory Summary

| Metric | Measured Value | Verification Method |
|---|---|---|
| **Total Directory Count** | 69 directories | Recursive directory enumeration (`Path('Dataset').glob('**/*')`) |
| **Total File Count** | **846 files** | Strict physical file count across all subdirectories |
| **Total Archive/Batch Folders** | **12 batch directories** | 1 Benign batch + 11 Malware family batches |
| **Total Execution Runs** | **45 distinct runs** | Exactly 12 Benign runs (`RUN-1100` to `RUN-1111`) + 33 Malware runs (`RUN-001` to `RUN-1002`) |
| **Files Per Execution Run** | **18 files per run** | 16 Volatility/source files + 2 interim JSONs (see breakdown below) |
| **Total Storage Size** | ~985 MB | Dominated by EVTX event logs and Volatility handles/vadinfo text dumps |

---

## 2. Inventory by File Extension

| Extension | Count | Percentage | Primary Content / Purpose |
|---|---|---|---|
| `.txt` | 495 | 58.5% | Volatility 3 command outputs (11 text files per run across 45 runs = 495 files) |
| `.json` | 147 | 17.4% | Batch manifests (12), run metadata (45), process interim (45), memory interim (45) |
| `.csv` | 102 | 12.1% | `process_snapshot.csv` (45), `network_connections.csv` (45), `batch_summary.csv` (12) |
| `.evtx` | 90 | 10.6% | `sysmon.evtx` (45), `powershell.evtx` (45) |
| `.md` | 12 | 1.4% | `README.md` documentation files (1 per batch directory) |
| **Total** | **846** | **100.0%** | |

---

## 3. Inventory by Evidence Category & Classification

| Category | File Pattern / Name | Files per Run | Total Files | Classification | Source / Generator |
|---|---|---|---|---|---|
| **System Event Logs** | `sysmon.evtx` | 1 | 45 | RAW_SOURCE_EVIDENCE | Windows Sysmon Service v15.11 |
| **PowerShell Event Logs** | `powershell.evtx` | 1 | 45 | RAW_SOURCE_EVIDENCE | Windows PowerShell Operational Log (EID 4104/800) |
| **Process Snapshot** | `process_snapshot.csv` | 1 | 45 | RAW_SOURCE_EVIDENCE | Live PowerShell `Get-Process` capture at termination |
| **Socket Snapshot** | `network_connections.csv` | 1 | 45 | RAW_SOURCE_EVIDENCE | Live PowerShell `Get-NetTCPConnection` socket state |
| **Process Memory Forensics** | `volatility/RUN-xxx/pslist.txt` | 1 | 45 | DERIVED_FORENSIC_OUTPUT | Volatility 3 `windows.pslist.PsList` |
| **Hidden Process Forensics** | `volatility/RUN-xxx/psscan.txt` | 1 | 45 | DERIVED_FORENSIC_OUTPUT | Volatility 3 `windows.psscan.PsScan` |
| **Process Tree Forensics** | `volatility/RUN-xxx/pstree.txt` | 1 | 45 | DERIVED_FORENSIC_OUTPUT | Volatility 3 `windows.pstree.PsTree` |
| **Thread Forensics** | `volatility/RUN-xxx/threads.txt` | 1 | 45 | DERIVED_FORENSIC_OUTPUT | Volatility 3 `windows.threads.Threads` |
| **Handle Forensics** | `volatility/RUN-xxx/handles.txt` | 1 | 45 | DERIVED_FORENSIC_OUTPUT | Volatility 3 `windows.handles.Handles` |
| **DLL Module Forensics** | `volatility/RUN-xxx/dlllist.txt` | 1 | 45 | DERIVED_FORENSIC_OUTPUT | Volatility 3 `windows.dlllist.DllList` |
| **Cross-View Process Scan** | `volatility/RUN-xxx/psxview.txt` | 1 | 45 | DERIVED_FORENSIC_OUTPUT | Volatility 3 `windows.psxview.PsXView` |
| **Privilege Forensics** | `volatility/RUN-xxx/privileges.txt` | 1 | 45 | DERIVED_FORENSIC_OUTPUT | Volatility 3 `windows.privileges.Privs` |
| **Code Injection Forensics** | `volatility/RUN-xxx/malfind.txt` | 1 | 45 | DERIVED_FORENSIC_OUTPUT | Volatility 3 `windows.malfind.Malfind` |
| **Memory Region Forensics** | `volatility/RUN-xxx/vadinfo.txt` | 1 | 45 | DERIVED_FORENSIC_OUTPUT | Volatility 3 `windows.vadinfo.VadInfo` |
| **PE Header Inconsistencies** | `volatility/RUN-xxx/ldrmodules.txt`| 1 | 45 | DERIVED_FORENSIC_OUTPUT | Volatility 3 `windows.ldrmodules.LdrModules` |
| **Run Metadata** | `metadata/RUN-xxx.json` | 1 | 45 | METADATA | Controlled sandbox test harness runner |
| **Derived Process Features** | `process/RUN-xxx.json` | 1 | 45 | EXTRACTED_FEATURES | Pre-extracted interim JSON features |
| **Derived Memory Features** | `memory/RUN-xxx.json` | 1 | 45 | EXTRACTED_FEATURES | Pre-extracted interim JSON features |
| **Batch Manifest** | `manifest.json` | N/A (1/batch) | 12 | METADATA | Sandbox batch configuration / family record |
| **Batch CSV Summary** | `batch_summary.csv` | N/A (1/batch) | 12 | METADATA | Execution and extraction status summary |
| **Batch README** | `README.md` | N/A (1/batch) | 12 | METADATA | Operator documentation per family |
| **Total** | | | **846** | | |

---

## 4. Batch and Run Enumeration

The dataset is partitioned into exactly 12 directories matching the 12 execution campaigns:

| Batch Directory Name | Label | Malware Family Name | Run IDs Contained | Total Files | Batch Manifest Status |
|---|---|---|---|---|---|
| `custom_benign_batch/` | 0 (Benign) | `benign` | `RUN-1100` to `RUN-1111` (12 runs) | 219 files | Present & Valid |
| `custom_powershell_fileless/` | 1 (Malware) | `powershell_fileless` | `RUN-001`, `RUN-002`, `RUN-003` (3 runs) | 57 files | Present & Valid |
| `custom_process_hollowing/` | 1 (Malware) | `process_hollowing` | `RUN-100`, `RUN-101`, `RUN-102` (3 runs) | 57 files | Present & Valid |
| `custom_memory_only_rat/` | 1 (Malware) | `memory_only_rat` | `RUN-200`, `RUN-201`, `RUN-202` (3 runs) | 57 files | Present & Valid |
| `custom_registry_resident_malware/` | 1 (Malware) | `registry_resident_malware` | `RUN-300`, `RUN-301`, `RUN-302` (3 runs) | 57 files | Present & Valid |
| `custom_cobalt_strike_beacon/` | 1 (Malware) | `cobalt_strike_beacon` | `RUN-400`, `RUN-401`, `RUN-402` (3 runs) | 57 files | Present & Valid |
| `custom_metasploit_memory_payloads/`| 1 (Malware) | `metasploit_memory_payloads`| `RUN-500`, `RUN-501`, `RUN-502` (3 runs) | 57 files | Present & Valid |
| `custom_wmi_malware/` | 1 (Malware) | `wmi_malware` | `RUN-600`, `RUN-601`, `RUN-602` (3 runs) | 57 files | Present & Valid |
| `custom_reflective_dll_injection/` | 1 (Malware) | `reflective_dll_injection` | `RUN-700`, `RUN-701`, `RUN-702` (3 runs) | 57 files | Present & Valid |
| `custom_lolbins_abuse/` | 1 (Malware) | `lolbins_abuse` | `RUN-800`, `RUN-801`, `RUN-802` (3 runs) | 57 files | Present & Valid |
| `custom_fileless_ransomware/` | 1 (Malware) | `fileless_ransomware` | `RUN-900`, `RUN-901`, `RUN-902` (3 runs) | 57 files | Present & Valid |
| `custom_empire_framework/` | 1 (Malware) | `empire_framework` | `RUN-1000`, `RUN-1001`, `RUN-1002` (3 runs) | 57 files | Present & Valid |
| **Totals** | | **11 Families + Benign** | **45 Independent Runs** | **846 files** | **12 / 12 Valid** |

---

## 5. Missing Expected Files vs. Unexpected Files

### 5.1 Missing Expected Files
1. **Raw Memory Dumps (`*.raw`, `*.dmp`, `*.vmem`):**
   - Expected: 45 files (each ~6.4 GB).
   - Actually Present: **0 files**.
   - Note: The dumps were retained on the Kali forensic processing node to keep git/archive packages lightweight (<1 GB total). All Volatility 3 plugins were executed directly against these dumps, and the resulting derived forensic text tables are 100% present.
2. **Network Packet Captures (`*.pcap`, `*.pcapng`):**
   - Expected: 45 files.
   - Actually Present: **0 files**.
   - Finding: Packet capture was not enabled or preserved during the execution harness runs.
3. **Interim Command Features (`command/RUN-xxx.json`):**
   - Absent from `Dataset/` (only `process/` and `memory/` interim folders were bundled).
4. **Interim Network Features (`network/RUN-xxx.json`):**
   - Absent from `Dataset/`.

### 5.2 Unexpected / Ancillary Files Discovered
- **BOM Markers in JSON Metadata:** Several `metadata/RUN-xxx.json` files contain UTF-8 Byte Order Marks (BOM `\xef\xbb\xbf`), requiring `utf-8-sig` decoding in Python.
- **`batch_summary.csv` and `README.md`:** 12 batch-level administrative files containing execution notes and validation logs created during the sandbox collection campaign.
