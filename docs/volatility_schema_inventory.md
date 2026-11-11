# Volatility 3 Forensic Schema & Plugin Inventory

**Date:** 2026-09-22  
**Investigation Scope:** Deep inspection of all 11 Volatility 3 output files across 45 runs, including representative runs from Benign and all 11 malware families.  
**Framework Version:** Volatility 3 Framework v2.28.0 (Windows symbols: Windows 11 22H2 x64).  
**Status:** COMPLETE — 495 TEXT DUMPS PHYSICAL VERIFICATION.

---

## 1. Overview of Volatility Plugins Available in Dataset

Every single one of the 45 runs in `Dataset/` contains exactly 11 Volatility 3 text dumps in `volatility/RUN-xxx/`. The table below lists the physical outputs, row count ranges, and structural levels:

| Plugin Name | Output File | Row Count Range | Forensic Granularity | Primary Forensic Question Answered |
|---|---|---|---|---|
| `windows.pslist.PsList` | `pslist.txt` | 131 to 158 rows | Process-level | Which processes are actively linked in the active process list (`ActiveProcessLinks`)? |
| `windows.psscan.PsScan` | `psscan.txt` | 137 to 164 rows | Process-level | Which processes exist in physical memory, including unlinked / DKOM-hidden processes? |
| `windows.pstree.PsTree` | `pstree.txt` | 131 to 158 rows | Relationship-level | What is the parent-child lineage, command line, and executable path of each process? |
| `windows.threads.Threads`| `threads.txt` | 1,440 to 1,920 rows | Thread-level | Which threads are executing outside known image base addresses or unbacked memory? |
| `windows.handles.Handles`| `handles.txt` | 47,500 to 57,200 rows | Handle-level | Which processes hold open handles to Mutant, Key, Process, Thread, and Section objects? |
| `windows.dlllist.DllList`| `dlllist.txt` | 6,100 to 7,250 rows | Module-level | Which DLLs are loaded into each process and from what physical disk paths? |
| `windows.psxview.PsXView`| `psxview.txt` | 125 to 145 rows | Cross-view / Process | Do cross-table discrepancies exist between `pslist`, `psscan`, `thrdscan`, and `csrss`? |
| `windows.privileges.Privs`| `privileges.txt` | 4,500 to 5,350 rows | Token-level | Which processes hold elevated security privileges (`SeDebugPrivilege`, `SeTcbPrivilege`)? |
| `windows.malfind.Malfind`| `malfind.txt` | 17 to 24 blocks (730-885 lines) | Region-level | Which VAD memory regions have `PAGE_EXECUTE_READWRITE` and unmapped code execution? |
| `windows.vadinfo.VadInfo`| `vadinfo.txt` | 16,300 to 19,200 rows | Memory / VAD | What is the full Virtual Address Descriptor tree structure, protection, and commit charge? |
| `windows.ldrmodules.LdrModules`| `ldrmodules.txt`| 6,450 to 7,650 rows | Module / Header | Are DLLs unlinked from `InLoadOrder`, `InMemoryOrder`, or `InInitializationOrder` lists? |

---

## 2. Plugin-by-Plugin Schema Breakdown

### 2.1 `pslist.txt` (Active Process List)
- **Columns:** `PID`, `PPID`, `ImageFileName`, `Offset(V)`, `Threads`, `Handles`, `SessionId`, `Wow64`, `CreateTime`, `ExitTime`, `File output`
- **Granularity:** Process-level.
- **Important Fields:**
  - `ImageFileName`: Process executable name (max 15 chars).
  - `Threads` & `Handles`: Immediate thread/handle count per process.
  - `ExitTime`: Distinguishes short-lived dropped helper processes from persistent processes.
- **Detection Utility:** HIGH (Total process count, thread/process ratios).
- **Family Classification Utility:** MODERATE (Identifies family-specific executable names e.g. `powershell.exe`, `cmd.exe`, `rundll32.exe`).
- **Known Limitations:** Cannot see processes unlinked via Direct Kernel Object Manipulation (DKOM).

### 2.2 `psscan.txt` (Pool-Tag Process Scan)
- **Columns:** `PID`, `PPID`, `ImageFileName`, `Offset(V)`, `Threads`, `Handles`, `SessionId`, `Wow64`, `CreateTime`, `ExitTime`, `File output`
- **Granularity:** Process-level.
- **Important Fields:**
  - `PID` vs `pslist.PID`: Discrepancy reveals hidden/unlinked processes.
- **Detection Utility:** HIGH (Hidden process count = `len(set(psscan_pids) - set(pslist_pids))`).
- **Family Classification Utility:** HIGH (Certain stealth frameworks e.g., rootkits/RATs intentionally unlink their process).
- **Representative Findings:**
  - In Benign `RUN-1100`: `psscan` has 147 processes vs `pslist` 144 (3 terminated system helper processes).
  - In Process Hollowing `RUN-100`: 6 unlinked processes detected.

### 2.3 `pstree.txt` (Process Hierarchy Tree)
- **Columns:** `PID`, `PPID`, `ImageFileName`, `Offset(V)`, `Threads`, `Handles`, `SessionId`, `Wow64`, `CreateTime`, `ExitTime`, `Audit`, `Cmd`, `Path`
- **Granularity:** Relationship-level.
- **Important Fields:**
  - `Cmd`: Command line string executed to spawn the process.
  - `Path`: Full binary path on disk.
  - `PID` / `PPID` structure: Tree indentation showing parentage.
- **Detection Utility:** HIGH (Identifies anomalous parentage e.g., `winword.exe` -> `powershell.exe` or `wmiprvse.exe` -> `cmd.exe`).
- **Family Classification Utility:** VERY HIGH (WMI malware spawns under `WmiPrvSE.exe`; LOLBins abuse spawns under `certutil.exe`/`mshta.exe`).

### 2.4 `threads.txt` (Kernel Thread Enumeration)
- **Columns:** `Offset`, `PID`, `TID`, `StartAddress`, `StartPath`, `Win32StartAddress`, `Win32StartPath`, `CreateTime`, `ExitTime`
- **Granularity:** Thread-level.
- **Important Fields:**
  - `Win32StartPath`: File backing the thread start routine. If `N/A` or points outside loaded modules, thread is executing injected shellcode in unbacked memory!
- **Detection Utility:** VERY HIGH (Thread start in unbacked private memory is a hallmark of reflective DLL injection and Cobalt Strike beacons).
- **Family Classification Utility:** HIGH (Thread creation patterns in remote processes characterize Process Hollowing and Metasploit payloads).

### 2.5 `handles.txt` (Process Handle Table)
- **Columns:** `PID`, `Process`, `Offset`, `HandleValue`, `Type`, `GrantedAccess`, `Name`
- **Granularity:** Handle-level (50,000+ rows per run).
- **Important Fields:**
  - `Type`: Object type (`Process`, `Thread`, `Mutant`, `Key`, `Section`, `File`).
  - `GrantedAccess`: Permissions e.g. `0x1fffff` (`PROCESS_ALL_ACCESS`) indicates injection capability.
  - `Name`: Target object name (e.g. named pipes `\Device\NamedPipe\msagent_*` created by Cobalt Strike).
- **Detection Utility:** HIGH (when filtered).
- **Known Limitations:** **Must filter out Windows Defender (`MsMpEng.exe`)**, which holds over 12,000 handles to scan files across the entire OS.

### 2.6 `dlllist.txt` (Loaded Dynamic Link Libraries)
- **Columns:** `PID`, `Process`, `Base`, `Size`, `Name`, `Path`, `LoadCount`, `LoadTime`, `File output`
- **Granularity:** Module-level.
- **Important Fields:**
  - `Path`: Detects DLLs loaded from `\Temp\`, `\Users\Public\`, or missing paths.
  - `Base`: Virtual memory address of the loaded module.
- **Detection Utility:** HIGH (Detects proxy DLLs, unbacked modules).
- **Family Classification Utility:** MODERATE.

### 2.7 `psxview.txt` (Cross-View Process Verification)
- **Columns:** `Offset(Virtual)`, `Name`, `PID`, `pslist`, `psscan`, `thrdscan`, `csrss`, `Exit Time`
- **Granularity:** Process-level.
- **Important Fields:**
  - Boolean flags across multiple scanning sources (`True`/`False`).
- **Detection Utility:** HIGH (Identifies stealth/DKOM processes where `pslist = False` but `psscan = True` or `thrdscan = True`).
- **Family Classification Utility:** MODERATE.

### 2.8 `privileges.txt` (Process Security Token Privileges)
- **Columns:** `PID`, `Process`, `Value`, `Privilege`, `Attributes`, `Description`
- **Granularity:** Token-level.
- **Important Fields:**
  - `Privilege`: `SeDebugPrivilege`, `SeTcbPrivilege`, `SeImpersonatePrivilege`.
  - `Attributes`: `Present`, `Enabled`, `Enabled|Default`.
- **Detection Utility:** MODERATE (Elevated privileges enabled in user processes like `powershell.exe` indicate privilege escalation; system daemons always possess them).
- **Known Limitations:** Background Windows services naturally possess elevated tokens. Must evaluate privileges conditioned on non-system PIDs.

### 2.9 `malfind.txt` (Injected Memory Finder)
- **Columns:** `PID`, `Process`, `Start VPN`, `End VPN`, `Tag`, `Protection`, `CommitCharge`, `PrivateMemory`, `File output`, `Notes`, `Hexdump`, `Disasm`
- **Granularity:** Memory Region-level (17 to 24 distinct regions per run).
- **Important Fields:**
  - `Protection`: Almost universally `PAGE_EXECUTE_READWRITE`.
  - `Tag`: `VadS` (short VAD, private allocation) vs `Vad` (mapped).
  - `Hexdump` / `Disasm`: Initial instructions in the region.
- **Detection Utility:** VERY HIGH (Primary indicator of unmapped shellcode).
- **Critical Ground Truth Finding:**
  - In Benign `RUN-1100`: **14 of 18 regions belong to `MsMpEng.exe`**, 3 belong to `powershell.exe` (.NET CLR JIT), and 1 belongs to `OneDrive.exe` (JIT).
  - In Malware runs: `MsMpEng.exe` continues to have 13-15 regions. Malware adds 3-7 additional unmapped executable regions in the victim or host process (e.g. `powershell.exe`, `rundll32.exe`, `svchost.exe`).
  - **Extractor Requirement:** Must evaluate `malfind` by process type, filtering out Defender's signature emulator.

### 2.10 `vadinfo.txt` (Virtual Address Descriptor Tree)
- **Columns:** `PID`, `Process`, `Offset`, `Start VPN`, `End VPN`, `Tag`, `Protection`, `CommitCharge`, `PrivateMemory`, `Parent`, `File`, `File output`
- **Granularity:** Memory-level (16,000 to 19,000 regions per run).
- **Important Fields:**
  - `Protection`: `PAGE_EXECUTE_READWRITE` vs `PAGE_EXECUTE_READ` vs `PAGE_READWRITE`.
  - `File`: Path to file backing the region. If `File` is `N/A` or empty and protection is executable, the region is **unbacked memory** (allocated via `VirtualAlloc`/`NtAllocateVirtualMemory`).
- **Detection Utility:** VERY HIGH (Unmapped executable page count = key feature for memory model).
- **Family Classification Utility:** HIGH (Memory footprint size and region fragmentation differ across Metasploit, Empire, and Cobalt Strike).

### 2.11 `ldrmodules.txt` (PEB Loader Module Inconsistencies)
- **Columns:** `Pid`, `Process`, `Base`, `InLoad`, `InInit`, `InMem`, `MappedPath`
- **Granularity:** Module-level (6,400 to 7,600 rows per run).
- **Important Fields:**
  - `InLoad`, `InInit`, `InMem`: Boolean flags indicating presence in the PEB doubly-linked module lists.
  - If a DLL is loaded in memory but `InLoad = False` or `InInit = False`, it was **manually mapped or unlinked** to evade standard detection!
- **Detection Utility:** VERY HIGH (Direct detection of Reflective DLL Injection and memory modules).
- **Family Classification Utility:** VERY HIGH (Specific to `reflective_dll_injection` and `process_hollowing`).

---

## 3. Comparison Across Representative Families

| Batch / Family | Run ID | Active Procs (`pslist`) | Hidden Procs (`psscan` delta) | Total Handles | Malfind Regions (Total) | Malfind Non-Defender Regions | Key Distinguishing Volatility Artifact |
|---|---|---|---|---|---|---|---|
| **Benign Baseline** | `RUN-1100` | 144 | +3 | 50,720 | 18 | **4** (3 powershell JIT, 1 OneDrive) | Standard system hierarchy, zero unmapped thread starts, 0 unlinked DLLs |
| **PowerShell Fileless** | `RUN-001` | 153 | +2 | 57,165 | 17 | **3** (powershell JIT/script) | High thread count in powershell.exe, elevated tokens in user session |
| **Process Hollowing** | `RUN-100` | 131 | +6 | 47,540 | 22 | **7** (hollowed svchost/powershell) | PE header mismatch in `ldrmodules`, unbacked start address in `threads.txt` |
| **Memory-only RAT** | `RUN-200` | 137 | +1 | 48,920 | 19 | **4** (injected beacon memory) | Persistent unbacked RWX region in user process with active socket handle |
| **Registry Resident** | `RUN-300` | 140 | +2 | 49,610 | 18 | **3** (script payload in RAM) | Spawns via `regsvr32.exe` / `mshta.exe` seen in `pstree.txt` |
| **Cobalt Strike Beacon** | `RUN-400` | 134 | +5 | 50,605 | 20 | **5** (beacon payload heap) | Named pipe handles (`\Device\NamedPipe\*`), thread start in unbacked VAD |
| **Metasploit Memory** | `RUN-500` | 138 | +3 | 51,200 | 19 | **4** (meterpreter stage) | Meterpreter reflective loader in `vadinfo`, MZ header in private memory |
| **WMI Malware** | `RUN-600` | 142 | +2 | 52,140 | 17 | **3** (WMI provider memory) | Anomalous child processes under `WmiPrvSE.exe` in `pstree.txt` |
| **Reflective DLL** | `RUN-700` | 139 | +4 | 51,800 | 21 | **6** (unlinked DLL memory) | `ldrmodules.txt` flags: `InLoad = False, InInit = False, InMem = True` |
| **LOLBins Abuse** | `RUN-800` | 142 | +0 | 52,863 | 20 | **7** (certutil/bitsadmin RAM) | LOLBin binaries executing with unusual command line arguments in `pstree.txt` |
| **Fileless Ransomware** | `RUN-900` | 145 | +3 | 53,400 | 21 | **6** (crypto key generator) | Anomalous handle churn on filesystem objects, rapid thread spawning |
| **Empire Framework** | `RUN-1000`| 141 | +4 | 52,950 | 19 | **5** (agent stager heap) | Base64 launcher script in memory, unmapped RWX region in `powershell.exe` |
