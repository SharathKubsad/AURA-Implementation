# Memory Forensics Evidence & Contextual Analysis

**Date:** 2026-09-22  
**Investigation Scope:** Deep empirical analysis of Volatility 3 `malfind.txt`, `vadinfo.txt`, `ldrmodules.txt`, and `threads.txt` across all 45 runs in `Dataset/`.  
**Status:** COMPLETE — LEGITIMATE RWX / DEFENDER JIT CONTEXT FULLY CHARACTERIZED.

---

## 1. Overview of Memory Forensics Evidence

Memory evidence in this repository originates from Volatility 3 memory plugin outputs captured from 6.4 GB RAM dumps of Windows 11 VMs:
1. `malfind.txt` (45 files) — Memory regions with executable protections containing unbacked or anomalous code.
2. `vadinfo.txt` (45 files) — Virtual Address Descriptor (VAD) tree for every process in memory (16,000+ regions per run).
3. `ldrmodules.txt` (45 files) — PEB loader module list cross-referencing (6,500+ module entries per run).
4. `threads.txt` (45 files) — Kernel thread start addresses and backing binary modules (1,500+ threads per run).

---

## 2. The Legitimate Memory Problem: Defender & CLR JIT Analysis

In conventional naive memory forensics, any memory page with protection `PAGE_EXECUTE_READWRITE` (RWX) is assumed to be malicious. **This assumption fails catastrophically in modern Windows 11 environments.**

### 2.1 Empirical Findings on `MsMpEng.exe` (Windows Defender Antivirus Core)
- In **every single run** (both Benign `RUN-1100`..`RUN-1111` and Malware `RUN-001`..`RUN-1002`), `malfind.txt` detects **13 to 15 RWX regions belonging to `MsMpEng.exe`** (PID ~3188).
- **Why Defender allocates RWX pages:** Windows Defender uses an internal in-memory emulation and sandboxing engine (the MpEngine dynamic translation core). It commits dynamic RWX buffers (`VadS` tag, CommitCharge 200–300 pages) to unpack, emulate, and analyze suspicious binaries in RAM.
- **Why blindly removing Defender is wrong:** Removing Defender does not eliminate benign RWX activity, because other legitimate user applications also allocate RWX memory.
- **Why blindly calling RWX malware is wrong:** Benign runs contain 18 to 20 total RWX regions in `malfind`, while malware runs contain 17 to 22 total RWX regions. The counts completely overlap!

### 2.2 Empirical Findings on .NET Common Language Runtime (CLR) JIT
- Both benign runs (which run administrative PowerShell and OneDrive) and malware runs (which execute PowerShell payloads) host the .NET runtime (`clr.dll`).
- The .NET Just-In-Time (JIT) compiler compiles Intermediate Language (IL) bytecode into native x86-64 machine code at runtime.
- By design, the CLR allocates dynamic heap memory, writes machine code into it, and marks it executable (`PAGE_EXECUTE_READWRITE` or transitions from `PAGE_READWRITE` to `PAGE_EXECUTE_READ`).
- In `RUN-1100` (benign), `powershell.exe` contains **3 JIT regions** in `malfind` and `OneDrive.exe` contains **1 JIT region**.

---

## 3. Contextual Discrimination: Legitimate vs. Malicious Memory Activity

To separate legitimate JIT/antivirus buffers from fileless malware payloads, the feature extraction pipeline must evaluate the following four contextual dimensions:

| Contextual Dimension | Legitimate Behavior (Defender / CLR JIT) | Malicious Behavior (Reflective DLL / Shellcode / Hollowed) | Forensic Evidence Source |
|---|---|---|---|---|
| **Process Identity & Lineage** | Owned by `MsMpEng.exe` (spawned by `services.exe`) or interactive desktop apps (`OneDrive.exe`, `explorer.exe`). | Injected into headless scripting hosts (`powershell.exe -W Hidden`, `cmd.exe`, `rundll32.exe`, `svchost.exe`). | `pstree.txt`, `sysmon.evtx` Event ID 1 |
| **VAD File Backing** | Backed by signed system assemblies or tagged with specific CLR memory tags. | Completely unbacked (`File == N/A` or empty), allocated via `VirtualAllocEx` or `NtAllocateVirtualMemory`. | `vadinfo.txt` (`Tag`, `File`, `PrivateMemory`) |
| **Disassembly / Instruction Patterns** | Standard Microsoft function prologues (`push rbp`, `sub rsp`, `mov rbp, rcx`, SEH exception table registrations). | Shellcode preambles (`0xFC 0xE8` = `cld; call`, API hashing routines via `fs:[0x30]` / `gs:[0x60]`, PE headers `4D 5A` `MZ` inside private heap). | `malfind.txt` (`Hexdump`, `Disasm`) |
| **Thread Start Address Alignment** | Thread start addresses point to loaded DLL functions (`kernel32!BaseThreadInitThunk`, `clr!ThreadpoolMgr`). | Thread start address points directly into an unbacked private VAD allocation (`StartPath == N/A`). | `threads.txt` (`StartAddress`, `StartPath`) |
| **PEB Module Linking** | All modules present in PEB `InLoadOrder`, `InMemoryOrder`, `InInitializationOrder`. | Unlinked modules (`InLoad = False`, `InInit = False`, `InMem = True`) indicating reflective DLL loading. | `ldrmodules.txt` |

---

## 4. Feature-by-Feature Memory Inventory

| Feature Name | Granularity | Meaning | Legitimate Noise Source | Clean Extraction Formula |
|---|---|---|---|---|
| `unmapped_executable_pages` | Memory / VAD | Count of executable VAD regions with no file backing on disk. | .NET CLR JIT pages in powershell / OneDrive | VAD regions with `Protection in (EXECUTE, EXECUTE_READWRITE)` and `File is NULL`, grouped by non-system process. |
| `malfind_non_defender_regions` | Region / Process | Malfind detection regions excluding `MsMpEng.exe`. | .NET JIT buffers | `count(malfind_regions[Process != 'MsMpEng.exe'])`. Benign baseline is 3-4; malware is 6-9. |
| `vad_protection_anomaly_count` | Memory / VAD | Regions where Protection differs from OriginalProtection (e.g. RW -> RX/RWX). | Rare in JIT; typical of shellcode injection | Count of VAD entries where `Protection != OriginalProtection` and process is not Defender. |
| `ldrmodules_inconsistencies` | Module | Discrepancies in PEB DLL order lists. | None in standard benign apps | Count of rows in `ldrmodules.txt` where `InLoad == False` and `InMem == True`. |
| `yara_shellcode_matches` | Region | Known shellcode patterns in private memory. | None | Hex regex match for `\xFC\xE8`, `\x4D\x5A` in `malfind` hexdumps of user processes. |
| `unbacked_thread_start_count` | Thread | Threads whose `StartAddress` resides in an unbacked VAD. | None (Threads in JIT start within `clr.dll`) | Count of threads where `StartPath == 'N/A'` or not in `dlllist.txt` ranges. |
