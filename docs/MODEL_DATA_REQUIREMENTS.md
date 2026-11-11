# Model Data Requirements & Training Pipeline Specifications

**Date:** 2026-09-22  
**Purpose:** Definitive, ground-truth-anchored specification of raw sources, required fields, derived features, unsupported fields, and proposed training representations for each of the four modality models and the multiclass extension.  
**Investigation Status:** COMPLETE — BASED SOLELY ON PHYSICAL EVIDENCE DISCOVERED IN `Dataset/`.

---

## 1. Process Model Data Requirements

### 1.1 Raw Sources
- `volatility/RUN-xxx/pslist.txt` (Active process table)
- `volatility/RUN-xxx/psscan.txt` (Physical pool-tag process scan)
- `volatility/RUN-xxx/pstree.txt` (Process hierarchy tree and command lines)
- `volatility/RUN-xxx/threads.txt` (Thread enumeration and start addresses)
- `volatility/RUN-xxx/handles.txt` (Process handle table)
- `volatility/RUN-xxx/dlllist.txt` (Loaded DLL listings)
- `volatility/RUN-xxx/privileges.txt` (Security privileges per process)
- `process_snapshot.csv` (Live process state at acquisition)

### 1.2 Required Fields
- From `pslist.txt` / `psscan.txt`: `PID`, `PPID`, `ImageFileName`, `Threads`, `Handles`
- From `pstree.txt`: `PID`, `PPID`, `Cmd`, `Path`
- From `handles.txt`: `PID`, `Process`, `Type`, `GrantedAccess`
- From `privileges.txt`: `PID`, `Process`, `Privilege`, `Attributes`
- From `dlllist.txt`: `PID`, `Path`, `Name`
- From `threads.txt`: `PID`, `TID`, `StartAddress`, `StartPath`

### 1.3 Optional Fields
- From `process_snapshot.csv`: `WorkingSet64` (Process memory footprint), `StartTime`

### 1.4 Derived Features
1. `total_process_count`: Total active processes from `pslist.txt` (integer, run-level).
2. `hidden_process_count`: `count(psscan.PID - pslist.PID)` — processes hidden via DKOM unlinking (integer, run-level).
3. `anomalous_ppid_count`: Processes whose PPID does not match expected Windows parent-child lineage (e.g. `cmd.exe` or `powershell.exe` spawned by `services.exe` or `spoolsv.exe`) (integer, run-level).
4. `avg_threads_per_process`: Total threads / total processes (float, run-level).
5. `max_threads_in_single_process`: Maximum threads in any single non-system process (integer, run-level).
6. `total_handle_count_non_system`: Sum of open handles excluding `MsMpEng.exe` (integer, run-level).
7. `suspicious_dll_count`: DLLs loaded from `\AppData\`, `\Temp\`, or with no file backing (integer, run-level).
8. `elevated_privilege_count_non_system`: Enabled `SeDebugPrivilege` or `SeImpersonatePrivilege` in userland processes (integer, run-level).
9. `unlinked_dll_count`: Count of modules unlinked from PEB load lists in `ldrmodules.txt` (integer, run-level).
10. `thread_to_process_ratio`: `avg_threads_per_process / total_process_count` (float, run-level).

### 1.5 Unsupported Data
- Real-time CPU utilization time-series (snapshot only captures cumulative CPU time).
- Sub-millisecond process lifetime metrics.

### 1.6 Features to Avoid (Contaminated / Misleading)
- **Unfiltered `total_handle_count`**: Dominated by Windows Defender (12,000+ handles) and `lsass.exe`.
- **System-wide `elevated_privilege_count`**: Normal system services naturally hold `SeDebugPrivilege`; must be evaluated strictly for userland / scripting PIDs.

### 1.7 Final Proposed Training Row
```json
{
  "run_id": "RUN-001",
  "label": 1,
  "features": {
    "total_process_count": 153,
    "hidden_process_count": 2,
    "anomalous_ppid_count": 1,
    "avg_threads_per_process": 12.51,
    "max_threads_in_single_process": 84,
    "total_handle_count_non_system": 44820,
    "suspicious_dll_count": 2,
    "elevated_privilege_count_non_system": 3,
    "unlinked_dll_count": 1,
    "thread_to_process_ratio": 0.0818
  },
  "provenance": {
    "batch": "custom_powershell_fileless",
    "source_files": ["pslist.txt", "psscan.txt", "pstree.txt", "handles.txt", "privileges.txt"]
  }
}
```

---

## 2. Command Model Data Requirements

### 2.1 Raw Sources
- `sysmon.evtx` (Microsoft-Windows-Sysmon/Operational)
- `powershell.evtx` (Microsoft-Windows-PowerShell/Operational)

### 2.2 Required Event Types
- **Sysmon Event ID 1 (Process Create):** 2,165 to 4,717 events per run.
- **PowerShell Event ID 4104 (ScriptBlock Logging):** 444 to 508 events per run.

### 2.3 Actual Fields
- From Sysmon Event ID 1: `CommandLine`, `Image`, `ParentCommandLine`, `ParentImage`, `CurrentDirectory`, `User`, `UtcTime`
- From PowerShell Event ID 4104: `ScriptBlockText`, `ScriptBlockId`, `MessageNumber`, `MessageTotal`, `Path`

### 2.4 Derived Features & NLP Tokens
- `raw_command_text`: Concatenated command sequence and de-obfuscated script blocks executed in the sample window.
- Heuristic / Numeric Features (optional tabular head):
  - `command_length`: Character length of executed command/script.
  - `shannon_entropy`: Character entropy (detects obfuscated/encrypted strings).
  - `is_base64_encoded`: Binary flag (detects `-Enc`, `[Convert]::FromBase64String`).
  - `has_download_cradle`: Binary flag (detects `Net.WebClient`, `Invoke-WebRequest`, `curl`, `IWR`).
  - `has_bypass_execution_policy`: Binary flag (`-ExecutionPolicy Bypass`, `-ep bypass`).
  - `has_hidden_window`: Binary flag (`-WindowStyle Hidden`, `-w hidden`).
  - `uses_lolbins`: Binary flag (spawns `certutil`, `mshta`, `regsvr32`, `rundll32`, `wmic`, `bitsadmin`).

### 2.5 Critical Architectural Decision: Granularity (One Row Per Run vs One Row Per Event)

We evaluated both representations:

| Strategy | Structure | Sample Count | Pros | Cons / Risks |
|---|---|---|---|---|
| **Option A: One Row Per Run** | All commands and ScriptBlocks executed during a run are concatenated into a single session document (truncated to max tokens). | N = 45 rows | Exactly matches the run-level labels (0 = Benign run, 1 = Malware run). No label ambiguity. Directly integrates with run-level fusion. | 512-token limit of DistilBERT may truncate later stage payload commands if earlier benign background commands take token budget. |
| **Option B: One Row Per Event** | Every individual Sysmon EID 1 command and PowerShell EID 4104 script block is an independent training sample. | N = 120,000+ rows | Massively increases training sample size for DistilBERT. Model learns fine-grained malicious syntax. | **Severe Label Leakage / Noise:** In a malware run, 95% of executed commands are standard background OS commands (`whoami`, `svchost`, `taskhostw`). Labeling all commands in a malware run as "1" creates false-positive poisoning! |

**Recommendation:**  
Adopt a **Filtered Event / Run Aggregation Strategy**:
Filter out known system executables (`services.exe`, `lsass.exe`, `svchost.exe` with standard arguments). Concatenate all non-system userland commands and PowerShell ScriptBlocks executed during the run into a unified session text representation for each run (N = 45).

---

## 3. Network Model Data Requirements

### 3.1 Raw Sources
- `sysmon.evtx` (Event ID 3: Network Connection Detected) — 243 to 404 events per run.
- `volatility/RUN-xxx/netscan.txt` (Kernel network structure scan).
- `network_connections.csv` (Listening socket baseline verification).

### 3.2 Available Fields
- From Sysmon Event ID 3: `DestinationIp`, `DestinationPort`, `DestinationPortName`, `Image`, `Protocol`, `Initiated`, `SourceIp`, `SourcePort`, `User`, `UtcTime`
- From `netscan.txt`: `Proto`, `LocalAddr`, `LocalPort`, `ForeignAddr`, `ForeignPort`, `State`, `PID`, `Owner`

### 3.3 Derived Features
1. `outbound_connection_count`: Count of outbound connection attempts (`Initiated == true`).
2. `unique_remote_ips`: Count of distinct non-loopback destination IPs.
3. `suspicious_port_usage`: Connections to ports outside standard web/DNS (e.g. 4444, 8000, 8080, 8443, 9001).
4. `scripting_process_network_count`: Network connections initiated by `powershell.exe`, `cmd.exe`, `rundll32.exe`.
5. `c2_subnet_connections`: Connections directed to the host-only sandbox subnet (`192.168.100.x`).
6. `listening_port_anomaly_count`: Listening sockets outside standard 10-port Windows baseline.

### 3.4 Unsupported PCAP Features (Must NOT Be Imputed)
- `avg_interpacket_interval_ms` = **UNSUPPORTED / REMOVED**
- `beacon_regularity_score` = **UNSUPPORTED / REMOVED**
- `dns_query_count` = **UNSUPPORTED / REMOVED**
- `total_bytes_sent` = **UNSUPPORTED / REMOVED**
- `total_bytes_received` = **UNSUPPORTED / REMOVED**

---

## 4. Memory Model Data Requirements

### 4.1 Raw Sources
- `volatility/RUN-xxx/vadinfo.txt`
- `volatility/RUN-xxx/malfind.txt`
- `volatility/RUN-xxx/ldrmodules.txt`
- `volatility/RUN-xxx/threads.txt`

### 4.2 Available Fields
- From `vadinfo.txt`: `PID`, `Process`, `Protection`, `Tag`, `CommitCharge`, `PrivateMemory`, `File`
- From `malfind.txt`: `PID`, `Process`, `Start VPN`, `End VPN`, `Protection`, `Tag`, `Hexdump`, `Disasm`
- From `ldrmodules.txt`: `Pid`, `Process`, `Base`, `InLoad`, `InInit`, `InMem`, `MappedPath`
- From `threads.txt`: `PID`, `TID`, `StartAddress`, `StartPath`

### 4.3 Legitimate-Behavior Context & Features to Avoid
- **DO NOT** use raw `rwx_page_count` across all processes: `MsMpEng.exe` (Defender) creates 14-15 RWX pages in every run.
- **DO NOT** treat all .NET PowerShell RWX allocations as malicious without inspecting instruction preambles and VAD unmapped tags.

### 4.4 Clean Memory Derived Features
1. `non_defender_malfind_regions`: `count(malfind[Process != 'MsMpEng.exe'])` (integer).
2. `unmapped_executable_vad_count`: VAD regions with `Protection in (EXECUTE, EXECUTE_READWRITE)` and `File is NULL`, excluding Defender (integer).
3. `vad_protection_anomalies`: Regions committed with protection elevation (integer).
4. `ldrmodules_unlinked_dll_count`: Modules where `InLoad == False` and `InMem == True` (integer).
5. `unbacked_thread_start_count`: Threads whose `StartAddress` resides in an unbacked VAD (integer).
6. `shellcode_preamble_matches`: Regex detection of `\xFC\xE8`, `\x4D\x5A` in userland `malfind` hexdumps (integer).

---

## 5. Architectural Decision: "Do We Need a Single Unified Dataset?"

### The Evaluation
Historically, the project attempted to build a single giant table (`unified_dataset.jsonl` / `unified_dataset.csv`) by doing an inner-join across all 4 modality records per run.

**Why a Single Giant Table is Flawed for This Architecture:**
1. **Mismatched Natural Granularity:** Command evidence is textual (sequences of strings); Process, Memory, and Network are numeric/tabular. Forcing DistilBERT text into the same flat row as tabular features creates bloated files, requires artificial zero-imputations, and obscures data provenance.
2. **Missing Modality Fragility:** If a single modality extractor encounters a parsing error or missing file, an inner-join drops the entire execution run from all models!
3. **Decoupled Scoring Requirement:** In production, Objective 2 executes a **hybrid detector**:
   - Process, Command, and Network score *live telemetry* independently.
   - Memory is triggered *only* when suspicion exceeds threshold.
   - The models operate as independent microservices / scoring functions before fusion.

### The Architectural Verdict
**NO. We do NOT need a monolithic unified dataset.**

Instead, we recommend **Four Dedicated, Clean Modality Datasets**:
- `data/processed/process_dataset.jsonl` (N = 45)
- `data/processed/command_dataset.jsonl` (N = 45)
- `data/processed/network_dataset.jsonl` (N = 45)
- `data/processed/memory_dataset.jsonl` (N = 45)

All four datasets share a strict primary key: **`sample_id`** (e.g. `EXEC_RUN-001`) and standard metadata (`label`, `family`, `track`).  
When the fusion layer or the multiclass model requires a combined vector, it performs a deterministic join on `sample_id` dynamically. This keeps each model's training data clean, verifiable, and free of cross-modality contamination.

---

## 6. Recommended Training Inputs Summary

| Dataset Name | Primary Sources | Key Features / Fields | Expected Rows | Granularity | Label Source |
|---|---|---|---|---|---|
| **Process Dataset** | Volatility `pslist`, `psscan`, `pstree`, `handles`, `privileges`, `dlllist` | 10 numeric features (excluding Defender handle noise) | 45 rows (12 benign, 33 malware) | 1 row per run | `metadata/RUN-xxx.json` |
| **Command Dataset** | `sysmon.evtx` (EID 1) + `powershell.evtx` (EID 4104) | Concatenated filtered command and ScriptBlock text + 7 NLP heuristics | 45 rows (12 benign, 33 malware) | 1 row per run (session text) | `metadata/RUN-xxx.json` |
| **Network Dataset** | `sysmon.evtx` (EID 3) + Volatility `netscan.txt` | 6 genuine socket and C2 connection features (0 PCAP imputations) | 45 rows (12 benign, 33 malware) | 1 row per run | `metadata/RUN-xxx.json` |
| **Memory Dataset** | Volatility `vadinfo.txt`, `malfind.txt`, `ldrmodules.txt`, `threads.txt` | 6 clean memory injection features (Defender filtered out) | 45 rows (12 benign, 33 malware) | 1 row per run | `metadata/RUN-xxx.json` |
| **Multiclass Dataset**| Joined Process + Memory + Network + Command vectors | 29 combined clean features across all 4 modalities | 33 rows (Malware only, 11 families, 3 runs/class) | 1 row per run | `metadata/RUN-xxx.json` (`family`) |
