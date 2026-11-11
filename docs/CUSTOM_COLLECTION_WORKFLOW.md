# Custom Dataset Collection & Processing Workflow (Milestone A6)

## 1. Overview & Architecture

The A6 Orchestrator establishes an automated, reproducible, one-click workflow for controlled fileless malware and benign activity data collection across our isolated dual-VM environment.

```
+-------------------------------------------------------------------------------+
|                             HOST-ONLY NETWORK (192.168.100.0/24)              |
|                                                                               |
|  +--------------------------------+       +--------------------------------+  |
|  | Windows Target (FMD-Windows)   |       | Analysis Host (FMD-Kali)       |  |
|  | IP: 192.168.100.20             |       | IP: 192.168.100.10             |  |
|  |                                |       |                                |  |
|  | 1. Double-click .bat or .ps1   |  SCP  | 4. Double-click or run:        |  |
|  | 2. READY -> COLLECTING         | =====>|    ./process_run_kali.sh       |  |
|  | 3. CAPTURE (DumpIt + Sysmon)   |       | 5. Verify & Volatility 3       |  |
|  | 4. FINALIZING (SHA256)         |       | 6. A4 Extraction -> Features   |  |
|  +--------------------------------+       +--------------------------------+  |
+-------------------------------------------------------------------------------+
```

### Scientific Principles
1. **One RUN = One Controlled Experiment**: Every RUN directory corresponds strictly to a single controlled sample execution or clean benign workload. Never combine unrelated activities.
2. **Four Modalities Collected**: Every run captures telemetry across all four feature spaces:
   - **Process**: Active process tree, handle counts, thread states.
   - **Command**: PowerShell logs (`powershell.evtx`), Sysmon event ID 1 command lines.
   - **Network**: Network connections snapshot (`network_connections.csv`), PCAP capture.
   - **Memory**: Volatile memory dump (`memory.raw` / `memory.dmp`) and Volatility 3 findings.
3. **No Automatic Malware Execution**: The orchestrator is collection infrastructure only. The researcher manually and deliberately launches the authorized activity in the isolated environment.

---

## 2. End-to-End Pipeline: PREPARE -> START ACTIVITY -> CAPTURE -> TRANSFER -> PROCESS -> VALIDATE

### Step 1: PREPARE
- Ensure `FMD-Windows` (192.168.100.20) and `FMD-Kali` (192.168.100.10) are booted on the isolated host-only network adapter.
- Ensure Sysmon service is running on `FMD-Windows` (`Get-Service Sysmon`).
- Ensure DumpIt is available in `C:\Tools\DumpIt\DumpIt.exe` or `C:\FMD-Transfer\DumpIt.exe`.
- **Python Runtime on FMD-Windows**: Python 3.11+ (e.g. 3.13) with the Windows Python Launcher (`py.exe`).
  - The collector launcher (`tools\collect_run_windows.bat`) automatically detects and prefers `py -3` / `py`.
  - Bypasses the Microsoft Store App Execution Alias without requiring manual PATH edits or disabling App Execution Aliases in Windows Settings.

### Step 2: START ACTIVITY (Windows Controller)
On `FMD-Windows`, launch the collection orchestrator:
- **Option A (One-Click GUI)**: Double-click `tools\collect_run_windows.bat`. Automatically detects Python (`py -3`), checks for Administrator rights, and requests elevation via UAC if needed.
- **Option B (PowerShell CLI)**:
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\tools\collect_run_windows.ps1
  # With optional automated SCP transfer:
  powershell -ExecutionPolicy Bypass -File .\tools\collect_run_windows.ps1 -Transfer -KaliHost 192.168.100.10 -KaliUser fmd
  ```
- **What happens automatically**:
  1. Checks for Windows Administrator rights; self-elevates using `RunAs` preserving arguments if unprivileged.
  2. Loads category catalog and inspects persistent allocation ledger (`data/raw/custom/allocated_runs.json`).
  3. Prompts the operator to select the experiment category (1–12).
  4. Allocates the next unused RUN ID in the category range (skipping `RUN-001` and any transferred runs).
  5. Atomically records status `ALLOCATED` in `allocated_runs.json`.
  6. Transitions state machine: `READY` -> `COLLECTING`.
  7. Prompts: *"Start your authorized, controlled activity inside this isolated VM now. Press [ENTER] when ready for CAPTURE..."*

### Step 3: CAPTURE & CANONICAL FINALIZATION
Once the payload or benign activity is executing in the VM:
- Press **[ENTER]** in the collector console.
- **What happens automatically**:
  1. Transitions state: `COLLECTING` -> `CAPTURE`.
  2. Exports Sysmon operational logs to `sysmon.evtx`.
  3. Exports PowerShell operational logs to `powershell.evtx`.
  4. Takes a snapshot of active processes to `process_snapshot.csv`.
  5. Takes a snapshot of active network connections to `network_connections.csv`.
  6. Runs DumpIt for volatile memory acquisition into `memory.raw`:
     - Distinguishes `MEMORY CAPTURE SUCCESS`, `MEMORY CAPTURE FAILED`, and `MEMORY CAPTURE SKIPPED`.
     - If memory capture unexpectedly fails, halts and does not mark run `COMPLETE`.
  7. Transitions state: `CAPTURE` -> `FINALIZING`.
  8. Computes the **Unified Canonical Evidence SHA-256**:
     - Gathers all evidence files recursively (excluding `metadata.json`).
     - Sorts files deterministically by normalized relative POSIX path.
     - Streams relative-path bytes followed by raw chunked file bytes into single SHA-256 digest.
     - Produces identical hash across PowerShell (.NET) and Python (`calculate_directory_evidence_sha256()`).
  9. Generates and validates `metadata.json` compliant with `CustomCollectionMetadata` schema.
  10. Updates ledger status to `FINALIZED`.
  11. If `-Transfer` was specified, executes SCP transfer to Kali and marks status `TRANSFERRED`.
  12. Transitions state: `FINALIZING` -> `COMPLETE`.

### Step 4: TRANSFER
If `-Transfer` was not passed during capture, transfer the completed RUN folder from `FMD-Windows` to `FMD-Kali`:
```bash
# From Windows to Kali (host-only network):
scp -r "C:\FMD-Transfer\RUN-XXX" fmd@192.168.100.10:~/fmd-results/custom/
```
Or use the HTTP transfer server running on `192.168.100.1:8000`. Windows evidence is preserved locally.

### Step 5: PROCESS (Kali Controller)
On `FMD-Kali`, process the incoming RUN:
- **Option A (One-Click CLI)**:
  ```bash
  ./tools/process_run_kali.sh RUN-XXX
  ```
- **Option B (GUI)**: Double-click `process_run_kali.sh` in Thunar file manager. A terminal will automatically open and prompt for the RUN ID.
- **What happens automatically**:
  1. Locates the RUN directory in `~/fmd-results/custom/RUN-XXX` or `data/raw/custom/*/RUN-XXX`.
  2. Verifies schema compliance of `metadata.json`.
  3. Verifies canonical SHA-256 evidence integrity matching the exact algorithm used on Windows.
  4. If raw memory dump (`memory.raw`) is present and Volatility outputs are missing, runs the 11 required Volatility 3 plugins.
  5. Invokes the existing Track A forensic extraction pipeline (`run_track_a_extraction`), reusing all semantic parsers.
  6. Writes standardized feature JSON records to:
     - `data/interim/custom/process/EXEC_RUN-XXX_process.json`
     - `data/interim/custom/memory/EXEC_RUN-XXX_memory.json`
  7. Verifies that Command and Network evidence files are preserved for Track B.
  8. Updates persistent ledger status to `PROCESSED`.
  9. Writes `validation_report.json` in the RUN directory.

### Step 6: VALIDATE
Examine the generated `validation_report.json` inside the RUN directory:
```json
{
  "status": "PASS",
  "sample_id": "EXEC_RUN-002",
  "run_dir": "/path/to/data/raw/custom/powershell_fileless/RUN-002",
  "label": 1,
  "family": "powershell_fileless",
  "track": "TRACK_A",
  "process_features": ".../data/interim/custom/process/EXEC_RUN-002_process.json",
  "memory_features": ".../data/interim/custom/memory/EXEC_RUN-002_memory.json",
  "process_status": "PASS",
  "memory_status": "PASS",
  "track_b_evidence": {
    "sysmon.evtx": true,
    "powershell.evtx": true,
    "process_snapshot.csv": true,
    "network_connections.csv": true,
    "network.pcap": false
  }
}
```

---

## 3. Category & RUN ID Allocation Table

Run IDs are allocated automatically in strictly partitioned non-overlapping numeric ranges:

| Index | Category Name | Track | Binary Label | Multi-class Label | Assigned Range |
|---|---|---|---|---|---|
| **0** | `benign_validation` (RUN-001) | Joint | 0 | 0 | **RUN-001** (Reserved Baseline) |
| **1** | `benign` | Joint / A | 0 | 0 | **RUN-1100 .. RUN-1299** |
| **2** | `powershell_fileless` | Track A | 1 | 1 | **RUN-002 .. RUN-099** |
| **3** | `process_hollowing` | Track A | 1 | 3 | **RUN-100 .. RUN-199** |
| **4** | `memory_only_rat` | Track A | 1 | 6 | **RUN-200 .. RUN-299** |
| **5** | `registry_resident_malware` | Track A | 1 | 5 | **RUN-300 .. RUN-399** |
| **6** | `cobalt_strike_beacon` | Track A | 1 | 7 | **RUN-400 .. RUN-499** |
| **7** | `metasploit_memory_payloads` | Track A | 1 | 8 | **RUN-500 .. RUN-599** |
| **8** | `wmi_malware` | Track B | 1 | 2 | **RUN-600 .. RUN-699** |
| **9** | `reflective_dll_injection` | Track B | 1 | 4 | **RUN-700 .. RUN-799** |
| **10** | `lolbins_abuse` | Track B | 1 | 9 | **RUN-800 .. RUN-899** |
| **11** | `fileless_ransomware` | Track B | 1 | 10 | **RUN-900 .. RUN-999** |
| **12** | `empire_framework` | Track B | 1 | 11 | **RUN-1000 .. RUN-1099** |

---

## 4. Error Handling & Failure Recovery

| Scenario | Handled By | Behavior |
|---|---|---|
| **Target directory already exists** | `CollectionStateMachine` | Fails immediately with collision error; never overwrites existing runs. |
| **DumpIt missing or memory capture fails** | Windows Collector | Logs warning, marks `memory_dump: false` in `metadata.json`, continues EVTX/process collection. |
| **Corrupted or tampered evidence file** | Orchestrator Verifier | Recomputed SHA-256 differs from `evidence_sha256`; flags integrity check failure and halts processing. |
| **Missing required Volatility output** | A4 Pipeline | Reports missing evidence file in `validation_report.json` and exits with code 1. |
| **Accidental execution attempt** | Safety Policy | Orchestrator contains zero payload generation, execution, or persistence routines. |
