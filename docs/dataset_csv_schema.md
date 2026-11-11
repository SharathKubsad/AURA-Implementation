# Dataset CSV Schema & Column Inventory

**Date:** 2026-09-22  
**Investigation Scope:** Empirical inspection of all 102 CSV files across `Dataset/`.  
**Status:** COMPLETE — ACTUAL HEADERS & VALUES INSPECTED WITHOUT INFERENCE.

---

## 1. Overview of Distinct CSV Schemas

Across the entire dataset, there are exactly **three distinct CSV schemas**:
1. `process_snapshot.csv` (45 files, 1 per run) — Live Windows process telemetry snapshot.
2. `network_connections.csv` (45 files, 1 per run) — Live TCP/UDP active socket snapshot.
3. `batch_summary.csv` (12 files, 1 per batch) — Administrative validation manifest.

---

## 2. Schema 1: `process_snapshot.csv`

- **Filename Pattern:** `<batch_dir>/source_evidence/<run_id>/process_snapshot.csv`
- **Example Path:** `Dataset/custom_benign_batch/source_evidence/RUN-1100/process_snapshot.csv`
- **Total Files:** 45 (present in 100% of runs)
- **Row Count per File:** Ranges from 112 to 158 rows per file (one row per active Windows process at capture time).
- **Generator:** PowerShell `Get-Process | Select-Object Id, ProcessName, Path, StartTime, CPU, WorkingSet64 | Export-Csv`.

### Column Inventory Table

| Column | Type | Example Value | Null % | Unique Values (Sample Run) | Constant Across Runs? | Constant Within Run? | Candidate Models | Evaluation & Forensic Utility |
|---|---|---|---|---|---|---|---|---|
| `Id` | `integer` (int64) | `4556` | 0.0% | 134 | NO (dynamic PIDs) | NO (unique per process) | Process | **QUESTIONABLE**. Ephemeral Windows PID. Unusable directly as a feature, but essential as a join key with Volatility and Sysmon. |
| `ProcessName` | `string` (object) | `powershell`, `svchost` | 0.0% | 47 | NO (varies by payload) | NO | Process, Command, Multiclass | **VALID**. Key identifier. Distinguishes benign system daemons from living-off-the-land binaries (`powershell.exe`, `wmic.exe`, `cmd.exe`). |
| `Path` | `string` (object) | `C:\Windows\System32\cmd.exe` | 14.9% | 33 | NO | NO | Process | **VALID**. Unbacked or null paths indicate hidden processes, memory-injected processes, or system processes run from non-standard locations (e.g. `\AppData\Local\Temp`). |
| `StartTime` | `datetime` (object) | `19-09-2026 14:01:27` | 1.5% | 57 | NO | NO | Process | **QUESTIONABLE / TEMPORAL LEAKAGE RISK**. Kernel/system processes lack `StartTime`. For userland processes, delta relative to run start time indicates staged execution. |
| `CPU` | `float` (float64) | `0.50000` | 1.5% | 76 | NO | NO | Process | **UNRELIABLE / TRANSIENT**. Process CPU time varies wildly with VM hypervisor scheduling and sleep pauses. High variance, weak generalization. |
| `WorkingSet64` | `integer` (int64) | `11919360` (bytes) | 0.0% | 133 | NO | NO | Process, Memory | **VALID**. Physical memory footprint of each process. Useful for detecting anomalously large powershell.exe or hollowed processes allocating large heaps. |

---

## 3. Schema 2: `network_connections.csv`

- **Filename Pattern:** `<batch_dir>/source_evidence/<run_id>/network_connections.csv`
- **Example Path:** `Dataset/custom_benign_batch/source_evidence/RUN-1100/network_connections.csv`
- **Total Files:** 45 (present in 100% of runs)
- **Row Count per File:** Ranges from 15 to 19 rows per file.
- **Generator:** PowerShell `Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | Export-Csv`.

### Column Inventory Table

| Column | Type | Example Value | Null % | Unique Values (Sample Run) | Constant Across Runs? | Constant Within Run? | Candidate Models | Evaluation & Forensic Utility |
|---|---|---|---|---|---|---|---|---|
| `LocalAddress` | `string` (object) | `::`, `0.0.0.0`, `127.0.0.1` | 0.0% | 3 | **YES** | NO | Network | **CONSTANT / UNINFORMATIVE**. Always standard loopback and wildcard bindings. Zero discriminative power. |
| `LocalPort` | `integer` (int64) | `135`, `445`, `49669` | 0.0% | 10 | **YES** (Identical 10 ports across all 45 runs) | NO | Network | **CONSTANT / CONTAMINATED**. Exactly the same 10 ports (135, 445, 5040, 7680, 49664-49669) appear in every benign and malware run. These are Windows 11 RPC/SMB/Wlan daemons. |
| `RemoteAddress` | `string` (object) | `::`, `0.0.0.0` | 0.0% | 2 | **NEARLY CONSTANT** | YES | Network | **UNUSABLE FROM THIS FILE**. 43 of 45 runs have exclusively wildcard `::` and `0.0.0.0`. Only 2 runs captured an active port 22 connection. Outbound C2 was not captured here (captured in Sysmon Event ID 3). |
| `RemotePort` | `integer` (int64) | `0` | 0.0% | 1 (in 43 runs) | **NEARLY CONSTANT** | YES | Network | **UNUSABLE FROM THIS FILE**. Always 0 (no foreign connection) except for two SSH administration events. |
| `State` | `string` (object) | `Listen` | 0.0% | 1 (in 43 runs) | **NEARLY CONSTANT** | YES | Network | **CONSTANT**. 99.5% of rows are in state `Listen`. |
| `OwningProcess` | `integer` (int64) | `808` (`svchost`) | 0.0% | 9 | NO (dynamic PIDs) | NO | Network, Process | **QUESTIONABLE**. Maps listening ports to system PIDs (lsass, svchost, spoolsv). Shows that no malware opened a persistent listening server socket. |

> [!CRITICAL]
> `network_connections.csv` records only local listening socket state. Because fileless malware operates as a client making outbound beacon connections or HTTPS downloads rather than opening listening servers, this CSV cannot distinguish malware from benign runs. Outbound connection events must be sourced from Sysmon Event ID 3 or Volatility `netscan.txt`.

---

## 4. Schema 3: `batch_summary.csv`

- **Filename Pattern:** `<batch_dir>/batch_summary.csv`
- **Example Path:** `Dataset/custom_benign_batch/batch_summary.csv`
- **Total Files:** 12 (1 per batch directory)
- **Row Count per File:** Exactly equal to the number of runs in the batch (12 rows for benign; 3 rows for each malware family = 45 rows total across all files).
- **Purpose:** Test harness logging and pipeline sanity verification.

### Column Inventory Table

| Column | Type | Example Value | Null % | Unique Values | Constant Across Runs? | Candidate Models | Forensic Utility |
|---|---|---|---|---|---|---|---|
| `sample_id` | `string` | `RUN-1100`, `RUN-001` | 0.0% | 45 | NO | ALL | **METADATA KEY**. Primary join key for all modalities. |
| `memory_exists` | `string` | `YES` | 0.0% | 1 | **YES** | None | Metadata check (confirms 6.4 GB RAM dump was acquired during VM execution). |
| `memory_size_bytes` | `integer` | `6422409216` | 0.0% | 1 | **YES** | None | Constant 6 GB RAM size of the execution VM. |
| `volatility_status`| `string` | `PASS` | 0.0% | 1 | **YES** | None | Pipeline verification flag. |
| `extraction_status`| `string` | `PASS` | 0.0% | 1 | **YES** | None | Feature extraction completion flag. |
| `validation_status`| `string` | `PASS` | 0.0% | 1 | **YES** | None | Schema validation completion flag. |
| `notes` | `string` | `NaN` | 100.0%| 0 | **YES** | None | Unpopulated operator notes field. |
