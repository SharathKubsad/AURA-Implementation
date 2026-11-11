# Dataset JSON Schema & Structure Inventory

**Date:** 2026-09-22  
**Investigation Scope:** Empirical inspection of all 147 JSON files located under `Dataset/`.  
**Status:** COMPLETE — STRUCTURES & KEYS VERIFIED WITH BOM-AWARE PARSING.

---

## 1. Overview of JSON Files

The 147 JSON files partition into four distinct schemas:
1. **Batch Manifests (`manifest.json`):** 12 files (1 per batch directory) — RAW METADATA.
2. **Run Metadata (`metadata/RUN-xxx.json`):** 45 files (1 per execution run) — RAW METADATA.
3. **Interim Process Features (`process/RUN-xxx.json`):** 45 files — DERIVED FEATURE DATA.
4. **Interim Memory Features (`memory/RUN-xxx.json`):** 45 files — DERIVED FEATURE DATA.

---

## 2. Structure 1: Batch Manifest (`manifest.json`)

- **Classification:** RAW/NEAR-RAW METADATA
- **Location:** `<batch_dir>/manifest.json` (12 files)
- **Top-Level Keys:** 10 keys:
  - `dataset` (str): Internal batch label e.g., `"custom_powershell_fileless"`.
  - `label` (int): Ground truth binary label (`0` for benign, `1` for malware).
  - `family` (str): Malware family name e.g., `"powershell_fileless"`, `"cobalt_strike_beacon"`.
  - `source_type` (str): `"controlled_windows_vm"`.
  - `created_utc` (str): ISO timestamp of batch creation e.g., `"2026-09-19T14:03:43.349897+00:00"`.
  - `completed_utc` (str): ISO timestamp of batch completion e.g., `"2026-09-19T14:48:12.112000+00:00"`.
  - `pipeline` (dict): Forensic pipeline versions e.g., `{"volatility": "3.28.0", "hypervisor": "kvm_qemu"}`.
  - `notes` (str): Execution notes e.g., `"Controlled execution for powershell_fileless"`.
  - `statistics` (dict): Summary sample counts and feature completion rates.
  - `runs` (list of str): List of run IDs belonging to this batch e.g., `["RUN-001", "RUN-002", "RUN-003"]`.

---

## 3. Structure 2: Run Metadata (`metadata/RUN-xxx.json`)

- **Classification:** RAW/NEAR-RAW METADATA
- **Location:** `<batch_dir>/metadata/RUN-xxx.json` (45 files)
- **Top-Level Keys:** 12 keys:

| Key | Datatype | Example Value | Description / Forensic Meaning |
|---|---|---|---|
| `sample_id` | `string` | `"EXEC_RUN-001"`, `"EXEC_RUN-1100"` | Canonical execution sample identifier. |
| `label` | `integer` | `0` or `1` | **GROUND TRUTH BINARY TARGET**. 0 = Benign, 1 = Malware. |
| `family` | `string` | `"powershell_fileless"`, `"benign"` | **GROUND TRUTH MULTICLASS TARGET**. Exact family name. |
| `track` | `string` | `"TRACK_A"`, `"TRACK_B"`, `"BENIGN"` | Track ownership flag. |
| `os` | `string` | `"microsoft_windows_11_home"` | Target OS version inside the VM. |
| `execution_timestamp` | `string` | `"2026-09-19T12:50:28Z"` | UTC start time of the execution campaign. |
| `source_type` | `string` | `"custom_sandbox"` | Origin classification. |
| `source_reference` | `string` | `"manual_controlled_execution"`| Execution protocol reference. |
| `evidence_sha256` | `string` | `4c4c7e6080658b...` | SHA-256 hash of the execution archive. |
| `memory_dump` | `boolean` | `true` | Confirms memory dump was captured for this run. |
| `sysmon_available` | `boolean` | `true` | Confirms Sysmon EVTX was captured for this run. |
| `notes` | `string` | `"Controlled execution for powershell_fileless"` | Execution notes. |

> [!IMPORTANT]
> **Provenance Discrepancy Found in Previous Builds:**  
> In `Dataset/custom_powershell_fileless/metadata/RUN-001.json`, the metadata clearly specifies:
> `{"sample_id": "EXEC_RUN-003", "label": 1, "family": "powershell_fileless"}`.  
> In the previously constructed `data/interim/dataset_audit_report.json`, this run was overridden to `binary_label: 0, family: "benign"`. This discrepancy must be rectified so that `RUN-001` retains its true label of 1.

---

## 4. Structure 3: Derived Process Features (`process/RUN-xxx.json`)

- **Classification:** DERIVED FEATURES (Pre-calculated output of an earlier extractor pass)
- **Location:** `<batch_dir>/process/RUN-xxx.json` (45 files)
- **Top-Level Keys:** 11 numeric/string keys:

| Key | Datatype | Range Across Dataset | Forensic Meaning | Evaluation & Issues |
|---|---|---|---|---|
| `sample_id` | `string` | `"RUN-1100"` to `"RUN-1002"` | Join identifier. | Valid. |
| `total_process_count` | `integer` | 82 to 158 | Total process entries in Volatility `pslist`. | Reflects OS process count. Slight inflation in malware runs due to child processes. |
| `hidden_process_count` | `integer` | 0 to 6 | Count of processes in `psscan` unlinked from `pslist`. | Genuine indicator of unlinked/DKOM processes. |
| `anomalous_ppid_count` | `integer` | 0 to 2 | PPID pointing to non-existent or invalid parent. | High specificity indicator for process injection/spoofing. |
| `avg_threads_per_process` | `float` | 10.4 to 14.8 | Mean thread count across all active processes. | Dominated by multi-threaded host processes (`MsMpEng`, `SearchIndexer`). |
| `max_threads_in_single_process` | `integer` | 48 to 112 | Maximum threads observed in any single process. | Often belongs to `svchost.exe` or `MsMpEng.exe`. |
| `total_handle_count` | `integer` | 42,000 to 58,000 | Sum of open handles in `handles.txt`. | **Severely contaminated** by Windows Defender and system daemons. |
| `suspicious_dll_count` | `integer` | 0 to 5 | DLLs loaded from unbacked memory or Temp paths. | Highly discriminative when present. |
| `malfind_process_count` | `integer` | 1 to 4 | Distinct PIDs flagged by Volatility `malfind`. | Contaminated by `MsMpEng.exe` (Defender). |
| `elevated_privilege_count`| `integer` | 12 to 24 | Enabled `SeDebugPrivilege` or `SeImpersonatePrivilege`. | Baseline system processes possess these tokens. |
| `unlinked_dll_count` | `integer` | 0 to 4 | Inconsistencies across InLoad/InInit/InMem orders. | Reflects reflective DLL injection or manual mapping. |

---

## 5. Structure 4: Derived Memory Features (`memory/RUN-xxx.json`)

- **Classification:** DERIVED FEATURES (Pre-calculated output of an earlier extractor pass)
- **Location:** `<batch_dir>/memory/RUN-xxx.json` (45 files)
- **Top-Level Keys:** 9 numeric/string keys:

| Key | Datatype | Range Across Dataset | Forensic Meaning | Evaluation & Issues |
|---|---|---|---|---|
| `sample_id` | `string` | `"RUN-1100"` to `"RUN-1002"` | Join identifier. | Valid. |
| `rwx_page_count` | `integer` | 17 to 26 | VAD regions with `PAGE_EXECUTE_READWRITE`. | **70% of regions belong to `MsMpEng.exe`**. Must filter Defender out. |
| `injected_code_regions` | `integer` | 15 to 22 | Tagged memory regions matching `malfind` criteria. | Heavy overlap between benign (18) and malware (17-22). |
| `unmapped_executable_pages` | `integer` | 18 to 28 | Executable memory regions with no backing file on disk. | Key fileless artifact, but includes .NET CLR JIT runtime. |
| `vad_protection_anomaly_count` | `integer` | 0 to 4 | Protections elevated from RW to RX/RWX via VirtualProtect. | Strong fileless indicator. |
| `ldrmodules_inconsistencies` | `integer` | 0 to 5 | Module load table discrepancies. | Reflects unlinked modules. |
| `yara_shellcode_matches` | `integer` | 0 to 2 | Shellcode preambles (`\xFC\xE8...`). | High precision, low recall. |
| `mean_memory_entropy` | `float` or `null` | `null` (100% missing) | Shannon entropy across injected memory pages. | Uncalculated because raw binary memory was not dumped. |
| `max_memory_entropy` | `float` or `null` | `null` (100% missing) | Maximum entropy among injected regions. | Uncalculated because raw binary memory was not dumped. |

---

## 6. Summary of Feature Integrity

The existing JSON feature files in `process/` and `memory/` represent early extractor outputs. While their schemas are architecturally sound, **they must not be blindly consumed as training inputs** because:
1. `handles` and `rwx_page_count` are dominated by Windows Defender (`MsMpEng.exe`).
2. `entropy` fields are 100% `null`.
3. Command and Network interim features are completely absent from these batch directories.
