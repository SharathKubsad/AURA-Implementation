# Process Modality Feature Validation Report

**Date:** 2026-09-22  
**Dataset:** `data/processed/process_dataset.jsonl` (N = 45 runs: 12 Benign, 33 Malware)  
**Status:** EMPIRICAL VALIDATION COMPLETED  

---

## 1. Process Feature Distribution Across All 45 Runs

| Feature Name | Dtype | Unique | Min | Max | Mean | Median | Std | Benign Mean (Range) | Malware Mean (Range) | Quality Status |
|---|---|---|---|---|---|---|---|---|---|---|
| `total_process_count` | `int64` | 19 | 129.0 | 152.0 | 137.3333 | 137.0 | 5.0091 | 142.6667 (137.00 - 146.00) | 135.3939 (129.00 - 152.00) | **VALID** |
| `hidden_process_count` | `int64` | 13 | 0.0 | 13.0 | 4.4889 | 4.0 | 2.9971 | 2.3333 (0.00 - 5.00) | 5.2727 (1.00 - 13.00) | **VALID** |
| `anomalous_ppid_count` | `int64` | 4 | 4.0 | 7.0 | 5.1333 | 5.0 | 0.5477 | 5.3333 (5.00 - 7.00) | 5.0606 (4.00 - 7.00) | **VALID** |
| `avg_threads_per_process` | `float64` | 45 | 9.4462 | 25436768.9556 | 1430800.8066 | 10.4526 | 5561119.4982 | 10.777 (10.32 - 11.80) | 1951088.0901 (9.45 - 25436768.96) | **QUESTIONABLE** |
| `max_threads_in_single_process` | `int64` | 20 | 137.0 | 3171608576.0 | 154205768.1333 | 144.0 | 605632071.0805 | 146.9167 (142.00 - 151.00) | 210280539.4848 (137.00 - 3171608576.00) | **VALID** |
| `total_handle_count_non_system` | `int64` | 45 | 19986.0 | 28742.0 | 25180.2222 | 25382.0 | 1893.0435 | 26386.1667 (23294.00 - 28385.00) | 24741.697 (19986.00 - 28742.00) | **VALID** |
| `suspicious_dll_count` | `int64` | 1 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 (0.00 - 0.00) | 0.0 (0.00 - 0.00) | **CONSTANT** |
| `elevated_privilege_count_non_system` | `int64` | 10 | 41.0 | 63.0 | 46.3111 | 45.0 | 4.6653 | 47.25 (45.00 - 63.00) | 45.9697 (41.00 - 59.00) | **VALID** |
| `unlinked_dll_count` | `int64` | 3 | 0.0 | 49.0 | 1.3333 | 0.0 | 7.4498 | 0.0 (0.00 - 0.00) | 1.8182 (0.00 - 49.00) | **VALID** |
| `thread_to_process_ratio` | `float64` | 45 | 0.066222 | 188420.510782 | 10634.9707 | 0.0758 | 41511.9517 | 0.0756 (0.07 - 0.08) | 14502.2053 (0.07 - 188420.51) | **VALID** |

---

## 2. Process Exclusions & Anomaly Rules Documented

### 2.1 Handle Counting Exclusions
In naive extractors, total handles exceeded 55,000 and were dominated by background Windows OS services.
In `total_handle_count_non_system`, the following explicit processes are excluded from the handle summation:
- `MsMpEng.exe` (Windows Defender Antivirus Core — 11,000 to 14,000 handles)
- `System` (PID 4 — Kernel handle tables)
- `lsass.exe` (Local Security Authority Subsystem)
- `services.exe` (Service Control Manager)
- `csrss.exe` (Client/Server Runtime Subsystem)
- `svchost.exe` (Shared Service Host containers)

### 2.2 Elevated Privilege Anomaly Rules
Only non-system userland processes possessing and enabling high-privilege tokens (`SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeTcbPrivilege`, `SeAssignPrimaryTokenPrivilege`) are counted.
System daemons that hold these privileges by design are filtered out, preventing false positive inflation.

### 2.3 PPID Anomaly Logic
Anomalous PPID evaluates parent-child lineages:
1. Scripting hosts (`powershell.exe`, `cmd.exe`, `wmic.exe`, `mshta.exe`) directly spawned by system daemons (`services.exe`, `csrss.exe`, `wininit.exe`).
2. Userland processes whose `PPID` is unlinked or non-existent in the active and unlinked process pools.