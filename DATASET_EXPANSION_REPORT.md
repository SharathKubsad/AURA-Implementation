# Dataset Specification, Expansion Architecture & Quality Report

**Document Date:** 2026-09-27  
**Project:** Real-Time Fileless Malware Detection via Multi-Modal Telemetry & Volatile Memory Forensics  
**Dataset Versions:** Dataset v1.0 (Archived at `data/archive/v1_45_samples/`), Dataset v2.0 Sandbox Pipeline (`tools/dataset/`)

---

## 1. Motivation & Scope

Fileless malware executes in volatile RAM, utilizing living-off-the-land binaries (LOLBins), reflective code injection, and PowerShell download cradles without writing detectable binaries to physical disks. To detect these threats in real time without causing endpoint memory-dump thrashing, we designed a **multi-tiered, multi-modal telemetry architecture** capturing four distinct evidence streams:
1. **Process Tree & Handle State** (`ProcessFeatures`)
2. **Command Line & PowerShell Script Block Tokens** (`CommandFeatures`)
3. **Network Sockets & Flow Statistics** (`NetworkFeatures`)
4. **Volatile Memory VAD Structures & Page Entropies** (`MemoryFeatures`)

---

## 2. Dataset Versioning & Preservation

* **Dataset v1.0 (Archived Base Runs):** Preserved in `data/archive/v1_45_samples/` containing the exact 45 authentic benchmark executions (`unified_dataset_v1.jsonl`, `dataset_manifest.json`, `feature_statistics.json`, `unified_dataset.csv`).
* **Active Production Benchmark (`data/processed/unified/unified_dataset.jsonl`):** 45 authentic sandbox executions (13 Benign, 32 Malware across 11 canonical families).
* **Scaled 6,000-Sample Benchmark Dataset (`Dataset/fileless_malware_6000_synthetic_samples.csv`):** The 45 authentic executions were used to characterize observed behavioral patterns, while the 6,000-sample benchmark was generated using controlled statistical distributions and behavioral templates (3,000 Benign, 3,000 Malware across all 11 malware families) to evaluate model convergence, high-throughput stress testing, and large-scale robustness.
* **Automated Collection Infrastructure (`tools/dataset/`):** Full reproducible sandbox framework capable of orchestrating controlled benign workloads and safe malware detonations.

---

## 3. Dataset Composition & Class Distribution

| Split / Category | Total Runs | Modalities Captured | Description |
|---|---|---|---|
| **Benign Workloads** | **13** | Process, Command, Network, Memory | System service diagnostics, WMI hardware inventory, network routing diagnostics, log rotation, ZIP archive tests, administrative scripts. |
| **Malware Executions** | **32** | Process, Command, Network, Memory | 11 canonical fileless families / granular attack tools detonated in isolated VMs. |
| **Total Authentic Executions** | **45** | **4 Modalities (100% Complete)** | Full multi-modal feature vectors without synthetic fabrication. |

### Malware Family Distribution ($N=32$):
1. **Cobalt Strike Beacon:** 3 executions (In-memory beaconing, reflective stager, sleep obfuscation)
2. **Empire Framework Multi-Launcher:** 3 executions (In-memory agent staging)
3. **Empire Invoke-PoshRat / Memory RAT:** 3 executions (Pure volatile memory shell)
4. **Metasploit Meterpreter Memory Payloads:** 3 executions (Staged reverse TCP in memory)
5. **Covenant Grunt:** 3 executions (CLR in-memory execution)
6. **PowerSploit Invoke-Shellcode:** 3 executions (Direct memory allocation and execution)
7. **PowerSploit Invoke-ReflectivePEInjection:** 3 executions (Unbacked memory PE loading)
8. **Empire Invoke-CredentialInjection:** 3 executions (Process token injection)
9. **Empire Invoke-BypassUAC / LOLBins:** 3 executions (Living-off-the-land binary abuse)
10. **PowerSploit Invoke-Mimikatz:** 3 executions (LSASS memory scraping)
11. **PowerShell Fileless Cradles:** 2 executions (Base64 encoded download cradles)

---

## 4. Telemetry Modality Schemas & Mathematical Formulations

### 1. Process Modality (`ProcessFeatures`)
- **Fields (10):** `total_process_count`, `hidden_process_count`, `anomalous_ppid_count`, `avg_threads_per_process`, `max_threads_in_single_process`, `total_handle_count`, `suspicious_dll_count`, `malfind_process_count`, `elevated_privilege_count`, `unlinked_dll_count`.

### 2. Command Modality (`CommandFeatures`)
- **Fields (9):** `raw_command_text`, `command_length`, `shannon_entropy`, `is_base64_encoded`, `has_download_cradle`, `has_bypass_execution_policy`, `has_hidden_window`, `uses_lolbins`, `registry_persistence_count`.
- **Shannon Entropy Calculation:**
  $$H(X) = -\sum_{i=1}^n p(x_i) \log_2 p(x_i)$$

### 3. Network Modality (`NetworkFeatures`)
- **Fields (10):** `active_connection_count`, `listening_port_count`, `outbound_connection_count`, `dns_query_count`, `unique_remote_ips`, `avg_interpacket_interval_ms`, `beacon_regularity_score`, `total_bytes_sent`, `total_bytes_received`, `suspicious_port_usage`.

### 4. Memory Modality (`MemoryFeatures`)
- **Fields (8):** `rwx_page_count`, `injected_code_regions`, `unmapped_executable_pages`, `vad_protection_anomaly_count`, `ldrmodules_inconsistencies`, `yara_shellcode_matches`, `mean_memory_entropy`, `max_memory_entropy`.
- **Memory Injection Score:**
  $$\text{MemoryInjectionScore} = 2.0(\text{RWX}) + 3.0(\text{InjectedRegions}) + 1.5(\text{VADAnomalies})$$

---

## 5. Automated Sandbox Collection Infrastructure (`tools/dataset/`)

The repository includes a standalone, safe collection framework:
- `collector.py`: Multi-modal coordinator.
- `execution_manager.py`: Workload dispatcher with automatic timeouts and snapshot isolation.
- `process_capture.py`: Live process state extraction via `psutil` and Win32 APIs.
- `command_capture.py`: EventLog 4104 / 4688 listener and entropy calculator.
- `network_capture.py`: Real-time socket table and traffic metrics analyzer.
- `memory_capture.py`: Volatility 3 VAD dump bridge and signature parser.
- `labeling.py`: Standard taxonomy mapper.
- `manifest.py`: SHA-256 evidence digest tracker (`data/processed/manifest.csv`).
- `validation.py`: Data quality and leakage auditing suite.

---

## 6. Dataset Quality & Leakage Audit Summary

Audited by `tools/dataset/validate_dataset.py`:
- **Duplicate Execution IDs:** 0 (PASS)
- **Missing Modality Vectors:** 0 (PASS across all 4 modalities)
- **Invalid Feature Ranges:** 0 (PASS)
- **Train/Test Group Leakage:** None (PASS)
- **Traceability:** 100% of samples registered in `data/processed/manifest.csv` with SHA-256 digests.
