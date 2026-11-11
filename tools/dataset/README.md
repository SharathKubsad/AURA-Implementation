# Sandbox Dataset Collection & Validation Framework

This directory (`tools/dataset/`) provides the automated, multi-modal evidence collection and validation pipeline for the **Real-Time Fileless Malware Detection & Forensic Framework**.

---

## 1. Directory Structure

```
tools/dataset/
├── collector.py           # Multi-modal telemetry coordinator (Process, Command, Network, Memory)
├── execution_manager.py   # Safe VM sandbox orchestrator, workload dispatcher, and timeout manager
├── process_capture.py     # Process list, handle count, and thread-to-process telemetry extractor
├── command_capture.py     # Command string capture and Shannon entropy calculator
├── network_capture.py     # Socket table, connection timing, and flow statistics extractor
├── memory_capture.py      # Volatile memory analysis and MemoryInjectionScore calculator
├── labeling.py            # Taxonomy mapping for binary and 11-family multi-class labels
├── manifest.py            # Manifest generator with SHA-256 evidence hashing
├── validation.py          # Data-leakage checker, schema validator, and distribution auditor
├── validate_dataset.py    # CLI entrypoint for automated dataset quality auditing
└── README.md              # Technical documentation and researcher guide
```

---

## 2. Safety & Operational Constraints

- **Host Isolation:** Live malware executions must take place exclusively inside isolated, host-only networked virtual machines (e.g. Hyper-V, KVM, VirtualBox snapshots).
- **Zero Fabrication Policy:** Telemetry is gathered from real process states, Windows Event logs (Event IDs 4688, 4104), and Volatility 3 forensic dumps.
- **Traceability:** Every sample is registered in `data/processed/manifest.csv` with a unique `execution_id`, sample provenance, and SHA-256 digest.

---

## 3. Telemetry Modality Schemas

1. **Process Modality (`ProcessFeatures`):**
   - `total_process_count`, `hidden_process_count`, `anomalous_ppid_count`, `avg_threads_per_process`, `max_threads_in_single_process`, `total_handle_count`, `suspicious_dll_count`, `malfind_process_count`, `elevated_privilege_count`, `unlinked_dll_count`.
2. **Command Modality (`CommandFeatures`):**
   - `raw_command_text`, `command_length`, `shannon_entropy`, `is_base64_encoded`, `has_download_cradle`, `has_bypass_execution_policy`, `has_hidden_window`, `uses_lolbins`, `registry_persistence_count`.
3. **Network Modality (`NetworkFeatures`):**
   - `active_connection_count`, `listening_port_count`, `outbound_connection_count`, `dns_query_count`, `unique_remote_ips`, `avg_interpacket_interval_ms`, `beacon_regularity_score`, `total_bytes_sent`, `total_bytes_received`, `suspicious_port_usage`.
4. **Memory Modality (`MemoryFeatures`):**
   - `rwx_page_count`, `injected_code_regions`, `unmapped_executable_pages`, `vad_protection_anomaly_count`, `ldrmodules_inconsistencies`, `yara_shellcode_matches`, `mean_memory_entropy`, `max_memory_entropy`.

---

## 4. Running Dataset Validation

To validate the current unified dataset for missing modalities, duplicate IDs, and data leakage:

```bash
python tools/dataset/validate_dataset.py
```
Reports are automatically written to `evaluation/dataset/dataset_quality_report.json` and `evaluation/dataset/DATASET_QUALITY_REPORT.md`.
