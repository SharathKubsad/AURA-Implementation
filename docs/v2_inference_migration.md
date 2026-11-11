# V2 Model Inference Migration Guide

**Date:** 2026-09-22  
**Purpose:** Formal migration specifications for `DetectionService`, live collectors, and API schemas to consume V2 model artifacts without breaking changes.

---

## 1. Summary of Model Artifact Changes

| Model | V1 Artifact Path (Retired) | V2 Artifact Path (Active) | Input Dimensionality Change |
|---|---|---|---|
| **Process** | `models/artifacts/process/` | `models/artifacts/process_v2/` | Reduced from 11 features to 6 features (dropped corrupted threads and constant DLLs) |
| **Command** | `models/artifacts/command/` | `models/artifacts/command_v2/` | Switched from broken fallback tokenizer to clean DistilBERT model |
| **Network** | `models/artifacts/network/` | `models/artifacts/network_v2/` | Reduced from 15 features to 4 features (excised 5 zero-imputed PCAP metrics & 2 constants) |
| **Memory** | `models/artifacts/memory/` | `models/artifacts/memory_v2/` | Reduced from 9 features to 4 features (excluded Defender RWX and constant shellcode) |

---

## 2. Required Modifications per Modality

### 2.1 Process Collector (`framework/live_collectors/process_collector.py`)
- **V1 Input Expected:** 10 Volatility features + thread_to_process_ratio.
- **V2 Input Required:** Exactly 6 features:
  1. `total_process_count`
  2. `hidden_process_count`
  3. `anomalous_ppid_count`
  4. `total_handle_count_non_system` (must apply system daemon exclusion set: MsMpEng, System, lsass, services, csrss, svchost)
  5. `elevated_privilege_count_non_system`
  6. `unlinked_dll_count`

### 2.2 Command Collector (`framework/live_collectors/command_collector.py`)
- **V1 Input Expected:** `raw_command_text` tokenized by broken fallback tokenizer.
- **V2 Input Required:** Concatenated session commands and ScriptBlock texts passed directly to `models/artifacts/command_v2/` tokenizer.

### 2.3 Network Collector (`framework/live_collectors/network_collector.py`)
- **V1 Input Expected:** 10 features + 5 missingness indicators (including PCAP packet counts).
- **V2 Input Required:** Exactly 4 features from Sysmon Event ID 3 and socket snapshots:
  1. `outbound_connection_count`
  2. `suspicious_port_usage`
  3. `scripting_process_network_count`
  4. `listening_port_anomaly_count`

### 2.4 Memory Trigger (`framework/live_collectors/memory_trigger.py`)
- **V1 Input Expected:** Total RWX page count, raw malfind regions.
- **V2 Input Required:** Exactly 4 non-Defender features from Volatility:
  1. `non_defender_malfind_regions`
  2. `unmapped_executable_vad_count`
  3. `vad_protection_anomalies`
  4. `ldrmodules_unlinked_dll_count`

---

## 3. Detection Service & Fusion Architecture

- The fusion formula (`(P_proc + P_cmd + P_net + P_mem) / 4 >= 0.60`) remains structurally unchanged.
- Model loading paths in `config/detector.yaml` or `DetectionService.__init__` should be updated to point to `models/artifacts/*_v2` once migration is scheduled.