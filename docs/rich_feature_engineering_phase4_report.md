# Phase 4 Report: Rich Forensic Feature Engineering
**Project:** Real-Time AI-Based Fileless Malware Detection and Classification System  
**Date:** 2026-09-24  
**Status:** `PHASE_4_APPROVED_FOR_MODEL_TRAINING`  

---

## 1. Executive Summary

Phase 4 has successfully constructed the **model-ready, semantically grounded feature layer** directly and exclusively from the canonical rich forensic representation (`data/forensic/`). 

In this phase:
1. **Strict Dataset Protection:** The authoritative `Dataset/` directory was **not touched, modified, or altered**.
2. **Exclusively Forensic Grounding:** Every feature was derived from verified forensic entities, events, and relationship graphs (`processes`, `threads`, `handles`, `privileges`, `memory_regions`, `malfind`, `commands`, `powershell`, `network_connections`, and cross-modal edges).
3. **Modal Decoupling:** Modality-specific datasets were produced with explicit schemas, feature statistics, and missingness audits under `data/features/`.
4. **Dual Representation for Command Modality:** Generated both structured tabular features (`command_features.jsonl`) and uncompressed textual sequences (`text_sequences.jsonl`, 200,090 records) suitable for fine-tuning transformer models (RoBERTa / DistilBERT).
5. **Collection Harness Exclusion:** Operator capture scripts (`DumpIt.exe`, `collect_run_windows.ps1`, `scp.exe`, etc.) were identified and strictly excluded from command and process training feature calculations.
6. **Strict Null Semantics:** Unsupported packet-level network metrics (`packet_count`, `byte_count`, `flow_duration_sec`, `beacon_periodicity_sec`) remain explicitly `NULL` (`None`) across all 45 runs, preventing artificial zero fabrication.
7. **Run-Disjoint Partitioning:** A run-level stratified train/validation/test split was established across all 45 runs, guaranteeing zero sample overlap across partitions.
8. **Automated Verification:** All 10 verification tests in `tests/test_rich_feature_engineering.py` passed with 100% success.

---

## 2. Feature Count Summary by Modality

| Modality | Target Directory | Number of Features | Number of Rows | Key Artifacts |
|---|---|:---:|:---:|---|
| **Process** | `data/features/process/` | **20** | 45 | `process_features.jsonl`, `process_features.csv`, `schema.json`, `statistics.json`, `missingness_report.json` |
| **Memory** | `data/features/memory/` | **18** | 45 | `memory_features.jsonl`, `memory_features.csv`, `schema.json`, `statistics.json`, `missingness_report.json` |
| **Command** | `data/features/command/` | **15** | 45 | `command_features.jsonl`, `command_features.csv`, `text_sequences.jsonl` (200,090 sequences), `schema.json`, `statistics.json`, `missingness_report.json` |
| **Network** | `data/features/network/` | **17** | 45 | `network_features.jsonl`, `network_features.csv`, `schema.json`, `statistics.json`, `missingness_report.json` |
| **Cross-Modal** | `data/features/cross_modal/` | **7** | 45 | `cross_modal_features.jsonl`, `cross_modal_features.csv`, `schema.json`, `statistics.json`, `missingness_report.json` |
| **Total Features** | **`data/features/`** | **77** | **45** | Fully documented in `docs/rich_feature_dictionary.md` |

---

## 3. Command Modality Dual Architecture

The Command modality preserves two parallel representations to support both tree-based and transformer-based architectures:
1. **Structured Numerical Features (`command_features.jsonl`):** 15 behavioral features capturing command counts, PowerShell ScriptBlock counts, length distributions, execution policy modifications, download cradles, LOLBin invocations, registry modifications, and command diversity.
2. **Raw Textual Sequences (`text_sequences.jsonl`):** 200,090 sequence records containing individual command lines and PowerShell ScriptBlocks with timestamps, process IDs, and source plugins. 
   - **Exclusion Rule:** All operator collection commands (`DumpIt.exe`, `collect_run_windows.ps1`, `scp.exe`) tagged as `COLLECTION_HARNESS` were filtered out.

---

## 4. Network Modality & Explicit Null Semantics

- **Source Separation:** Dynamic Sysmon EID 3 remote connections are explicitly separated from static netstat listening socket snapshots (`NETSTAT_SNAPSHOT` vs `SYSMON_EID3`).
- **Strict Null Semantics:** Because packet captures (PCAP) were not collected during sandbox execution, packet and byte-level fields are **NOT** fabricated as `0`. They are maintained as explicit `NULL` (`None`) across all 45 runs:
  - `net_packet_count`: `None` (100% missing, `is_explicit_null_field: true`)
  - `net_byte_count`: `None` (100% missing, `is_explicit_null_field: true`)
  - `net_flow_duration_sec`: `None` (100% missing, `is_explicit_null_field: true`)
  - `net_beacon_periodicity_sec`: `None` (100% missing, `is_explicit_null_field: true`)
- **No RPC Port Bias:** Fixed Windows RPC listening ports (49664–49669) are not used as malware indicators; remote outbound connections are evaluated based on non-local, non-loopback destinations.

---

## 5. Statistical and Missingness Findings

Every feature was audited for distribution, missingness, and variance across the 45 runs.

### 5.1 Constant / Near-Constant Features Flagged
The following features were identified as invariant or near-invariant in the custom dataset:
1. `cmd_encoded_command_count`, `cmd_hidden_window_count`, `cmd_download_cradle_count`, `cmd_registry_modification_count`: In the custom batch, fileless malware payloads were executed directly in memory via PowerShell ScriptBlocks rather than via CLI flags. These are retained in the dictionary as documented baseline features but flagged for downstream feature selection.
2. `proc_tree_max_depth`: Constant at 6 across all runs due to the standardized Windows 11 base image hierarchy.
3. `proc_temp_directory_count`: Invariant at 0 because the evaluated fileless techniques operated strictly in memory without disk staging in `%temp%`.
4. `net_listening_sockets_count`: Invariant at 17 across runs (standard core Windows services listening sockets).
5. `net_packet_count`, `net_byte_count`, `net_flow_duration_sec`, `net_beacon_periodicity_sec`: Invariant `NULL` due to lack of PCAP.

*Per instructions, these features were NOT automatically deleted, but their invariance is explicitly documented in each modality's `statistics.json`.*

### 5.2 Missingness Summary
- `proc_working_set_bytes_mean` and `proc_cpu_utilization_mean`: Missing in runs where process snapshot was captured after process termination; handled with explicit `None`.
- All PCAP-dependent network fields: Explicitly 100% `None` (`null`).
- All other 71 features: 0.0% missingness across all 45 runs.

---

## 6. Leakage Prevention and Provenance Auditing

Every candidate feature was audited against the leakage criteria specified in Phase 4 instructions:
- **Sample ID / Run ID Leakage:** Verified that no feature column encodes run identifiers or execution timestamps.
- **Label / Family Leakage:** Verified zero embedding of ground truth labels or family strings in feature vectors.
- **Collection Harness Leakage:** Filtered out all operator script activity.
- **Provenance Completeness:** Documented in [`data/features/feature_provenance.json`](file:///c:/Users/Prash/Desktop/Real-Time-Fileless-Malware-Detection/data/features/feature_provenance.json) (77 feature entries with modality, source evidence, aggregation method, and null semantics).
- **Leakage Audit Log:** Recorded in [`data/features/feature_leakage_audit.csv`](file:///c:/Users/Prash/Desktop/Real-Time-Fileless-Malware-Detection/data/features/feature_leakage_audit.csv), confirming all 77 features have `audit_verdict = VERIFIED_SAFE` and `leakage_risk = NONE`.

---

## 7. Run-Level Train / Validation / Test Split

A strict, run-disjoint stratified split was established in [`data/features/splits/`](file:///c:/Users/Prash/Desktop/Real-Time-Fileless-Malware-Detection/data/features/splits/) and documented in [`docs/feature_split_strategy.md`](file:///c:/Users/Prash/Desktop/Real-Time-Fileless-Malware-Detection/docs/feature_split_strategy.md):

| Split | Runs Count | Benign Runs (Label 0) | Malware Runs (Label 1) | Share | Properties |
|---|:---:|:---:|:---:|:---:|---|
| **Train** | **28** | 8 | 20 | 62.2% | Contains representative runs from all 11 malware families |
| **Validation** | **9** | 3 | 6 | 20.0% | Strictly run-disjoint; used for early stopping and threshold calibration |
| **Test** | **8** | 2 | 6 | 17.8% | Held-out benchmark evaluation (includes clean baseline RUN-001) |
| **Total** | **45** | **13** | **32** | **100.0%** | Zero cross-partition overlap |

---

## 8. Verification Test Suite Execution

The dedicated Phase 4 test suite [`tests/test_rich_feature_engineering.py`](file:///c:/Users/Prash/Desktop/Real-Time-Fileless-Malware-Detection/tests/test_rich_feature_engineering.py) was executed:

```
collected 10 items

tests/test_rich_feature_engineering.py::test_01_45_run_coverage_all_modalities PASSED
tests/test_rich_feature_engineering.py::test_02_no_label_or_run_id_in_features PASSED
tests/test_rich_feature_engineering.py::test_03_strict_null_semantics_for_network PASSED
tests/test_rich_feature_engineering.py::test_04_collection_harness_exclusion PASSED
tests/test_rich_feature_engineering.py::test_05_cross_modal_join_integrity PASSED
tests/test_rich_feature_engineering.py::test_06_train_val_test_run_disjointness PASSED
tests/test_rich_feature_engineering.py::test_07_feature_provenance_completeness PASSED
tests/test_rich_feature_engineering.py::test_08_feature_leakage_audit_csv PASSED
tests/test_rich_feature_engineering.py::test_09_command_text_sequences PASSED
tests/test_rich_feature_engineering.py::test_10_dataset_immutability PASSED

============================= 10 passed in 1.08s ==============================
```

---

## 9. Absolute Restrictions Compliance

During Phase 4:
- **NO ML MODELS WERE TRAINED.**
- **NO HYPERPARAMETERS WERE TUNED.**
- **NO MODEL CHECKPOINTS WERE CREATED.**
- **NO PUBLIC DATASETS WERE INTEGRATED.**
- **NO DATASET MODIFICATIONS OCCURRED.**
- **NO LABELS WERE ALTERED.**
- **NO FABRICATED VALUES WERE INTRODUCED.**
- **NO FUSION SYSTEM OR API SERVICE WAS BUILT.**

---

## 10. Final Gate Declaration

```
================================================================================
FINAL VERDICT: PHASE_4_APPROVED_FOR_MODEL_TRAINING
================================================================================
```

The feature engineering layer is complete, semantically faithful, mathematically auditable, free of leakage, and verified across all 45 runs.

All work for Phase 4 is finished. Awaiting human review before proceeding to model training.
