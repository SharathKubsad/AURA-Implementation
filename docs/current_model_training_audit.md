# Current Model Training Audit & Data Lineage Analysis

**Date:** 2026-09-22  
**Investigation Scope:** Forensic audit of all five trained models in `models/artifacts/` and `models/multiclass/artifacts/` against `data/processed/unified/unified_dataset.jsonl` and the discovered ground truth evidence in `Dataset/`.  
**Status:** COMPLETE INVESTIGATION — NO MODELS RETRAINED — NO DATA MODIFIED.

---

## 1. Executive Summary & Master Model Audit Table

All five models currently residing in the repository were trained on a unified 45-sample file (`data/processed/unified/unified_dataset.jsonl`, git commit `466a8202fd6e40278e810faa4de7bbc5f362286c`, generated on 2026-09-21). While the codebase implements clean, zero-leakage scikit-learn/XGBoost/CatBoost/LightGBM pipelines, the **underlying feature data suffers from severe forensic disconnects, extractor fallbacks, host baseline contamination, and synthetic defaults**.

| Model | Algorithm | Training Data | Samples (Train/Val/Test) | Input Representation | Training Script | Artifact Location | Data Trust Rating |
|---|---|---|---|---|---|---|---|
| **Process** | XGBoost (`XGBClassifier`) | `data/processed/unified/unified_dataset.jsonl` | 31 train / 7 val / 7 test (45 total) | 11 numeric features (`total_process_count`, `hidden_process_count`, `thread_to_process_ratio`, etc.) | `models/process/train.py` | `models/artifacts/process/` (`model.json`, `metadata.json`) | **LOW** (Host Defender/Worker Process Contamination) |
| **Command** | DistilBERT (`DistilBertForSequenceClassification`) | `data/processed/unified/unified_dataset.jsonl` | 31 train / 7 val / 7 test (45 total) | Raw text tokens from `raw_command_text` (max_length=128) | `models/command/train.py` | `models/artifacts/command/` (`model.safetensors`, `config.json`) | **ZERO / INVALID** (Extractor crashed to fallback; 2 static strings repeated 45 times) |
| **Network** | LightGBM (`LGBMClassifier`) | `data/processed/unified/unified_dataset.jsonl` | 31 train / 7 val / 7 test (45 total) | 15 numeric/indicator features (10 base + 5 missingness indicators) | `models/network/train.py` | `models/artifacts/network/` (`model.txt`, `metadata.json`) | **ZERO / UNINFORMATIVE** (100% idle baseline host ports; 0 PCAP packets) |
| **Memory** | CatBoost (`CatBoostClassifier`) | `data/processed/unified/unified_dataset.jsonl` | 31 train / 7 val / 7 test (45 total) | 9 numeric features (`rwx_page_count`, `injected_code_regions`, `vad_protection_anomaly_count`, etc.) | `models/memory/train.py` | `models/artifacts/memory/` (`model.cbm`, `metadata.json`) | **LOW** (Splits on Windows Defender `MsMpEng.exe` RWX/JIT pages, not malware) |
| **Multiclass** | XGBoost (`XGBClassifier`, Multi-Softprob) | `data/processed/unified/unified_dataset.jsonl` (malware only) | 32 samples across 11 families (LOO-CV) | 38 concatenated features (Process + Memory + Command + Network) | `models/multiclass/train_on_custom.py` | `models/multiclass/artifacts/` (`multiclass_xgboost.json`, `multiclass_metadata.json`) | **ZERO / BROKEN** (9.38% LOO accuracy; N=2-3 per family; garbage-in, garbage-out) |

---

## 2. Individual Model Training Audits

### 2.1 Process Model (XGBoost)

- **Training Script:** `models/process/train.py`
- **Training Dataset:** `data/processed/unified/unified_dataset.jsonl` (and `.csv`)
- **Sample Count:** 45 total (31 train, 7 validation, 7 test)
  - Train: 9 Benign, 22 Malware
  - Val: 2 Benign, 5 Malware
  - Test: 2 Benign, 5 Malware
- **Ground Truth Labels:** Binary (0 = Benign, 1 = Malware).
- **Features / Input Representation:** 11 features:
  - 10 base features: `total_process_count`, `hidden_process_count`, `anomalous_ppid_count`, `avg_threads_per_process`, `max_threads_in_single_process`, `total_handle_count`, `suspicious_dll_count`, `malfind_process_count`, `elevated_privilege_count`, `unlinked_dll_count`.
  - 1 engineered feature: `thread_to_process_ratio = avg_threads_per_process / total_process_count`.
- **Preprocessing:** `StandardScaler` fitted strictly on `X_train`, transforming `X_val` and `X_test`. Zero missing values.
- **Train / Val / Test Split:** Deterministic stratified 70 / 15 / 15 split with `random_state=42`.
- **Model Algorithm & Hyperparameters:**
  - `XGBClassifier` (v3.4.1)
  - `n_estimators=100`, `max_depth=3`, `learning_rate=0.05`, `subsample=0.8`, `colsample_bytree=0.8`, `eval_metric="logloss"`, `random_state=42`.
  - Early stopping enabled on validation set.
- **Artifact Location & Timestamp:** `models/artifacts/process/` (`model.json`, `metadata.json`, `feature_names.json`, `scaler.joblib`, `train_config.json`); generated `2026-09-21T10:11:50Z`.
- **Evaluation Metrics (on Test Set N=7):**
  - Accuracy: **0.8571** (6/7 correct)
  - Precision: **0.8333**
  - Recall: **1.0000** (5/5 malware detected)
  - F1-Score: **0.9091**
  - ROC-AUC: **0.9000**
  - False Positive Rate (FPR): **0.5000** (1 of 2 benign samples falsely flagged as malware)
  - False Negative Rate (FNR): **0.0000**
  - Confusion Matrix: `[[1, 1], [0, 5]]`
- **Data Quality & Forensic Trust Evaluation:**
  - **LOW TRUST**. The process extractor (`forensics/extraction/process_extractor.py`) parses Volatility `pslist.txt`, `psscan.txt`, `pstree.txt`, `handles.txt`, and `dlllist.txt`.
  - While these Volatility text outputs actually exist in `Dataset/`, the extractor aggregates system-wide totals without filtering out background Windows processes.
  - Specifically, `elevated_privilege_count` (which counts `SeDebugPrivilege`, `SeImpersonatePrivilege`, etc.) and `total_handle_count` are dominated by Windows Defender (`MsMpEng.exe`), `svchost.exe`, and `lsass.exe`.
  - The model's 85.7% test accuracy on 7 samples is driven by slight variations in total process count (benign runs had 82-87 processes, malware runs had 88-105 processes due to sandbox instrumentation and payload staging), rather than intrinsic fileless execution indicators.

---

### 2.2 Command Model (DistilBERT)

- **Training Script:** `models/command/train.py`
- **Training Dataset:** `data/processed/unified/unified_dataset.jsonl`
- **Sample Count:** 45 total (31 train, 7 validation, 7 test)
  - Train: 9 Benign, 22 Malware
  - Val: 2 Benign, 5 Malware
  - Test: 2 Benign, 5 Malware
- **Ground Truth Labels:** Binary (0 = Benign, 1 = Malware).
- **Features / Input Representation:**
  - Tokenized text from `raw_command_text`.
  - Max token sequence length: 128 tokens.
- **Preprocessing:** HuggingFace `AutoTokenizer` (`distilbert-base-uncased`), padded and truncated to 128 tokens.
- **Train / Val / Test Split:** Deterministic stratified 70 / 15 / 15 split with `random_state=42`.
- **Model Algorithm & Hyperparameters:**
  - `DistilBertForSequenceClassification` (`transformers 5.17.0`, `torch 2.14.0`)
  - `base_model="distilbert-base-uncased"`, `epochs=3`, `batch_size=4`, `learning_rate=5e-5`, `weight_decay=0.01`, `optimizer="AdamW"`, `device="cpu"`.
- **Artifact Location & Timestamp:** `models/artifacts/command/` (`model.safetensors`, `config.json`, `tokenizer.json`, `vocab.txt`, `metadata.json`); generated `2026-09-21T10:15:52Z`.
- **Evaluation Metrics (on Test Set N=7):**
  - Accuracy: **0.7143** (5/7 correct)
  - Precision: **0.7143**
  - Recall: **1.0000** (5/5 malware detected)
  - F1-Score: **0.8333**
  - ROC-AUC: **0.3000** (Suspiciously inverted ranking)
  - False Positive Rate (FPR): **1.0000** (Both 2 benign test samples falsely classified as malware!)
  - False Negative Rate (FNR): **0.0000**
  - Confusion Matrix: `[[0, 2], [0, 5]]` (Trivial majority classifier predicting 1 for every sample)
- **Data Quality & Forensic Trust Evaluation:**
  - **ZERO TRUST / INVALID / COMPROMISED**.
  - Inspection of `forensics/extraction/command_extractor.py` reveals that it attempted to use `win32evtlog` (Windows Event Viewer COM API) to parse EVTX files. When run in headless environments or on non-Windows/unregistered channels, the extractor failed silently into its `except Exception:` block and substituted hardcoded fallback strings.
  - In `data/processed/unified/unified_dataset.jsonl`, **all 45 samples contain identical or near-identical text**:
    - For 43 samples: `"C:\\Windows\\system32\\cmd.exe /c \"C:\\Program Files\\HP\\HP Touchpoint Analytics Client\\hpatchmonTask.cmd\""`
    - For 2 samples: `"powershell.exe -ExecutionPolicy Bypass -NoProfile"`
  - Even worse, in `Dataset/`, each run actually contains a rich 6.3MB–9.5MB `sysmon.evtx` and a 15.8MB `powershell.evtx` containing genuine PowerShell ScriptBlock logs (Event ID 4104) and Process Creation logs (Event ID 1). **None of this evidence was parsed by the extractor.**
  - DistilBERT was trained on HP diagnostic telemetry strings and learned to output probability > 0.5 for all inputs, yielding an FPR of 1.0000 and ROC-AUC of 0.3000.

---

### 2.3 Network Model (LightGBM)

- **Training Script:** `models/network/train.py`
- **Training Dataset:** `data/processed/unified/unified_dataset.jsonl`
- **Sample Count:** 45 total (31 train, 7 validation, 7 test)
  - Train: 9 Benign, 22 Malware
  - Val: 2 Benign, 5 Malware
  - Test: 2 Benign, 5 Malware
- **Ground Truth Labels:** Binary (0 = Benign, 1 = Malware).
- **Features / Input Representation:** 15 features total:
  - 10 telemetry features: `active_connection_count`, `listening_port_count`, `outbound_connection_count`, `dns_query_count`, `unique_remote_ips`, `avg_interpacket_interval_ms`, `beacon_regularity_score`, `total_bytes_sent`, `total_bytes_received`, `suspicious_port_usage`.
  - 5 missingness indicators: `is_missing_dns_query_count`, `is_missing_avg_interpacket_interval_ms`, `is_missing_beacon_regularity_score`, `is_missing_total_bytes_sent`, `is_missing_total_bytes_received`.
- **Preprocessing:** `SimpleImputer(strategy="constant", fill_value=0.0)` for missing PCAP fields, plus preserved binary missingness indicators.
- **Train / Val / Test Split:** Deterministic stratified 70 / 15 / 15 split with `random_state=42`.
- **Model Algorithm & Hyperparameters:**
  - `LGBMClassifier` (v4.7.0)
  - `n_estimators=100`, `max_depth=3`, `num_leaves=7`, `learning_rate=0.05`, `subsample=0.8`, `colsample_bytree=0.8`, `min_child_samples=3`, `random_state=42`.
- **Artifact Location & Timestamp:** `models/artifacts/network/` (`model.txt`, `metadata.json`, `feature_names.json`, `imputer.joblib`); generated `2026-09-21T10:15:53Z`.
- **Evaluation Metrics (on Test Set N=7):**
  - Accuracy: **0.7143** (5/7 correct)
  - Precision: **0.7143**
  - Recall: **1.0000** (5/5 malware detected)
  - F1-Score: **0.8333**
  - ROC-AUC: **0.5000** (Equivalent to random coin flip)
  - False Positive Rate (FPR): **1.0000** (Both 2 benign test samples falsely classified as malware!)
  - False Negative Rate (FNR): **0.0000**
  - Confusion Matrix: `[[0, 2], [0, 5]]` (Predicts class 1 for all samples)
- **Data Quality & Forensic Trust Evaluation:**
  - **ZERO TRUST / UNINFORMATIVE**.
  - All 5 PCAP-dependent features (`dns_query_count`, `avg_interpacket_interval_ms`, `beacon_regularity_score`, `total_bytes_sent`, `total_bytes_received`) were 100% `null` across all 45 samples because no PCAP files were captured.
  - The remaining 5 socket features came from `network_connections.csv` (or Volatility `netscan.txt`). In all 45 samples, `listening_port_count` is identically **10** (ports 135, 445, 5040, 7680, 49664, 49665, 49666, 49667, 49668, 49669 — standard Windows 11 RPC/SMB baseline).
  - Outbound connection count is 0 or 1 for nearly all samples because the sandbox VMs were isolated from the internet (Host-Only network adapter).
  - With zero variance in socket telemetry and 100% missing PCAP telemetry, LightGBM had zero predictive signal and collapsed to predicting the malware prior for every sample.

---

### 2.4 Memory Model (CatBoost)

- **Training Script:** `models/memory/train.py`
- **Training Dataset:** `data/processed/unified/unified_dataset.jsonl`
- **Sample Count:** 45 total (31 train, 7 validation, 7 test)
  - Train: 9 Benign, 22 Malware
  - Val: 2 Benign, 5 Malware
  - Test: 2 Benign, 5 Malware
- **Ground Truth Labels:** Binary (0 = Benign, 1 = Malware).
- **Features / Input Representation:** 9 features:
  - `rwx_page_count`, `injected_code_regions`, `unmapped_executable_pages`, `vad_protection_anomaly_count`, `ldrmodules_inconsistencies`, `yara_shellcode_matches`, `mean_memory_entropy`, `max_memory_entropy`, `memory_injection_score`.
- **Preprocessing:** Native CatBoost missing value handling (`nan_mode="Min"`).
- **Train / Val / Test Split:** Deterministic stratified 70 / 15 / 15 split with `random_state=42`.
- **Model Algorithm & Hyperparameters:**
  - `CatBoostClassifier` (v1.2.10)
  - `iterations=100`, `depth=3`, `learning_rate=0.05`, `random_seed=42`, `nan_mode="Min"`, `verbose=False`.
- **Artifact Location & Timestamp:** `models/artifacts/memory/` (`model.cbm`, `metadata.json`, `feature_names.json`); generated `2026-09-21T10:15:55Z`.
- **Evaluation Metrics (on Test Set N=7):**
  - Accuracy: **0.8571** (6/7 correct)
  - Precision: **0.8333**
  - Recall: **1.0000** (5/5 malware detected)
  - F1-Score: **0.9091**
  - ROC-AUC: **1.0000**
  - False Positive Rate (FPR): **0.5000** (1 of 2 benign samples falsely flagged as malware)
  - False Negative Rate (FNR): **0.0000**
  - Confusion Matrix: `[[1, 1], [0, 5]]`
- **Data Quality & Forensic Trust Evaluation:**
  - **LOW TRUST / ARTIFACT CONFUSION**.
  - The memory features were parsed from Volatility `vadinfo.txt`, `malfind.txt`, and `ldrmodules.txt`.
  - Forensics inspection shows that `rwx_page_count` across all 45 samples ranges between 19 and 26, and `injected_code_regions` ranges between 17 and 22.
  - Crucially, **14 to 15 of these RWX regions belong to `MsMpEng.exe` (Windows Defender Antivirus Core Engine)**, which allocates RWX pages for its emulation engine. Additional RWX regions belong to .NET Common Language Runtime (CLR) JIT compilation in standard Windows background processes.
  - CatBoost split on micro-variations in the total count of RWX pages (e.g. threshold at > 21.5 pages) rather than identifying specific unmapped injected payloads or shellcode headers.

---

### 2.5 Multiclass Model (XGBoost)

- **Training Script:** `models/multiclass/train_on_custom.py`
- **Training Dataset:** `data/processed/unified/unified_dataset.jsonl` (filtered to `binary_label == 1`)
- **Sample Count:** 32 malware samples across 11 families:
  - `powershell_fileless`: 2 samples
  - `process_hollowing`: 3 samples
  - `memory_only_rat`: 3 samples
  - `registry_resident_malware`: 3 samples
  - `cobalt_strike_beacon`: 3 samples
  - `metasploit_memory_payloads`: 3 samples
  - `wmi_malware`: 3 samples
  - `reflective_dll_injection`: 3 samples
  - `lolbins_abuse`: 3 samples
  - `fileless_ransomware`: 3 samples
  - `empire_framework`: 3 samples
- **Ground Truth Labels:** 11 multiclass labels.
- **Features / Input Representation:** 38 concatenated features across all 4 modalities (10 process, 8 memory, 8 command, 10 network, plus 2 engineered).
- **Validation Strategy:** Leave-One-Out Cross-Validation (LOO-CV) across N=32 samples.
- **Model Algorithm & Hyperparameters:**
  - `XGBClassifier` (`objective="multi:softprob"`, `num_class=11`)
  - `n_estimators=50`, `max_depth=3`, `learning_rate=0.05`, `subsample=0.8`, `colsample_bytree=0.8`, `random_state=42`.
- **Artifact Location & Timestamp:** `models/multiclass/artifacts/` (`multiclass_xgboost.json`, `multiclass_metadata.json`, `label_encoder.json`); generated `2026-09-21T10:15:58Z`.
- **Evaluation Metrics (LOO-CV on N=32):**
  - LOO Accuracy: **0.0938 (9.38%)** (Only 3 of 32 samples correctly classified!)
  - Macro F1-Score: **0.0758**
  - Weighted F1-Score: **0.0781**
  - Per-Class F1-Scores:
    - 9 of 11 families have **F1 = 0.0000** (0% precision, 0% recall)
    - `Memory-only RAT`: F1 = 0.3333 (1 of 3 correct)
    - `Empire Framework`: F1 = 0.5000 (2 of 3 correct)
- **Data Quality & Forensic Trust Evaluation:**
  - **ZERO TRUST / STATISTICALLY UNTENABLE**.
  - A 32-sample dataset split across 11 classes gives an average class support of 2.9 samples per class.
  - Combined with the corrupted Command text (identical HP strings) and uninformative Network features (zero variance), 18 of the 38 input features were pure noise or constants.
  - Multiclass accuracy of 9.38% is approximately equivalent to random guessing (1/11 = 9.09%).

---

## 3. Tracing Data Lineage & Extraction Failure Points

```
[RAW SOURCE EVIDENCE IN DATASET/]
   ├── sysmon.evtx (6-9 MB) ──┐
   ├── powershell.evtx (15 MB)─┤
   ├── process_snapshot.csv ───┼─► [EXTRACTORS (forensics/extraction/)]
   ├── network_connections.csv ┤      ├── process_extractor.py
   └── volatility/RUN-xxx/*.txt┘      ├── memory_extractor.py
                                       ├── command_extractor.py  <-- [FAILED: win32evtlog crash]
                                       └── network_extractor.py  <-- [PCAP missing; netscan constant]
                                              │
                                              ▼
                                   [data/interim/*.json]
                                   (45 files per modality)
                                              │
                                              ▼
                               [tools/build_unified_dataset.py]
                                              │
                                              ▼
                              [data/processed/unified/unified_dataset.jsonl]
                               (45 samples: 13 benign, 32 malware)
                                              │
                                              ▼
                                     [TRAINING SCRIPTS]
                                 ├── models/process/train.py
                                 ├── models/command/train.py
                                 ├── models/network/train.py
                                 ├── models/memory/train.py
                                 └── models/multiclass/train_on_custom.py
                                              │
                                              ▼
                                      [MODEL ARTIFACTS]
                                  (models/artifacts/*)
```

### Detailed Failure Points Identified

1. **Command Extractor Fallback Collapse:**
   - In `forensics/extraction/command_extractor.py`, lines 185–230 attempted to open Windows Event Logs using `win32evtlog.OpenEventLog` or standard COM bindings.
   - When executed without Windows admin privileges or on non-Windows/CI environments, the script caught the exception and defaulted to fallback command strings.
   - The result: Genuine payload executions (e.g. base64-encoded PowerShell download cradles, reflective injection scripts in `sysmon.evtx` Event ID 1) were completely bypassed.
2. **Missing PCAP Features vs Zero-Imputation:**
   - In `forensics/extraction/network_extractor.py`, PCAP reading was implemented via `scapy`. Because no `.pcap` files were included in the VM execution bundles, all 5 flow/timing features (`avg_interpacket_interval_ms`, `beacon_regularity_score`, `total_bytes_sent`, `total_bytes_received`, `dns_query_count`) were returned as `None`.
   - `models/network/train.py` imputed these with `0.0` and added missingness indicator flags. Since every sample was missing PCAP data, the indicator flags were identical constants (1 for all samples), providing zero discriminatory power.
3. **Host Process Contamination in Memory & Process Forensics:**
   - `forensics/extraction/memory_extractor.py` counted all VAD regions with `PAGE_EXECUTE_READWRITE` protection.
   - It did not filter by PID or process image path. Consequently, the 14-15 RWX pages created by `MsMpEng.exe` (Windows Defender) and the JIT allocations from .NET assemblies were counted for every single run.
   - This masked any real difference between benign and malware runs, compressing the dynamic range to 19–26 pages.
4. **Label Misassignment in Previous Unified Build:**
   - In `data/interim/dataset_audit_report.json`, `EXEC_RUN-001` was recorded with `binary_label: 0` and `family: "benign"`, despite belonging to the `custom_powershell_fileless` batch whose metadata (`RUN-001.json`) clearly specifies `"family": "powershell_fileless", "label": 1`.
   - This reduced `powershell_fileless` from 3 samples to 2, and inflated benign from 12 to 13.

---

## 4. Comparison: Evidence in `Dataset/` vs Current Model Training

| Modality | Original Evidence Available in `Dataset/` | Currently Used For Training | Correct Genuine Evidence Available | Identified Problem & Disconnect |
|---|---|---|---|---|
| **PROCESS** | Volatility `pslist.txt`, `psscan.txt`, `pstree.txt`, `threads.txt`, `handles.txt`, `dlllist.txt` (45/45 runs) + `process_snapshot.csv` | Total counts across all processes from Volatility outputs (N=45) | Process features calculated after whitelisting known Windows system daemons (`MsMpEng.exe`, `svchost.exe`, `System`) | System daemons dominate handle and thread counts; models learn background noise rather than malware behavior. |
| **COMMAND** | `sysmon.evtx` (6.3–9.5MB, 4,600–7,800 events) + `powershell.evtx` (15.8MB, ~500 events, EID 4104) (45/45 runs) | Static fallback string (`hpatchmonTask.cmd` & `powershell.exe`) repeated across all 45 samples | Full command lines from Sysmon Event ID 1 and ScriptBlock text from PowerShell Event ID 4104 | The extractor threw an unhandled exception and replaced all genuine commands with 2 diagnostic strings. DistilBERT is completely uncalibrated. |
| **NETWORK** | `network_connections.csv` (45/45 runs) + Volatility `netscan.txt` (45/45 runs). PCAP = **None** | 10 constant baseline listening ports + 5 zero-imputed PCAP metrics | Remote IP counts and active non-loopback outbound connections from `network_connections.csv` | Zero PCAP files exist. Features had zero variance; LightGBM collapsed to majority guessing (ROC-AUC 0.50). |
| **MEMORY** | Volatility `vadinfo.txt`, `malfind.txt`, `ldrmodules.txt` (45/45 runs) | Raw total RWX pages (19-26) and malfind regions (17-22) across entire dump | RWX and injected regions filtered to exclude `MsMpEng.exe` and CLR JIT runtime memory | 70% of measured RWX pages belong to Windows Defender itself. Model split on benign antivirus artifacts. |
| **MULTICLASS** | 11 malware families (3 runs each = 33 total malware runs) | 32 samples across 11 families with corrupted command text and constant network features | Combined clean features from process, memory, command, and network across all 33 malware runs | Inadequate sample size (N=3 per class), 1 class had only 2 samples due to label error; feature inputs were 50% noise/fallbacks. |
