# Training Data Mapping & Future Training Pipeline Specification

**Date:** 2026-09-22  
**Investigation Scope:** Future training pipeline design based strictly on genuine forensic evidence discovered in `Dataset/`.  
**Status:** SPECIFICATION ONLY — NO CODE OR DATA MODIFIED — AWAITING REVIEW.

---

## 1. What Evidence Is Present vs Missing

A complete forensic accounting of the evidence residing in `Dataset/` (45 runs across 12 packages) establishes the following status:

### 1.1 Evidence That Exists and Is Genuine (45/45 Runs)
1. **Sysmon Event Logs (`sysmon.evtx`):**
   - Size: 6.3 MB to 9.5 MB per run.
   - Event Count: 4,600 to 7,800 events per run.
   - Content: Full process creation telemetry (Event ID 1), including Image, CommandLine, ParentCommandLine, CurrentDirectory, Hashes, and User.
2. **PowerShell Operational Event Logs (`powershell.evtx`):**
   - Size: ~15.8 MB per run.
   - Content: Contains ScriptBlock logging (Event ID 4104), Pipeline Execution (Event ID 800), and Provider Lifecycle (Event ID 600). Captures de-obfuscated script blocks and memory-executed scripts.
3. **Volatility 3 Forensic Outputs (`volatility/RUN-xxx/*.txt`):**
   - 11 plugins present for all 45 runs: `pslist`, `psscan`, `pstree`, `threads`, `handles`, `dlllist`, `psxview`, `malfind`, `privileges`, `vadinfo`, `ldrmodules`.
4. **Live OS Process Snapshot (`process_snapshot.csv`):**
   - Process listings with PID, PPID, process name, and thread count captured at run termination.
5. **Live OS Network Snapshot (`network_connections.csv`):**
   - Active socket listing with Protocol, LocalAddress:Port, ForeignAddress:Port, State, PID.
6. **Execution Metadata (`metadata/RUN-xxx.json`):**
   - Exact run ID, ground truth binary label (0 or 1), malware family name, OS version, execution timestamp, and source type.

### 1.2 Evidence That Does NOT Exist
1. **Raw Memory Dumps (`memory.raw` / `memory.dmp`):**
   - Not included in `Dataset/` distribution (retained on hypervisor to keep package size under 1 GB).
2. **PCAP Capture Files (`*.pcap` / `*.pcapng`):**
   - Not present in any of the 45 run directories.

### 1.3 Evidence Requiring Parser Fixes
1. **EVTX Event Extraction (`command_extractor.py`):**
   - Current parser relies on `win32evtlog` COM bindings, which failed and defaulted to static HP strings.
   - **Fix Required:** Replace COM dependency with a pure-Python binary EVTX parser (`evtx` library) to reliably extract Sysmon Event ID 1 (`CommandLine`, `ParentCommandLine`) and PowerShell Event ID 4104 (`ScriptBlockText`).
2. **System Daemon Whitelisting (`memory_extractor.py` & `process_extractor.py`):**
   - Current extractors sum RWX pages and handles globally.
   - **Fix Required:** Filter out `MsMpEng.exe` (Windows Defender), `System` (PID 4), and known CLR JIT allocations to measure only anomalous/payload process space.

---

## 2. Proposed Training Pipeline Mapping Per Modality

### 2.1 PROCESS MODEL

```yaml
PROCESS:
  SOURCE:
    - "volatility/RUN-xxx/pslist.txt"
    - "volatility/RUN-xxx/psscan.txt"
    - "volatility/RUN-xxx/pstree.txt"
    - "volatility/RUN-xxx/handles.txt"
    - "volatility/RUN-xxx/dlllist.txt"
    - "volatility/RUN-xxx/privileges.txt"
    - "process_snapshot.csv"
  EXTRACTOR:
    - "forensics/extraction/process_extractor.py"
    - Filter: Exclude baseline system daemons (System, registry, smss.exe, csrss.exe, wininit.exe, services.exe, lsass.exe, MsMpEng.exe) from privilege and handle anomaly counts.
  FEATURES:
    - total_process_count (int)
    - hidden_process_count (psscan PID not in pslist PID) (int)
    - anomalous_ppid_count (PPID not matching standard Windows parent-child hierarchy) (int)
    - avg_threads_per_process (float)
    - max_threads_in_single_process (int)
    - total_handle_count (excluding MsMpEng.exe) (int)
    - suspicious_dll_count (DLLs loaded from Temp, AppData, or unbacked memory) (int)
    - malfind_process_count (distinct processes with injected code) (int)
    - elevated_privilege_count (SeDebugPrivilege, SeImpersonatePrivilege enabled outside system PIDs) (int)
    - unlinked_dll_count (from ldrmodules InLoad/InInit/InMem inconsistencies) (int)
    - thread_to_process_ratio (engineered: avg_threads / total_processes) (float)
  LABEL:
    - Binary label: 0 (Benign) or 1 (Malware) from metadata/RUN-xxx.json
  TRAINING INPUT:
    - Matrix of 11 numeric features, StandardScaled (zero-leakage fit on train fold).
    - Classifier: XGBoost (XGBClassifier) with StratifiedKFold cross-validation.
```

---

### 2.2 COMMAND MODEL

```yaml
COMMAND:
  SOURCE:
    - "sysmon.evtx" (Event ID 1: Process Creation)
    - "powershell.evtx" (Event ID 4104: ScriptBlock Logging)
  EXTRACTOR:
    - "forensics/extraction/command_extractor.py" (Updated to use binary EVTX parser)
    - Extract: All command lines executed during the sample window; de-obfuscate base64 payloads where present.
  FEATURES:
    - Raw text representation: Concatenated command sequence and ScriptBlock text executed during the run.
    - Numeric NLP features (optional for hybrid head):
        - command_length (int)
        - shannon_entropy (float)
        - is_base64_encoded (0 or 1)
        - has_download_cradle (IWR, WebClient, Net.WebClient, curl) (0 or 1)
        - has_bypass_execution_policy (-ep bypass, -ExecutionPolicy Bypass) (0 or 1)
        - has_hidden_window (-W Hidden, -WindowStyle Hidden) (0 or 1)
        - uses_lolbins (certutil, mshta, regsvr32, rundll32, powershell, wmic, bitsadmin) (0 or 1)
        - registry_persistence_count (Run, RunOnce, Image File Execution Options writes) (int)
  LABEL:
    - Binary label: 0 (Benign) or 1 (Malware) from metadata/RUN-xxx.json
  TRAINING INPUT:
    - Text Model: DistilBERT (distilbert-base-uncased) fine-tuned on actual Sysmon/PowerShell command strings with max_length=256 or 512.
    - Fallback Tabular Head: LightGBM on the 8 numeric NLP/heuristic features.
```

---

### 2.3 NETWORK MODEL

```yaml
NETWORK:
  SOURCE:
    - "network_connections.csv" (Active socket snapshot)
    - "volatility/RUN-xxx/netscan.txt" (Kernel network artifact scan)
    - "sysmon.evtx" (Event ID 3: Network Connection Detected)
  EXTRACTOR:
    - "forensics/extraction/network_extractor.py"
    - Note: Formally remove PCAP dependencies; extract connection events from Sysmon EID 3 and netscan.txt.
  FEATURES:
    - active_connection_count (int)
    - outbound_connection_count (connections to non-loopback, non-private RFC1918 IPs) (int)
    - unique_remote_ips (int)
    - suspicious_port_usage (connections to ports outside 80/443/53 e.g., 4444, 8080, 8443, 9001) (int)
    - non_standard_dns_connections (int)
    - sysmon_network_event_count (Event ID 3 count) (int)
    - listening_port_anomaly_count (listening ports outside standard Windows baseline) (int)
  LABEL:
    - Binary label: 0 (Benign) or 1 (Malware) from metadata/RUN-xxx.json
  TRAINING INPUT:
    - Matrix of 7 genuine socket/Sysmon network features (zero PCAP imputation required).
    - Classifier: LightGBM (LGBMClassifier) or Random Forest.
```

---

### 2.4 MEMORY MODEL

```yaml
MEMORY:
  SOURCE:
    - "volatility/RUN-xxx/vadinfo.txt"
    - "volatility/RUN-xxx/malfind.txt"
    - "volatility/RUN-xxx/ldrmodules.txt"
    - "volatility/RUN-xxx/psxview.txt"
  EXTRACTOR:
    - "forensics/extraction/memory_extractor.py"
    - Filter: Subtract known MsMpEng.exe RWX regions (base range: 14-15 regions) and CLR JIT runtime pages to isolate injected regions.
  FEATURES:
    - rwx_page_count_non_system (RWX pages belonging to non-whitelisted processes) (int)
    - injected_code_regions_non_system (malfind hits excluding MsMpEng.exe) (int)
    - unmapped_executable_pages (VAD regions marked EXECUTE without a mapped file backing) (int)
    - vad_protection_anomaly_count (transitions from PAGE_READWRITE to PAGE_EXECUTE_READWRITE) (int)
    - ldrmodules_inconsistencies (modules missing from InLoadOrder, InMemoryOrder, or InInitializationOrder) (int)
    - yara_shellcode_matches (shellcode preamble patterns e.g., 0xFC, 0xE8 in unmapped VADs) (int)
    - memory_injection_score (weighted composite: malfind * 3 + unmapped * 2 + rwx) (float)
  LABEL:
    - Binary label: 0 (Benign) or 1 (Malware) from metadata/RUN-xxx.json
  TRAINING INPUT:
    - Matrix of 7 cleaned memory features.
    - Classifier: CatBoost (CatBoostClassifier) with depth=3, iterations=100.
```

---

### 2.5 MULTICLASS MODEL

```yaml
MULTICLASS:
  SOURCE:
    - Combined processed features from all 4 modalities across all 33 genuine malware runs in Dataset/.
  FAMILY LABELS (11 Families, 3 samples each):
    - cobalt_strike_beacon: 3 samples
    - empire_framework: 3 samples
    - fileless_ransomware: 3 samples
    - lolbins_abuse: 3 samples
    - memory_only_rat: 3 samples
    - metasploit_memory_payloads: 3 samples
    - powershell_fileless: 3 samples (corrected from 2 after fixing RUN-001 label)
    - process_hollowing: 3 samples
    - reflective_dll_injection: 3 samples
    - registry_resident_malware: 3 samples
    - wmi_malware: 3 samples
  FEATURES:
    - Unified feature vector (Cleaned Process + Cleaned Memory + Genuine Command Text / NLP + Genuine Network).
  REQUIRED MINIMUM CLASS SUPPORT:
    - Notice: With N=3 samples per class, statistical generalization is severely constrained.
    - Training Strategy: Leave-One-Group-Out CV or Leave-One-Out CV across N=33 samples.
    - Augmentation / Benchmark Anchor: Multi-class evaluation must explicitly document small-sample variance or merge with public reference datasets (e.g. CIC-MalMem, CAPE Sandbox) to achieve adequate statistical power.
  TRAINING INPUT:
    - Multi-class classifier: XGBoost (objective="multi:softprob", num_class=11).
```
