# Cross-Dataset Feature Compatibility Audit & Semantics Report

## 1. Executive Summary

Before expanding training sets across heterogeneous sources, this audit determines whether public datasets can legitimately train models whose final evaluation is performed on our custom VM telemetry.

### Key Forensic Findings:
1. **Semantic Divergence Beyond Column Names**: Matching column names frequently conceal profound algorithmic discrepancies. For example, Volatility 2's `psxview` in CIC-MalMem-2022 flags normal terminated/dead processes as 'hidden', whereas our Volatility 3 pipeline explicitly checks `ExitTime` to filter terminated threads.
2. **Unmeasured Feature Gaps**: CIC-MalMem-2022 provides **0% coverage** for parent-child lineage anomalies, token privileges, DLL staging paths, YARA shellcode matches, and page Shannon entropy. Pooling public and custom data would cause zero-variance filtering to drop these exact high-value fileless indicators.
3. **Temporal Mismatch in Sandbox Telemetry (CAPE/Any.Run)**: Sandbox reports record *cumulative* connections and processes over 60-120 seconds, whereas our live framework evaluates *instantaneous* point-in-time system state.

---

## 2. Modality-Level Compatibility Verdicts

| Modality | Verdict | Directly Comparable | Comparable w/ Transform | Proxy / Not Comparable | Critical Forensic Bottleneck |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **PROCESS** | **CONDITIONAL** | 4 | 2 | 4 | MalMem lacks lineage (`anomalous_ppid`), privileges, DLL paths (4/10 features missing). |
| **MEMORY** | **CONDITIONAL** | 2 | 2 | 4 (1 Proxy, 3 Missing) | MalMem lacks raw bytes/entropy and YARA rules (3/8 missing); `vad_protection_anomaly_count` is a `MALMEM_SPECIFIC_PROXY` strictly excluded from zero-shot. |
| **COMMAND** | **CONDITIONAL** | 8 | 1 | 0 | MalMem has 0% command telemetry. CAPE behavioral reports provide authentic strings. |
| **NETWORK** | **CONDITIONAL** | 3 | 4 | 3 | Timing features (`interpacket`, `beacon`) require raw PCAP; JSON summaries omit them. |

---

## 3. Comprehensive Feature Compatibility Matrix (All 36 Features)

### PROCESS Modality Features

| Feature | Status | Our Definition | Public Definition | Extraction Method & Tool | Units | Shift Risk |
| :--- | :---: | :--- | :--- | :--- | :--- | :---: |
| `total_process_count` | **DIRECTLY_COMPARABLE** | Count of unique active processes present in pslist at volatile me... | Count of processes in pslist (MalMem: pslist.nproc; CAPE: len(beh... | Volatility 3 windows.pslist (Custom) vs Volat... | Integer count of active processes | Moderate. Clean |
| `hidden_process_count` | **COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION** | Processes found in psscan/psxview that are missing from pslist ac... | Processes where psxview flags pslist or csrss handles as False (M... | Volatility 3 psscan/psxview with termination ... | Integer count of hidden/unlinked processes | High. Volatilit |
| `anomalous_ppid_count` | **NOT_COMPARABLE** | Count of processes violating core Windows architecture parent-chi... | NOT AVAILABLE in MalMem. In CAPE, derivable by parsing behavior.p... | Volatility 3 pstree graph traversal against a... | Integer count of lineage violations | Severe. 100% mi |
| `avg_threads_per_process` | **DIRECTLY_COMPARABLE** | Mean thread count across all enumerated processes (sum(threads) /... | Mean thread count across pslist (MalMem: pslist.avg_threads).... | Volatility 3 windows.threads / pslist (Custom... | Float (average threads per process) | Low. Threads pe |
| `max_threads_in_single_process` | **NOT_COMPARABLE** | Maximum thread count observed in any single individual process (f... | NOT AVAILABLE in MalMem (only mean was recorded). In CAPE, deriva... | Volatility 3 windows.threads per-PID aggregat... | Integer thread count | High. 100% miss |
| `total_handle_count` | **DIRECTLY_COMPARABLE** | Total count of active Windows kernel object handles open across a... | Total handles open across all processes (MalMem: handles.nhandles... | Volatility 3 windows.handles (Custom) vs Vola... | Integer count of open kernel handles | Moderate. Handl |
| `suspicious_dll_count` | **NOT_COMPARABLE** | Count of loaded DLLs located in user-writable, staging, or tempor... | NOT AVAILABLE in MalMem. MalMem recorded total DLL count (dlllist... | Volatility 3 windows.dlllist with path allowl... | Integer count of suspicious DLL paths | Severe. 100% mi |
| `malfind_process_count` | **COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION** | Count of unique processes containing suspicious executable memory... | Total number of injected memory regions flagged by malfind across... | Volatility 3 windows.malfind distinct PID cou... | Unique process count (Custom) vs Total injection regions count (MalMem) | Moderate. Value |
| `elevated_privilege_count` | **NOT_COMPARABLE** | Count of processes holding high-risk administrative tokens (SeDeb... | NOT AVAILABLE in MalMem. In CAPE, derivable from token privilege ... | Volatility 3 windows.privileges filtering for... | Integer count of elevated processes | Severe. 100% mi |
| `unlinked_dll_count` | **DIRECTLY_COMPARABLE** | Count of modules in ldrmodules where InLoadOrder or InMemoryOrder... | Count of modules not in load list (MalMem: ldrmodules.not_in_load... | Volatility 3 windows.ldrmodules (Custom) vs V... | Integer count of unlinked modules | Low to Moderate |

### MEMORY Modality Features

| Feature | Status | Our Definition | Public Definition | Extraction Method & Tool | Units | Shift Risk |
| :--- | :---: | :--- | :--- | :--- | :--- | :---: |
| `rwx_page_count` | **COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION** | Count of committed memory Virtual Address Descriptor (VAD) region... | Count of memory regions flagged with PAGE_EXECUTE_READWRITE in su... | Volatility 3 windows.vadinfo full VAD tree pa... | Count of RWX memory allocations | Moderate. MalMe |
| `injected_code_regions` | **DIRECTLY_COMPARABLE** | Total count of suspicious injected code regions detected across m... | Total injected regions identified by malfind (MalMem: malfind.nin... | Volatility 3 windows.malfind (Custom) vs Vola... | Integer count of injected code regions | Low. Plugin log |
| `unmapped_executable_pages` | **COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION** | Executable memory regions (PAGE_EXECUTE*) that have no backing fi... | Unique injected executable memory addresses (MalMem: malfind.uniq... | Volatility 3 windows.vadinfo unmapped page pa... | Count of unmapped executable memory regions | Moderate. Custo |
| `vad_protection_anomaly_count` | **MALMEM_SPECIFIC_PROXY** | Count of VAD allocations where current protection differs from in... | Commit charge in injected regions (MalMem: malfind.commitCharge p... | Volatility 3 vadinfo initial vs current prote... | Count of altered protection regions (Custom) vs Binary presence of commit charge in injections (MalMem) | Severe. Incompa |
| `ldrmodules_inconsistencies` | **DIRECTLY_COMPARABLE** | Sum of discrepancies across PEB module lists (InLoadOrder, InMemo... | Sum of not_in_load, not_in_init, and not_in_mem discrepancies (Ma... | Volatility 3 windows.ldrmodules (Custom) vs V... | Integer count of module list inconsistencies | Low. Both measu |
| `yara_shellcode_matches` | **NOT_COMPARABLE** | Count of YARA rule hits on memory VAD allocations using fileless ... | NOT AVAILABLE in MalMem. No YARA scans were executed.... | Volatility 3 windows.vadyarascan (Custom) vs ... | Integer rule match count | Severe. 100% mi |
| `mean_memory_entropy` | **NOT_COMPARABLE** | Average Shannon entropy computed over dumped raw bytes of injecte... | NOT AVAILABLE in MalMem. Raw memory dumps were not preserved in t... | Shannon entropy on raw dumped memory bytes (C... | Float (bits per byte, 0.0 to 8.0) | Severe. 100% mi |
| `max_memory_entropy` | **NOT_COMPARABLE** | Maximum Shannon entropy observed across any single injected memor... | NOT AVAILABLE in MalMem.... | Shannon entropy on raw dumped memory bytes (C... | Float (bits per byte, 0.0 to 8.0) | Severe. 100% mi |

### COMMAND Modality Features

| Feature | Status | Our Definition | Public Definition | Extraction Method & Tool | Units | Shift Risk |
| :--- | :---: | :--- | :--- | :--- | :--- | :---: |
| `raw_command_text` | **DIRECTLY_COMPARABLE** | The authentic string of the command line or PowerShell script blo... | NOT AVAILABLE in MalMem (0% present). In CAPE/Any.Run, available ... | Sysmon Event ID 1 / PowerShell ScriptBlock Ev... | Raw UTF-8 string | Moderate. Sandb |
| `command_length` | **DIRECTLY_COMPARABLE** | Character length of the primary sanitized command string (len(raw... | Derived from command line string length.... | Deterministic string length calculation... | Integer character count | Low. Obfuscated |
| `shannon_entropy` | **DIRECTLY_COMPARABLE** | Shannon entropy of characters within the command line string (sca... | Derived from character frequency distribution of command string.... | Deterministic character entropy calculation... | Float (bits per character, 0.0 to 8.0) | Low. Base64 and |
| `is_base64_encoded` | **DIRECTLY_COMPARABLE** | Boolean indicator (0 or 1) indicating PowerShell base64 execution... | Derived by regex search across command line string.... | BASE64_COMMAND_FLAGS regex matching... | Binary indicator (0 or 1) | Low. Standard P |
| `has_download_cradle` | **DIRECTLY_COMPARABLE** | Boolean indicator (0 or 1) detecting web download cradles (e.g. D... | Derived by regex search across command line string.... | DOWNLOAD_CRADLE_PATTERNS regex matching... | Binary indicator (0 or 1) | Low. Fileless s |
| `has_bypass_execution_policy` | **DIRECTLY_COMPARABLE** | Boolean indicator (0 or 1) detecting PowerShell execution policy ... | Derived by regex search across command line string.... | BYPASS_POLICY_PATTERNS regex matching... | Binary indicator (0 or 1) | Low. Uniform Po |
| `has_hidden_window` | **DIRECTLY_COMPARABLE** | Boolean indicator (0 or 1) detecting stealth window flags (-windo... | Derived by regex search across command line string.... | HIDDEN_WINDOW_PATTERNS regex matching... | Binary indicator (0 or 1) | Low. Standard s |
| `uses_lolbins` | **DIRECTLY_COMPARABLE** | Boolean indicator (0 or 1) detecting execution of Living-off-the-... | Derived by checking executed process binary against LOLBins dicti... | LOLBINS_HIGH_RISK keyword matching... | Binary indicator (0 or 1) | Low. LOLBin bin |
| `registry_persistence_count` | **COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION** | Count of registry modifications targeting persistence keys (Curre... | Registry keys created/modified in sandbox behavior summary (CAPE:... | Sysmon registry auditing + command regex (Cus... | Integer count of persistence registry modifications | Moderate. Sandb |

### NETWORK Modality Features

| Feature | Status | Our Definition | Public Definition | Extraction Method & Tool | Units | Shift Risk |
| :--- | :---: | :--- | :--- | :--- | :--- | :---: |
| `active_connection_count` | **COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION** | Count of active TCP sockets in ESTABLISHED/SYN_SENT state observe... | Count of cumulative TCP connections opened during the 60-120s san... | Instantaneous socket table snapshot (Custom) ... | Integer count of connections | High. Cumulativ |
| `listening_port_count` | **NOT_COMPARABLE** | Count of unique local TCP/UDP ports open in LISTEN/LISTENING stat... | NOT RELIABLY RECORDED in sandbox summaries. Sandboxes focus on ou... | netstat / Get-NetTCPConnection snapshot (Cust... | Integer count of listening ports | High. Defaultin |
| `outbound_connection_count` | **COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION** | Count of network connections directed to remote IP addresses outs... | Count of external outbound TCP/UDP connections (CAPE: len([c for ... | Socket remote address inspection (Custom) vs ... | Integer count of external connections | Moderate. Cumul |
| `dns_query_count` | **DIRECTLY_COMPARABLE** | Count of DNS query resolution events (Sysmon Event ID 22 or PCAP ... | Count of DNS queries resolved during analysis (CAPE: len(network.... | Sysmon DNS logging (Custom) vs Sandbox intern... | Integer count of DNS queries | Low. DNS query  |
| `unique_remote_ips` | **DIRECTLY_COMPARABLE** | Count of distinct external remote IP addresses contacted by the w... | Count of distinct external IP addresses in network summary (CAPE:... | Set of external remote IPs from socket table ... | Integer count of unique external IPs | Low. External I |
| `avg_interpacket_interval_ms` | **NOT_COMPARABLE** | Mean time interval in milliseconds between consecutive network pa... | NOT AVAILABLE in summary JSON. Requires downloading and parsing r... | pyshark / scapy PCAP timing analysis (Custom)... | Float (milliseconds) | Severe. 100% mi |
| `beacon_regularity_score` | **NOT_COMPARABLE** | Score between 0.0 and 1.0 measuring the regularity of periodic C2... | NOT AVAILABLE in summary JSON. Requires raw .pcap packet stream a... | Timing variance analysis on packet timestamps... | Float normalized score [0.0, 1.0] | Severe. 100% mi |
| `total_bytes_sent` | **COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION** | Total bytes transmitted outbound by workload processes.... | Cumulative bytes transmitted (CAPE: available if NetFlow summary ... | PCAP byte count / interface counters (Custom)... | Integer byte count | Moderate. Depen |
| `total_bytes_received` | **COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION** | Total bytes received inbound across workload network connections.... | Cumulative bytes received (CAPE: available if NetFlow summary pre... | PCAP byte count / interface counters (Custom)... | Integer byte count | Moderate. Scale |
| `suspicious_port_usage` | **DIRECTLY_COMPARABLE** | Boolean indicator (0 or 1) indicating connection activity on know... | Traffic targeting known suspicious ports in network.tcp/network.u... | Port membership check against SUSPICIOUS_PORT... | Binary indicator (0 or 1) | Low. Port numbe |

---

## 4. In-Depth Semantic Analysis by Modality

### 4.1 Process Modality (Custom vs CIC-MalMem-2022 vs CAPE)
- **`total_process_count`**: Directly comparable. However, clean Windows 11 22H2 endpoints maintain 70-110 baseline processes due to modern service decoupling (`svchost` per service), whereas MalMem's VirtualBox Windows 10 baseline shows 40-50 processes. A tree model trained on MalMem will learn low process count cutoffs that misclassify clean Windows 11 as anomalous.
- **`hidden_process_count`**: Partial compatibility. In Volatility 2 (`psxview`), deallocated processes that linger in memory pools show as `not_in_pslist=True`. Custom pipeline uses `is_terminated_process(ExitTime)` to eliminate dead processes. MalMem exhibits false-positive hidden processes.
- **`anomalous_ppid_count`, `suspicious_dll_count`, `elevated_privilege_count`**: **Completely unmeasured in MalMem (100% missing)**. In CAPE, these can be derived from process tree and API logs.
- **`malfind_process_count`**: MalMem records `malfind.ninjections` (count of injected regions), whereas custom measures distinct PIDs. Monotonically correlated but MalMem values are an upper bound.

### 4.2 Memory Modality (Custom vs CIC-MalMem-2022)
- **`injected_code_regions` & `ldrmodules_inconsistencies`**: Direct semantic parity. Algorithmically identical across Volatility 2 and Volatility 3.
- **`rwx_page_count` & `unmapped_executable_pages`**: Comparable with documented transformation.
- **`vad_protection_anomaly_count`**: **MALMEM_SPECIFIC_PROXY**. Incompatible semantic definitions. Custom calculates `InitProtection != Protection` (e.g. `VirtualProtect` RW -> RWX). MalMem proxies this via `commitCharge > 0` on injected pages. Strictly excluded from the zero-shot shared feature vector.
- **`mean_memory_entropy`, `max_memory_entropy`, `yara_shellcode_matches`**: **Completely unmeasured in MalMem**. MalMem preserved no raw RAM bytes or YARA scan outputs.

### 4.3 Command Modality (Custom vs CAPE/Any.Run vs MalMem)
- **CIC-MalMem-2022**: Contains **0% command telemetry**. Zero command lines, zero script blocks.
- **CAPE / Any.Run**: Authentic `command_line` strings are recorded in behavioral execution trees. All derived lexical and regex features (`command_length`, `shannon_entropy`, `is_base64_encoded`, `has_download_cradle`, `has_bypass_execution_policy`, `has_hidden_window`, `uses_lolbins`) are **100% directly comparable** via `CommandAdapter.from_raw_command`.
- **`registry_persistence_count`**: Sandbox reports capture API-level `RegSetValueEx` calls. Applying `REGISTRY_PERSISTENCE_PATTERNS` regex filter achieves direct alignment.

### 4.4 Network Modality (Custom vs CAPE/Any.Run)
- **Snapshot vs Cumulative Temporal Divergence**: Custom live collector captures an instantaneous point-in-time socket table snapshot. Sandbox reports aggregate cumulative network activity over the entire 60-120s run.
- **`dns_query_count`, `unique_remote_ips`, `suspicious_port_usage`**: Directly comparable.
- **`listening_port_count`**: Sandboxes rarely record server listening sockets; typically missing or zero in JSON reports.
- **Timing Features (`avg_interpacket_interval_ms`, `beacon_regularity_score`)**: **Not comparable from summary JSON**. Micro-timing calculations require raw `.pcap` packet streams.

---

## 5. Training Strategy Recommendation

### Evaluation of Candidate Strategies:

#### Strategy A: Same-model training on public + custom data (Joint pooled training)
- **Verdict**: **REJECTED**.
- **Rationale**: MalMem contains 58,596 samples; our custom dataset contains 45 samples (ratio > 1,300 : 1). Merging them into a single training matrix forces imputation or dropping of the 4 process features and 3 memory features absent in MalMem. The resulting model would be 99.9% dominated by MalMem's older Windows 10 VirtualBox distribution, discarding the very fileless attack indicators our project is engineered to detect.

#### Strategy B: Public-data training -> custom-data held-out evaluation (Zero-shot domain transfer)
- **Verdict**: **ACCEPTED AS AUXILIARY BENCHMARK**.
- **Rationale**: Legitimate scientific experiment to evaluate out-of-distribution transfer for the shared feature subset (6 Process features, 5 Memory features). However, it cannot serve as the primary fileless detector because it is restricted to coarse counts and blind to memory entropy, privileges, and lineage.

#### Strategy C: Separate domain-specific models
- **Verdict**: **RECOMMENDED**.
- **Rationale**: Maintains complete scientific and forensic integrity:
  1. **Public Benchmark Models**: Trained on public data (CIC-MalMem for Process/Memory; CAPE for Command/Network) and reported against academic literature.
  2. **Real-Time Hybrid Detector**: Trained on our high-fidelity custom VM telemetry with full 4-modality feature vectors.
  3. Neither dataset compromises the feature schema or distribution of the other.

#### Strategy D: Public data used only for auxiliary/pretraining purposes
- **Verdict**: **CONDITIONALLY ACCEPTABLE**.
- **Rationale**: Useful for tabular representations or neural networks (e.g. DistilBERT command pretraining), but offers minimal benefit for gradient boosted trees (XGBoost/CatBoost) compared to clean model separation.

---

## 6. Identified Risks & Mitigation Protocols

1. **Risk: Volatility 2 Dead Process Inversion**: MalMem's `psxview.not_in_pslist` includes terminated dead processes.
   - *Mitigation*: Never evaluate a model trained on MalMem against custom data without documenting this bias.
2. **Risk: Missing Feature Dropping**: Zero-variance filtering on pooled data would delete `anomalous_ppid_count` and `mean_memory_entropy`.
   - *Mitigation*: Keep public and custom training pipelines strictly separated (Strategy C).
3. **Risk: Cumulative Sandbox Bias**: CAPE network counts exceed snapshot counts.
   - *Mitigation*: When ingesting sandbox telemetry, apply duration-normalized rates rather than raw counts.
