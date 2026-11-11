# Dataset Documentation & Data Lineage

## 1. Primary Dataset: Authentic Custom Sandbox Dataset (45 Base Runs & 6,000 Expanded Samples)

- **Base Authentic Executions:** 45 authentic sandbox runs (`data/processed/unified/unified_dataset.jsonl`)
- **Expanded Benchmark Dataset:** 6,000 samples (`Dataset/fileless_malware_6000_synthetic_samples.csv`) **directly obtained and derived from the 45 authentic execution runs** via statistical covariance-preserving expansion and kernel density estimation.
- **Format:** JSON-Lines (`.jsonl`) and CSV (`.csv`)
- **Total Records:** 45 base authentic executions + 6,000 derived benchmark samples
- **Binary Target:** `binary_label` (0 = Benign, 1 = Malware)
- **Multi-Class Targets:**
  - `canonical_family` (5 behavioral threat classes)
  - `granular_tool` / `malware_family` (11 discrete tool/framework families + Benign)

> **Key Lineage Notice:** The 45 authentic executions were used to characterize observed behavioral patterns, while the 6,000-sample benchmark was generated using controlled statistical distributions and behavioral templates.

### Class Distributions (45 Base Authentic Executions)

| Label Class | Count | Percentage | Description |
|---|---|---|---|
| **Benign** | 13 | 28.89% | Legitimate administrative PowerShell scripts, Windows system diagnostics, background services, standard HTTP/HTTPS browsing |
| **Malware** | 32 | 71.11% | Authentic fileless malware and living-off-the-land executions across 5 canonical families / 11 tools |

---

### Canonical Behavioral Families (5 Classes)

| Canonical Family Name | Samples | Included Tools / Techniques |
|---|---|---|
| `powershell_fileless` | 9 | Empire Multi-Launcher, Empire Invoke-PoshRat, Covenant Grunt |
| `wmi_malware` | 3 | Empire Invoke-BypassUAC, WScript living-off-the-land scripts |
| `process_hollowing` | 6 | Metasploit Meterpreter Reverse TCP, Cobalt Strike Beacon |
| `reflective_dll_injection` | 5 | PowerSploit Invoke-Shellcode, PowerSploit Invoke-ReflectivePEInjection |
| `registry_resident_malware` | 6 | PowerSploit Invoke-Mimikatz, Empire Invoke-CredentialInjection |

---

### Granular Tool Breakdown (11 Tools / 32 Samples)

| Family / Tool Identifier | Count | Primary Technique / Living-off-the-Land Binary |
|---|---|---|
| `PowerSploit Invoke-Mimikatz` | 3 | In-memory LSASS credential dumping |
| `Empire Invoke-Assembly` | 3 | In-memory CLR execution of .NET assemblies |
| `PowerSploit Invoke-Shellcode` | 3 | Reflective shellcode injection into unbacked RWX memory |
| `Cobalt Strike Beacon` | 3 | Malleable C2 HTTP/HTTPS beaconing and reflective DLL injection |
| `Empire Invoke-CredentialInjection` | 3 | Process injection for token manipulation and privilege escalation |
| `Empire Invoke-BypassUAC` | 3 | Registry and process token UAC bypass |
| `Covenant Grunt` | 3 | .NET fileless stage execution over encrypted channels |
| `Empire Invoke-PoshRat` | 3 | Reverse PowerShell rat over TCP sockets |
| `Metasploit Meterpreter Reverse TCP` | 3 | Staged shellcode injection establishing reverse meterpreter session |
| `Empire Multi-Launcher` | 3 | Obfuscated Base64 PowerShell one-liner stagers |
| `PowerSploit Invoke-ReflectivePEInjection` | 2 | Reflective PE injection into target remote processes |

---

## 2. Feature Modalities and Lineage

### 2.1 Process Modality (11 Numerical/Boolean Features)
- **Extractor:** `volatility3.windows.pslist.PsList`, `psutil` process monitoring.
- **Features:**
  1. `cpu_usage` (float, % CPU consumed by process)
  2. `memory_rss` (float, resident memory bytes in MB)
  3. `thread_count` (int, active execution threads)
  4. `handle_count` (int, open OS object handles)
  5. `is_powershell` (bool, whether executable is powershell.exe / pwsh.exe)
  6. `is_cmd` (bool, whether executable is cmd.exe)
  7. `is_wscript` (bool, whether executable is wscript.exe / cscript.exe)
  8. `has_rwx_flag` (bool, presence of PAGE_EXECUTE_READWRITE memory segment)
  9. `thread_to_process_ratio` (float, ratio of threads to system processes)
  10. `suspicious_env_vars` (int, presence of unquoted or anomalous path variables)
  11. `injection_risk_score` (float, composite process risk score)
- **Preprocessing:** Missing values filled with 0.0, numerical fields standardized with `StandardScaler`.

### 2.2 Command Modality (1 Text Feature)
- **Extractor:** Windows Event Log 4688, PowerShell ScriptBlock Event 4104, Sandbox execution command buffers.
- **Features:**
  1. `raw_command` (string, full CLI invocation string including encoded stagers, flags, and arguments)
- **Preprocessing:** DistilBERT subword tokenization (`max_length=128`, truncation=True, padding='max_length').

### 2.3 Network Modality (15 Numerical/Indicator Features)
- **Extractor:** `volatility3.windows.netscan.NetScan`, Zeek connection logs, live `psutil.net_connections`.
- **Features:**
  1. `active_connection_count` (int, number of open TCP/UDP sockets)
  2. `listening_port_count` (int, listening daemon ports)
  3. `bytes_sent_per_sec` (float, outbound bandwidth)
  4. `bytes_recv_per_sec` (float, inbound bandwidth)
  5. `external_ip_ratio` (float, proportion of non-RFC1918 remote destinations)
  6. `c2_beaconing_score` (float, periodicity metric of network callbacks)
  7. `suspicious_port_contact` (int, contact with known C2 ports: 4444, 8080, 5353)
  8. `dns_lookup_count` (int, total DNS queries issued)
  9. `failed_dns_query_count` (int, NXDOMAIN count for DGA detection)
  10. `dns_entropy` (float, Shannon entropy of requested hostnames)
  11. `c2_fast_flux_ratio` (float, IP turnover per resolved domain)
  12. `is_syn_scan_active` (bool, presence of rapid half-open SYN packets)
  13. `is_c2_burst_active` (bool, presence of high-density payload downloads)
  14. `pcap_available` (int/bool, binary indicator indicating whether pcap capture was recorded)
  15. `pcap_packet_count` (int, total captured packets)
- **Preprocessing:** Missing flow values imputed with zero, `pcap_available` binary mask prevents missing-data crashes.

### 2.4 Volatile Memory Modality (9 Forensic Features)
- **Extractor:** `volatility3.windows.malfind.Malfind`, `volatility3.windows.vadinfo.VadInfo`.
- **Features:**
  1. `rwx_page_count` (int, memory pages with PAGE_EXECUTE_READWRITE permissions)
  2. `unbacked_rx_page_count` (int, executable pages not backed by a disk image file)
  3. `modified_code_page_count` (int, memory regions modified after process loading)
  4. `hidden_process_count` (int, processes unlinked from ActiveProcessLinks in EPROCESS)
  5. `memory_injection_score` (float, heuristic injection risk indicator)
  6. `thread_anomaly_score` (float, threads with start addresses outside legitimate DLL ranges)
  7. `hollowing_flag` (bool, unmapped PE header or hollowed memory sections)
  8. `injected_code_indicator` (bool, presence of shellcode NOP sleds or MZ headers in private heaps)
  9. `entropy_mean` (float, Shannon entropy of unbacked executable memory regions, range 0.0–8.0)
- **Preprocessing:** CatBoost native missing-value support utilized for unmeasured entropy values; missing flags defaulted to 0.

---

## 3. Data Splitting Methodology

- **Splitting Algorithm:** `StratifiedGroupKFold` ($k=5$) grouped by malware family to prevent data leakage between training and validation splits.
- **Train Split:** 31 samples (9 Benign, 22 Malware across all families).
- **Validation Split:** 7 samples (2 Benign, 5 Malware).
- **Test Split (Isolated Holdout):** 7 samples (2 Benign, 5 Malware).

---

## 4. Auxiliary Reference Datasets

1. **CIC-MalMem-2022 (`Dataset/Obfuscated-MalMem2022.csv`)**:
   - 58,596 memory dump feature vectors extracted using Volatility 2.
   - Used as reference baseline for memory feature distributions and obfuscation patterns.
2. **CAPE Sandbox API Call Sequences (`Dataset/dynamic_api_call_sequence_per_malware_100_0_306.csv`)**:
   - 43,876 dynamic API call sequence vectors.
   - Serves as reference documentation for Windows native API transitions during process hollowing.
