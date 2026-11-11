# Complete Dataset Structure & Inventory Audit

**Audit Date:** September 22, 2026  
**Audited Location:** `Dataset/` (Root repository directory)  
**Investigation Type:** Non-destructive recursive inventory, artifact classification, and forensic source evidence verification.

---

## 1. Executive Directory Overview & Structure Tree

The `Dataset/` folder contains the unpacked forensic evidence and derived artifacts for **12 experimental batches** comprising **45 unique execution runs** (`RUN-001` through `RUN-1111`).

### Directory Statistics
- **Total Files:** 846 files
- **Total Subdirectories:** 12 top-level batch folders
- **File Extensions Present:**
  - `.txt` (495 files) — Volatility 3 tabular plugin outputs (11 plugins × 45 runs)
  - `.json` (147 files) — Extracted Process/Memory feature models and per-run metadata
  - `.csv` (102 files) — `process_snapshot.csv` (45), `network_connections.csv` (45), and `batch_summary.csv` (12)
  - `.evtx` (90 files) — Raw Windows event logs: `sysmon.evtx` (45) and `powershell.evtx` (45)
  - `.sha256` (12 files) — Batch package SHA-256 checksum manifests

### Complete Directory Tree Archetype

Every batch package follows an identical, standardized layout:

```text
Dataset/
├── custom_benign_batch/                    (12 runs: RUN-1100 to RUN-1111)
│   ├── batch_summary.csv                   [METADATA] Run status, memory sizes, execution notes
│   ├── checksums.sha256                    [METADATA] Cryptographic hashes of all files in batch
│   ├── manifest.json                       [METADATA] Batch definition, pipeline flags, labels
│   ├── memory/                             [EXTRACTED_FEATURES] MemoryFeatures JSONs (RUN-1100.json ... RUN-1111.json)
│   ├── metadata/                           [METADATA] Per-run metadata JSONs (RUN-1100.json ... RUN-1111.json)
│   ├── process/                            [EXTRACTED_FEATURES] ProcessFeatures JSONs (RUN-1100.json ... RUN-1111.json)
│   ├── source_evidence/                    [RAW_SOURCE_EVIDENCE] Live telemetry per run
│   │   ├── RUN-1100/
│   │   │   ├── network_connections.csv     [RAW_SOURCE_EVIDENCE] TCP/UDP socket snapshot via Get-NetTCPConnection
│   │   │   ├── powershell.evtx             [RAW_SOURCE_EVIDENCE] Windows PowerShell Event Log (EID 4104)
│   │   │   ├── process_snapshot.csv        [RAW_SOURCE_EVIDENCE] Running process tree snapshot via Get-Process
│   │   │   └── sysmon.evtx                 [RAW_SOURCE_EVIDENCE] Sysmon Log (EID 1 ProcessCreate, EID 12-14 Reg)
│   │   └── ... (RUN-1101 to RUN-1111)
│   └── volatility/                         [DERIVED_FORENSIC_OUTPUT] Volatility 3 v2.28.0 text outputs
│       ├── RUN-1100/
│       │   ├── dlllist.txt                 [DERIVED_FORENSIC_OUTPUT] Loaded module paths
│       │   ├── handles.txt                 [DERIVED_FORENSIC_OUTPUT] Object handle tables
│       │   ├── ldrmodules.txt              [DERIVED_FORENSIC_OUTPUT] InLoad/InMem/InInit unlinking status
│       │   ├── malfind.txt                 [DERIVED_FORENSIC_OUTPUT] RWX VAD injection candidates & disasm
│       │   ├── privileges.txt              [DERIVED_FORENSIC_OUTPUT] Token security privilege assignments
│       │   ├── pslist.txt                  [DERIVED_FORENSIC_OUTPUT] EPROCESS active process list
│       │   ├── psscan.txt                  [DERIVED_FORENSIC_OUTPUT] Pool-scanned process headers
│       │   ├── pstree.txt                  [DERIVED_FORENSIC_OUTPUT] Process ancestry tree
│       │   ├── psxview.txt                 [DERIVED_FORENSIC_OUTPUT] Multi-source cross-view discrepancy
│       │   ├── threads.txt                 [DERIVED_FORENSIC_OUTPUT] ETHREAD thread counts per process
│       │   └── vadinfo.txt                 [DERIVED_FORENSIC_OUTPUT] Virtual Address Descriptor tree
│       └── ... (RUN-1101 to RUN-1111)
├── custom_cobalt_strike_beacon/             (3 runs: RUN-400, RUN-401, RUN-402)
├── custom_empire_framework/                 (3 runs: RUN-1000, RUN-1001, RUN-1002)
├── custom_fileless_ransomware/              (3 runs: RUN-900, RUN-901, RUN-902)
├── custom_lolbins_abuse/                    (3 runs: RUN-800, RUN-801, RUN-802)
├── custom_memory_only_rat/                  (3 runs: RUN-200, RUN-201, RUN-202)
├── custom_metasploit_memory_payloads/       (3 runs: RUN-500, RUN-501, RUN-502)
├── custom_powershell_fileless/              (3 runs: RUN-001, RUN-002, RUN-003)
├── custom_process_hollowing/                (3 runs: RUN-100, RUN-101, RUN-102)
├── custom_reflective_dll_injection/         (3 runs: RUN-700, RUN-701, RUN-702)
├── custom_registry_resident_malware/        (3 runs: RUN-300, RUN-301, RUN-302)
└── custom_wmi_malware/                      (3 runs: RUN-600, RUN-601, RUN-602)
```

---

## 2. All 45 Runs / Samples Master Table

| run_id | label | family | source | evidence_available |
|:---|:---:|:---|:---|:---|
| `RUN-001` | 0 / 1* | benign / powershell_fileless | `Dataset/custom_powershell_fileless` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-002` | 1 | powershell_fileless | `Dataset/custom_powershell_fileless` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-003` | 1 | powershell_fileless | `Dataset/custom_powershell_fileless` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-100` | 1 | process_hollowing | `Dataset/custom_process_hollowing` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-101` | 1 | process_hollowing | `Dataset/custom_process_hollowing` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-102` | 1 | process_hollowing | `Dataset/custom_process_hollowing` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-200` | 1 | memory_only_rat | `Dataset/custom_memory_only_rat` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-201` | 1 | memory_only_rat | `Dataset/custom_memory_only_rat` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-202` | 1 | memory_only_rat | `Dataset/custom_memory_only_rat` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-300` | 1 | registry_resident_malware | `Dataset/custom_registry_resident_malware` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-301` | 1 | registry_resident_malware | `Dataset/custom_registry_resident_malware` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-302` | 1 | registry_resident_malware | `Dataset/custom_registry_resident_malware` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-400` | 1 | cobalt_strike_beacon | `Dataset/custom_cobalt_strike_beacon` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-401` | 1 | cobalt_strike_beacon | `Dataset/custom_cobalt_strike_beacon` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-402` | 1 | cobalt_strike_beacon | `Dataset/custom_cobalt_strike_beacon` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-500` | 1 | metasploit_memory_payloads | `Dataset/custom_metasploit_memory_payloads` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-501` | 1 | metasploit_memory_payloads | `Dataset/custom_metasploit_memory_payloads` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-502` | 1 | metasploit_memory_payloads | `Dataset/custom_metasploit_memory_payloads` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-600` | 1 | wmi_malware | `Dataset/custom_wmi_malware` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-601` | 1 | wmi_malware | `Dataset/custom_wmi_malware` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-602` | 1 | wmi_malware | `Dataset/custom_wmi_malware` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-700` | 1 | reflective_dll_injection | `Dataset/custom_reflective_dll_injection` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-701` | 1 | reflective_dll_injection | `Dataset/custom_reflective_dll_injection` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-702` | 1 | reflective_dll_injection | `Dataset/custom_reflective_dll_injection` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-800` | 1 | lolbins_abuse | `Dataset/custom_lolbins_abuse` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-801` | 1 | lolbins_abuse | `Dataset/custom_lolbins_abuse` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-802` | 1 | lolbins_abuse | `Dataset/custom_lolbins_abuse` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-900` | 1 | fileless_ransomware | `Dataset/custom_fileless_ransomware` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-901` | 1 | fileless_ransomware | `Dataset/custom_fileless_ransomware` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-902` | 1 | fileless_ransomware | `Dataset/custom_fileless_ransomware` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-1000` | 1 | empire_framework | `Dataset/custom_empire_framework` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-1001` | 1 | empire_framework | `Dataset/custom_empire_framework` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-1002` | 1 | empire_framework | `Dataset/custom_empire_framework` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-1100` | 0 | benign | `Dataset/custom_benign_batch` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-1101` | 0 | benign | `Dataset/custom_benign_batch` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-1102` | 0 | benign | `Dataset/custom_benign_batch` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-1103` | 0 | benign | `Dataset/custom_benign_batch` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-1104` | 0 | benign | `Dataset/custom_benign_batch` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-1105` | 0 | benign | `Dataset/custom_benign_batch` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-1106` | 0 | benign | `Dataset/custom_benign_batch` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-1107` | 0 | benign | `Dataset/custom_benign_batch` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-1108` | 0 | benign | `Dataset/custom_benign_batch` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-1109` | 0 | benign | `Dataset/custom_benign_batch` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-1110` | 0 | benign | `Dataset/custom_benign_batch` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |
| `RUN-1111` | 0 | benign | `Dataset/custom_benign_batch` | sysmon.evtx, powershell.evtx, process_snapshot.csv, network_connections.csv, 11 Volatility txts |

*\*Note on RUN-001:* In `custom_powershell_fileless/manifest.json`, RUN-001 is listed under label 1, but in `unified_dataset.jsonl` it was treated as the benign uninfected baseline for that VM sequence.

---

## 3. Classification of Evidence Artifacts

| Category | File Extension / Name | Count | Classification | Technical Description |
|:---|:---|:---:|:---:|:---|
| **Windows Event Logs** | `sysmon.evtx` | 45 | `RAW_SOURCE_EVIDENCE` | Binary XML EVTX file containing Sysmon Event ID 1 (Process Creation), 12/13/14 (Registry manipulation). Sizes: 6.3MB–9.5MB per run. |
| **PowerShell Event Logs**| `powershell.evtx` | 45 | `RAW_SOURCE_EVIDENCE` | Binary XML EVTX file containing PowerShell operational logs, including Event ID 4104 (ScriptBlockText execution). Size: ~15.8MB per run. |
| **Process Snapshot** | `process_snapshot.csv` | 45 | `RAW_SOURCE_EVIDENCE` | Live CSV snapshot from `Get-Process` containing running process names, IDs, paths, and handles at capture time. |
| **Network Socket Snapshot** | `network_connections.csv` | 45 | `RAW_SOURCE_EVIDENCE` | Live CSV snapshot from `Get-NetTCPConnection` containing local/remote IP addresses, ports, states, and owning PIDs. |
| **Volatility Text Dumps** | `*.txt` | 495 | `DERIVED_FORENSIC_OUTPUT` | Tabular text files output by Volatility 3 plugins (`pslist`, `vadinfo`, `malfind`, etc.) executed against raw memory. |
| **Feature Models (JSON)** | `process/*.json`, `memory/*.json` | 90 | `EXTRACTED_FEATURES` | Extracted numerical and categorical features structured according to Pydantic schemas. |
| **Manifests & Metadata** | `manifest.json`, `metadata/*.json`, `batch_summary.csv`, `checksums.sha256` | 81 | `METADATA` | Package configuration, cryptographic hashes, operator timestamps, and execution validation summaries. |

---

## 4. Modality Evidence Deep-Dive

### 4.1 Memory & Volatility Evidence
- **Raw Memory Dumps (`memory.raw`):** **0 present** in `Dataset/`. Memory dumps were 6.4 GB each and were processed on the Kali sandbox host; textual plugin outputs were extracted and packaged.
- **Volatility Plugin Coverage:** **100% (45/45 runs)** have complete outputs for all 11 plugins: `pslist`, `psscan`, `pstree`, `threads`, `handles`, `dlllist`, `psxview`, `malfind`, `privileges`, `vadinfo`, `ldrmodules`.
- **Finding on Validity:** Volatility plugin files are **completely authentic and uncorrupted**. However, `malfind.txt` and `vadinfo.txt` are heavily populated by Windows Defender (`MsMpEng.exe`) JIT scanning engine buffers (14–15 RWX regions) and .NET CLR JIT stubs (`powershell.exe`) across both benign and malware runs.

### 4.2 Command & Script Evidence
- **Genuine Source Evidence Exists:** Every single run contains `sysmon.evtx` (6MB–9.5MB) and `powershell.evtx` (15.8MB).
- **Available Events:**
  - Sysmon Event ID 1: Between 2,165 and 3,782 process creation events per run, complete with command lines and parent processes.
  - PowerShell Event ID 4104: Between 444 and 501 script blocks executed per run.
- **Why Current Model Used Fallback Data:**
  - The batch extraction environment lacked the native Windows API parser (`win32evtlog`), causing an exception.
  - The fallback ASCII regex failed against the binary EVTX chunk format, finding 0 events.
  - The extractor defaulted to `active_paths[0]` from `process_snapshot.csv`, assigning `"hpatchmonTask.cmd"` or `"powershell.exe"` to all samples.

### 4.3 Network Evidence
- **PCAP Evidence:** **0 PCAP files exist** anywhere in `Dataset/`.
- **Socket Evidence (`network_connections.csv`):** Exactly 45 files exist (1 per run).
- **Finding on Validity:** All 45 files contain exactly 10 listening ports: `135, 139, 445, 5040, 49664, 49665, 49666, 49667, 49668, 49669`. These represent the idle Windows 11 operating system baseline (RPC/SMB daemons). Because the malware operated strictly in memory without opening local server listening sockets, `listening_port_count = 10` has zero discriminative variance. Packet-level features (`dns_query_count`, bytes sent/received, beacon regularity) are genuinely absent and must remain `null`.

### 4.4 Process Evidence
- **Available Evidence:** `pslist.txt`, `psscan.txt`, `pstree.txt`, `threads.txt`, `handles.txt`, `dlllist.txt`, `psxview.txt`, `privileges.txt`, and `process_snapshot.csv` (45/45 runs).
- **Finding on Validity:** Features such as `total_process_count`, `avg_threads_per_process`, and `total_handle_count` are genuine. However, because malware was executed inside a standard Windows 11 desktop VM, background Windows system processes (`svchost.exe`, `explorer.exe`, `EdgeUpdate.exe`, `SearchIndexer.exe`) dominate the total handle and thread counts.
