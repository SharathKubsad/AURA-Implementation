# Public Benchmark Datasets Investigation & Ingestion Specification

## 1. Executive Summary

This document establishes the technical, forensic, and compatibility analysis of public candidate datasets for the **Real-Time Fileless Malware Detection** project. 

### Core Scientific Findings:
1. **No Monolithic 4-Modality Public Dataset Exists**: In contemporary cybersecurity research, no single public repository captures all four target modalities (**Process**, **Command**, **Network**, and **Memory**) simultaneously for the same execution.
   - Datasets created via volatile memory dumps (e.g., CIC-MalMem-2022) provide structured Volatility outputs (**Process** and **Memory**), but omit execution command strings and network packet captures.
   - Datasets created via dynamic sandbox execution (e.g., Any.Run, CAPEv2, Hybrid Analysis) provide rich **Command** and **Network** traces, but omit full multi-gigabyte volatile RAM memory images.
   - Static datasets (e.g., EMBER, SOREL-20M) provide only Portable Executable (PE) file structure and byte headers, completely lacking live runtime telemetry.
2. **Modality-Isolated Ingestion**: Because our detector architecture relies on four independent specialized models (`ProcessModel`, `CommandModel`, `NetworkModel`, `MemoryModel`), public data must be ingested through **modality-isolated adapters** preserving strict provenance, without synthetic data fabrication.

---

## 2. Comprehensive Candidate Dataset Evaluations

---

### Candidate 1: CIC-MalMem-2022 (Obfuscated Malware Memory Dataset)
- **Official Source**: Canadian Institute for Cybersecurity (CIC) / University of New Brunswick (UNB)
- **URL**: `https://www.unb.ca/cic/datasets/malmem-2022.html`
- **Citation**: Carrier, T., et al. (2022). "Detecting Obfuscated Malware using Memory Feature Engineering." *Proceedings of the 8th International Conference on Information Systems Security and Privacy (ICISSP 2022)*.
- **License**: Creative Commons / Open Access for academic research with attribution.
- **Total Sample Count**: **58,596** memory feature vectors
- **Benign / Malware Distribution**:
  - Benign: **29,298** (50.0%)
  - Malware: **29,298** (50.0%)
- **Malware Families & Categories**:
  - **Spyware** (10,020 samples): 192.com, Gator, Transponder, TIBS
  - **Ransomware** (9,791 samples): Ako, Conti, Phorpiex, Shade, WannaCry
  - **Trojan Horse** (9,487 samples): Emotet, Zeus, Reconyc, Refroso
- **Operating System**: Windows 10 x64
- **Modality Telemetry Breakdown**:
  - **Process Telemetry**: **YES**. Features from `pslist`, `pstree`, `psxview`, `dlllist`, `handles`.
  - **Memory Telemetry**: **YES**. Deep forensic features from `malfind` (injected code, protection flags, vad anomalies), `ldrmodules` (unlinked DLLs).
  - **Command Telemetry**: **NO**. Does not record raw command-line text (`raw_command_text`).
  - **Network Telemetry**: **NO**. Does not capture network sockets, DNS queries, or PCAP timing.
- **Raw Format**: CSV containing 55 extracted Volatility forensic features.
- **Label Granularity**: Binary (`Benign` vs `Malware`) and Multi-class (`Category` and `Family`).
- **Schema Mapping**:
  - Maps to `ProcessFeatures` via `ProcessAdapter.from_malmem()`.
  - Maps to `MemoryFeatures` via `MemoryAdapter.from_malmem()` (memory entropy preserved as `null`).
- **Limitations**: Completely lacks command lines and network telemetry; does not compute Shannon entropy on memory pages.
- **Classification**: **PARTIALLY_COMPATIBLE** (Process & Memory modalities only).

---

### Candidate 2: EMBER 2018 (Elastic Malware Benchmark for Emerging Research)
- **Official Source**: Endgame / Elastic Security
- **URL**: `https://github.com/elastic/ember`
- **Citation**: Anderson, H. S., & Roth, P. (2018). "EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models." *arXiv:1804.04159*.
- **License**: MIT License.
- **Total Sample Count**: **1,100,000** PE files (900,000 train, 200,000 test).
- **Benign / Malware Distribution**: 400,000 Benign, 400,000 Malware, 300,000 Unlabeled.
- **Operating System**: Windows PE32/PE32+ binaries.
- **Modality Telemetry Breakdown**:
  - **Process Telemetry**: **NO**.
  - **Command Telemetry**: **NO**.
  - **Network Telemetry**: **NO**.
  - **Memory Telemetry**: **NO**.
- **Raw Format**: JSONL containing parsed static PE format representations (byte histograms, section names, imported API symbols).
- **Schema Mapping**: **CANNOT MAP**. Mapping static PE header attributes to dynamic volatile memory or Sysmon telemetry would require fabricating live runtime signals.
- **Classification**: **INCOMPATIBLE** (Static PE structure only, zero runtime telemetry).

---

### Candidate 3: SOREL-20M (Sophos-ReversingLabs 20 Million PE Dataset)
- **Official Source**: Sophos AI & ReversingLabs
- **URL**: `https://github.com/sophos-ai/SOREL-20M`
- **Citation**: Harang, R., et al. (2020). "SOREL-20M: A Large Scale Benchmark Dataset for Malicious PE Detection." *arXiv:2012.07634*.
- **License**: Creative Commons Attribution 4.0 International (CC BY 4.0).
- **Total Sample Count**: **20,000,000** PE samples.
- **Benign / Malware Distribution**: Approximately 9.2 million malware binaries with multi-label tag attributes.
- **Modality Telemetry Breakdown**: Static PE metadata, disassembly counts, and neural network feature embeddings.
  - Process: None
  - Command: None
  - Network: None
  - Memory: None
- **Schema Mapping**: **CANNOT MAP**. Lacks all runtime and forensic signals.
- **Classification**: **INCOMPATIBLE** (Static PE format).

---

### Candidate 4: MalwareBazaar / VX-Underground / VirusShare
- **Official Source**: abuse.ch, VX-Underground, VirusShare.com
- **URLs**: `https://bazaar.abuse.ch/`, `https://vx-underground.org/`
- **License**: Open sharing for security research and law enforcement.
- **Nature**: Repositories of live, unexecuted malware binaries and hashes.
- **Modality Telemetry Breakdown**:
  - Zero pre-extracted runtime telemetry.
  - Requires active execution in a sandbox VM to produce telemetry.
- **Schema Mapping**: Pre-extracted feature ingestion is impossible because no runtime feature vectors are published with the binaries.
- **Classification**: **INCOMPATIBLE** as a pre-extracted telemetry dataset (Useful strictly as a raw sample source for manual sandbox execution).

---

### Candidate 5: CAPEv2 & Any.Run Sandbox Behavioral Corpus
- **Official Source**: Any.Run Interactive Sandbox / CAPEv2 Community Submissions
- **Citation**: CAPE Sandbox Open Source Community & Any.Run public execution sandbox.
- **License**: Terms of Service / Community research data.
- **Total Sample Count**: 100,000+ public dynamic sandbox runs.
- **Operating System**: Windows 7, Windows 10, Windows 11.
- **Modality Telemetry Breakdown**:
  - **Process Telemetry**: **YES** (Spawned process tree, parent-child PID hierarchy, injection events).
  - **Command Telemetry**: **YES** (Actual command lines, PowerShell script blocks, LOLBins arguments).
  - **Network Telemetry**: **YES** (TCP/UDP socket connections, HTTP requests, DNS query logs).
  - **Memory Telemetry**: **NO** (Lacks full volatile RAM memory dumps; does not provide Volatility VAD/malfind metrics).
- **Raw Format**: JSON execution reports.
- **Schema Mapping**:
  - Maps to `CommandFeatures` via `CommandAdapter.from_sandbox_report()` (authentic `raw_command_text`).
  - Maps to `NetworkFeatures` via `NetworkAdapter.from_flow_or_sandbox()`.
  - Maps to `ProcessFeatures` via `ProcessAdapter.from_behavioral()`.
- **Classification**: **PARTIALLY_COMPATIBLE** (Process, Command, and Network modalities).

---

### Candidate 6: BODMAS Malware Dataset
- **Official Source**: Georgia Tech / Stony Brook University
- **Citation**: Yang, L., et al. (2021). "BODMAS: An Open Dataset for Learning based Temporal Analysis of PE Malware." *IEEE Transactions on Dependable and Secure Computing*.
- **Sample Count**: 57,293 malware and 13,912 benign PE files.
- **Nature**: PE binary static features with curated timestamp metadata.
- **Classification**: **INCOMPATIBLE** (Static PE structure only).

---

### Candidate 7: CIC-IDS-2017 / CTU-13 (Network Flow Benchmark)
- **Official Source**: Canadian Institute for Cybersecurity / Stratosphere IPS
- **Sample Count**: Millions of network flow records.
- **Modality Telemetry Breakdown**:
  - Network: **YES** (NetFlow / PCAP flow attributes).
  - Process: **NO**.
  - Command: **NO**.
  - Memory: **NO**.
- **Classification**: **PARTIALLY_COMPATIBLE** (Network modality only).

---

## 3. Dataset Compatibility Summary Table

| Dataset | Primary Focus | Process | Command | Network | Memory | Compatibility Classification | Recommended Ingestion Target |
|---|---|:---:|:---:|:---:|:---:|:---:|---|
| **CIC-MalMem-2022** | Volatile Memory Forensics | ✅ | ❌ | ❌ | ✅ | **PARTIALLY_COMPATIBLE** | Scale Process (XGBoost) & Memory (CatBoost) |
| **Any.Run / CAPEv2** | Dynamic Sandbox Execution | ✅ | ✅ | ✅ | ❌ | **PARTIALLY_COMPATIBLE** | Scale Command (DistilBERT) & Network (LightGBM) |
| **EMBER 2018** | Static PE Headers | ❌ | ❌ | ❌ | ❌ | **INCOMPATIBLE** | Reject (Avoid static file bias) |
| **SOREL-20M** | Static PE Embeddings | ❌ | ❌ | ❌ | ❌ | **INCOMPATIBLE** | Reject (No live telemetry) |
| **BODMAS** | Static PE Temporal Data | ❌ | ❌ | ❌ | ❌ | **INCOMPATIBLE** | Reject (No live telemetry) |
| **MalwareBazaar** | Raw Binary Repository | ❌ | ❌ | ❌ | ❌ | **INCOMPATIBLE** (for telemetry) | Raw execution source only |
| **CIC-IDS-2017** | Network Flows | ❌ | ❌ | ✅ | ❌ | **PARTIALLY_COMPATIBLE** | Network-only reference |

---

## 4. Ingestion & Provenance Architecture

All public samples ingested into the repository must adhere to the following directory layout:
```
data/
├── raw/public/             # Raw downloaded CSV/JSON source records (gitignored)
├── interim/public/         # Per-modality extracted public features (gitignored)
│   ├── process/
│   ├── memory/
│   ├── command/
│   └── network/
└── processed/public/       # Standardized public benchmark datasets + manifests (DVC-tracked)
    ├── public_dataset_manifest.json
    ├── public_compatibility_report.json
    └── public_benchmark_dataset.jsonl
```

### Provenance Tracking Record (`PublicProvenance`):
Every public sample maintains an immutable provenance header:
- `original_dataset`: Source name (`CIC-MalMem-2022`, `AnyRun-Sandbox-Corpus`).
- `original_sample_id`: Original identifier/index in public source.
- `original_label`: Exact label string in source (`Benign`, `Spyware-Gator`, etc.).
- `original_family`: Malware family if provided.
- `source_reference`: Official publication DOI or URL.
- `available_modalities`: Explicit subset of `["process", "command", "network", "memory"]`.
- `mapping_method`: Documented schema translation method.
- `checksum`: Cryptographic hash (SHA256) of raw record.
