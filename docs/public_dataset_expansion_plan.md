# Public Dataset Expansion Plan (Phase 3)

## 1. Executive Context & Objectives

Following the completion of the CIC-MalMem-2022 public benchmark (Process and Memory modalities) and the Phase 2 custom 45-sample audit, this expansion plan investigates candidate public datasets for scaling the remaining two modalities:
- **COMMAND** (DistilBERT / sequence modeling)
- **NETWORK** (LightGBM / flow and socket modeling)

### Current Baseline Facts:
- **Custom Dataset**: 45 samples (13 Benign, 32 Malware across 11 families).
- **Process & Memory**: Functionally validated on custom telemetry (Process AUC = 0.90; Memory AUC = 1.00) and backed by the 58,596-sample CIC-MalMem-2022 memory forensics benchmark.
- **Command & Network**: Severely starved in the custom VM dataset:
  - Command: Sysmon only captured two ambient background OS commands (ROC-AUC = 0.30).
  - Network: 100% of PCAP-derived packet timing features are missing due to host-only isolation (ROC-AUC = 0.50).

---

## 2. Candidate Priority & Screening

| Candidate | Primary Source | Modalities Evaluated | License / Feasibility Status | Preliminary Screening |
|---|---|---|---|---|
| **1. CAPEv2 Dynamic Analysis Corpus (Avast-CTU / CAPE Community)** | CTU AI Center / Avast Software & CAPE Community | Process, Command, Network | Open Research / Academic citation (arXiv:2209.03188). Public JSON reports. | **ACCEPTED FOR EVALUATION** |
| **2. ANY.RUN Interactive Sandbox** | ANY.RUN Sandbox SaaS | Process, Command, Network | Proprietary ToS. No public downloadable bulk dataset. Automated harvesting prohibited. | **REJECTED (Licensing/Technical ToS)** |
| **3. EMBER / SOREL-20M / BODMAS** | Endgame / Sophos / Georgia Tech | Static PE structure | MIT / CC BY 4.0. No runtime telemetry. | **REJECTED (Zero live telemetry)** |

---

## 3. Deep Dive: CAPEv2 Dynamic Sandbox Benchmark

### 3.1 Official Source & Provenance
- **Dataset**: CAPEv2 Dynamic Sandbox Behavioral Corpus (Avast-CTU Public CAPE Dataset & Standardized CAPEv2 Dynamic Analysis Reports).
- **Publisher**: Czech Technical University (AIC-CTU) & Avast Software / CAPE Sandbox Community.
- **Reference**: Bosansky et al., *"Avast-CTU Public CAPE Dataset"*, arXiv:2209.03188 (2022).
- **License**: Creative Commons Attribution-ShareAlike / Open Academic Research Use with citation.

### 3.2 Intended Modality Coverage
1. **Command Modality**:
   - Source fields: `behavior.processes[].command_line`, `behavior.summary.commands`, `cmdline`.
   - Authentic commands: Raw PowerShell invocations, obfuscated LOLBins, rundll32 parameters, staged execution commands, and clean administrative/system commands.
   - Fully compatible with `CommandAdapter.from_raw_command()`.
2. **Network Modality**:
   - Source fields: `network.tcp`, `network.udp`, `network.dns`, `network.hosts`, `network.domains`.
   - Socket metrics: Outbound connection counts, unique remote IP counts, DNS query counts, suspicious port membership.
   - Compatible with `NetworkAdapter.from_flow_or_sandbox()`.
3. **Process Modality (Secondary / Reference Only)**:
   - Source fields: `behavior.processtree`, `behavior.processes`.
   - Critical Caveat: Measures *cumulative* processes spawned over 60-120 seconds, whereas our live framework evaluates *instantaneous* process list snapshots.
4. **Memory Modality**:
   - **NOT AVAILABLE**. CAPE does not dump complete volatile physical RAM or extract full VAD trees. Memory must remain unmapped (`NOT_COMPARABLE`).

---

## 4. Compatibility & Technical Risks

1. **Cumulative vs. Instantaneous Distortion**:
   - Sandboxes record cumulative telemetry over the full execution window (e.g. 10 spawned processes over 120s), while live forensics takes point-in-time snapshots (e.g. 3 active processes at timestamp $t$).
2. **Class Imbalance / Goodware Scarcity**:
   - Avast-CTU CAPE corpus is 100% malicious. A valid binary detector requires verified benign (goodware) execution traces (from baseline Windows 10/11 system software and standard administrative utilities).
3. **PCAP Missingness Parity**:
   - Summary JSON reports typically omit raw packet streams, meaning `avg_interpacket_interval_ms` and `beacon_regularity_score` will remain null. This faithfully matches the custom-domain missingness profile.
4. **No Synthetic Value Generation**:
   - Unmeasured fields must strictly be mapped to `None` / `null`, never synthetic zeros or artificial medians.

---

## 5. Decision Gates & Acceptance Criteria

To pass the decision gate for public benchmark training and zero-shot evaluation:
1. **Provenance Gate**: Must verify official academic publication, authors, and source URLs.
2. **Licensing Gate**: Must confirm open academic research license permitting ingestion.
3. **Schema Gate**: Must map to canonical `CommandFeatures` and `NetworkFeatures` without fabrication.
4. **Semantic Gate**: Must document cumulative vs. instantaneous transformations.
5. **Quality Gate**: Must contain $\ge 0$ valid benign samples if binary classification is attempted, or be restricted to auxiliary/family classification.
6. **Isolation Gate**: Must maintain strict isolation from custom VM artifacts and CIC-MalMem artifacts.

---
*Plan established in Stage 0 under strict research isolation rules.*
