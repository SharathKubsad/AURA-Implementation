# Virtual Machine Snapshot & Chain-of-Custody Policy (Task A1)

This policy establishes the rules for baseline snapshot creation, post-execution reversion, forensic evidence handling, and chain-of-custody integrity.

---

## 1. Clean Baseline Snapshot Criteria

Before capturing the official clean baseline snapshot (`Clean_Baseline_v1`), the target VM must satisfy:

1. **Operating System Hardening**:
   - All pending Windows/Linux updates completed.
   - Clean shutdown and reboot cycle performed.
2. **Telemetry Verification**:
   - Sysmon service running and actively writing to operational log.
   - PowerShell ScriptBlock (EID 4104) and Transcription logging verified active.
   - Event log buffers flushed (`wevtutil cl`).
3. **Forensic Tools Staged**:
   - `DumpIt.exe` or `winpmem_mini_x64.exe` staged in `C:\ForensicTools\`.
   - Volatility3 symbol tables cached locally to prevent internet access requirements.
4. **Network Verification**:
   - Network adapter confirmed on **Host-Only / Custom Internal Virtual Network**.
   - Static IP assigned (`192.168.100.20` for Windows, `192.168.100.30` for Linux).
   - Zero Internet or LAN connectivity verified.
5. **Hypervisor Controls**:
   - Shared folders, clipboard sharing, and drag-and-drop **disabled**.
6. **Snapshot Naming**:
   - Windows: `Windows_Clean_Baseline_v1`
   - Linux: `Linux_Clean_Baseline_v1`
   - Kali: `Kali_Clean_Baseline_v1`

---

## 2. Reversion Protocol (Zero Residual Contamination)

> [!CAUTION]
> **Strict Single-Sample Execution Rule**:
> No target virtual machine may ever run more than one malware sample or execution test without being reverted. Reversion must occur immediately after memory acquisition and evidence collection.

### Step-by-Step Reversion Cycle:
1. Complete observation window (typically 3–5 minutes).
2. Acquire volatile memory dump using `DumpIt.exe` or LiME.
3. Stop external `tshark` packet capture.
4. Export event logs (`.evtx`, transcripts).
5. Transfer evidence package to host external evidence storage.
6. Record execution metadata in `sandbox/execution-logs/log.csv`.
7. **Revert VM to Clean Baseline**:
   - In hypervisor UI or CLI: `vmrun -T ws revertToSnapshot "target-win11.vmx" Windows_Clean_Baseline_v1`.
8. Confirm baseline restore before initiating the next run.

---

## 3. Storage Sizing & Evidence Requirements

Raw volatile forensic artifacts consume significant disk storage:
- **Windows Memory Dumps**: ~8.2 GB per raw dump (`.raw`).
- **Linux Memory Dumps**: ~4.1 GB per raw dump (`.lime`).
- **Network Captures**: ~10 MB to 200 MB per run (`.pcap`).
- **Event Logs & Transcripts**: ~5 MB to 50 MB per run (`.evtx`, `.txt`).

### Storage Provisioning Recommendation
For 11 families with 3 runs each (approx. 33 execution sessions):
- **Raw Memory Storage Required**: ~250 GB to 300 GB.
- **Location**: External Dedicated Forensic Drive (e.g. `D:\ForensicEvidence\` or `/mnt/forensics/`).
- **Git Exclusion**: Storage paths are strictly excluded via `.gitignore`. Never place `.raw`, `.mem`, or `.pcap` files inside Git repositories.

---

## 4. Evidence Naming Convention & Chain-of-Custody

All forensic artifacts must follow the standardized naming convention tied to the canonical `sample_id` from `data/schemas/`:

```
<sample_id>/
├── <sample_id>_memory.raw          # Volatile memory dump (Track A)
├── <sample_id>_network.pcap        # Promiscuous network packet capture (Track B)
├── <sample_id>_sysmon.evtx         # Windows Sysmon operational event log (Track A/B)
├── <sample_id>_powershell.evtx     # Windows PowerShell operational log (Track B)
├── <sample_id>_transcripts.txt     # PowerShell console transcription output (Track B)
└── <sample_id>_hashes.sha256       # Cryptographic hashes of all evidence files
```

### Chain-of-Custody Verification
Immediately upon acquisition:
1. Compute SHA-256 hashes of all generated evidence files:
   ```powershell
   Get-FileHash -Algorithm SHA256 * > <sample_id>_hashes.sha256
   ```
2. Log the execution row in `sandbox/execution-logs/log.csv`:
   ```csv
   sample_id,family,vm,os,timestamp,operator,sample_sha256,notes
   EXEC_20260913_001,Process Hollowing,Target_Win11,windows_11,2026-09-13T10:30:00Z,Track A,e3b0c44...,Clean baseline revert confirmed
   ```
3. Verify that the SHA-256 hash in the execution log matches the evidence hash before feeding offline extractors.
