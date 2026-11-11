# Telemetry & Logging Plan (Task A1)

This document establishes the logging architecture, event telemetry configurations, and artifact export protocols required to populate the four feature modalities.

---

## 1. Modality-to-Log Mapping

Every execution session produces artifacts mapped to the feature contracts defined in `data/schemas/`:

```
┌─────────────────┬───────────────────────────────┬────────────────────────────────────────────┐
│ Modality        │ Primary Telemetry Source      │ Key Fields Extracted                       │
├─────────────────┼───────────────────────────────┼────────────────────────────────────────────┤
│ Process         │ Sysmon Event ID 1             │ CommandLine, ParentCommandLine, PPID,      │
│ (Track A)       │ Sysmon Event ID 7, 8, 10      │ ImageLoaded, Hashes, TargetProcessAddress  │
│                 │ Volatility3 pslist / pstree   │ Process tree, hidden PIDs, handle count    │
├─────────────────┼───────────────────────────────┼────────────────────────────────────────────┤
│ Command         │ PowerShell Event ID 4104      │ ScriptBlockText (raw NLP representation),   │
│ (Track B)       │ PowerShell Transcription Logs │ decoded command lines, execution policy    │
│                 │ Sysmon Event ID 1             │ Shannon entropy, base64 flags, LOLBins     │
├─────────────────┼───────────────────────────────┼────────────────────────────────────────────┤
│ Network         │ Sysmon Event ID 3             │ SourceIp, DestinationIp, DestinationPort   │
│ (Track B)       │ tshark packet capture (.pcap) │ Inter-arrival deltas, DNS queries, bytes   │
│                 │ Volatility3 netscan           │ Socket states at dump time                 │
├─────────────────┼───────────────────────────────┼────────────────────────────────────────────┤
│ Memory          │ Volatility3 vadinfo / malfind │ RWX pages, unmapped executable memory      │
│ (Track A)       │ Memory acquisition (.raw)     │ Page entropy, YARA shellcode matches       │
└─────────────────┴───────────────────────────────┴────────────────────────────────────────────┘
```

---

## 2. Windows Endpoint Logging Configuration

### 2.1 Sysmon Configuration (`sysmon_config.xml`)
Sysmon must be installed using a schema tuned for fileless indicators:
```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- Process Create: Log all command lines and parent PIDs -->
    <RuleGroup name="ProcessCreate" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="is not">""</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- Network Connect: Log outbound socket activity -->
    <RuleGroup name="NetworkConnect" groupRelation="or">
      <NetworkConnect onmatch="include">
        <DestinationPort condition="is not">0</DestinationPort>
      </NetworkConnect>
    </RuleGroup>

    <!-- Image Load: Focus on abnormal AppData or unlinked DLLs -->
    <RuleGroup name="ImageLoad" groupRelation="or">
      <ImageLoad onmatch="include">
        <ImageLoaded condition="contains">AppData</ImageLoaded>
        <ImageLoaded condition="contains">Temp</ImageLoaded>
      </ImageLoad>
    </RuleGroup>

    <!-- CreateRemoteThread: Injection detection -->
    <RuleGroup name="CreateRemoteThread" groupRelation="or">
      <CreateRemoteThread onmatch="exclude"/>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

### 2.2 PowerShell Deep Auditing
1. **ScriptBlock Logging (EID 4104)**: Logs the full, de-obfuscated content of PowerShell code blocks upon execution, neutralizing multi-layer encoding or dynamic code generation.
2. **Transcription Logging**: Automatically streams all console input and output into standardized text files on disk:
   - Target Directory: `C:\ForensicEvidence\Transcripts\`
   - Format: `<Date>_<Time>_<PID>_transcript.txt`

---

## 3. Linux Endpoint Logging (`auditd`)

On the Ubuntu Linux target, the audit subsystem captures process lifecycle and socket activity:
```text
# Process execution monitoring
-a always,exit -F arch=b64 -S execve -k exec_log
-a always,exit -F arch=b32 -S execve -k exec_log

# Network socket creation
-a always,exit -F arch=b64 -S connect -k net_connect

# Memory injection & anonymous execution
-a always,exit -F arch=b64 -S memfd_create -k fileless_mem
-a always,exit -F arch=b64 -S ptrace -k proc_injection
```

---

## 4. Telemetry Export & Storage

At the conclusion of an execution window:
1. **Event Export**:
   - Sysmon operational log: `wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\ForensicEvidence\<sample_id>_sysmon.evtx`
   - PowerShell log: `wevtutil epl "Microsoft-Windows-PowerShell/Operational" C:\ForensicEvidence\<sample_id>_powershell.evtx`
2. **Transfer**:
   - Files are moved to host evidence storage via out-of-band hypervisor mounting or internal evidence transfer scripts.
   - Files are stored under the external evidence directory (never tracked in git):
     `<EVIDENCE_ROOT>/<sample_id>/`
     - `<sample_id>_sysmon.evtx`
     - `<sample_id>_transcripts.txt`
     - `<sample_id>_network.pcap`
     - `<sample_id>_memory.raw`
3. **Execution Metadata**:
   A single metadata record is appended to `sandbox/execution-logs/log.csv`:
   `sample_id,family,vm,os,timestamp,operator,sample_sha256,notes`
