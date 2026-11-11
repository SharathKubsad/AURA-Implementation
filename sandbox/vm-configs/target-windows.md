# Virtual Machine Specification: Target Windows Endpoint (Windows 10/11)

This specification defines the configuration for the primary victim/target virtual machine used for volatile memory dumps and live telemetry collection.

---

## 1. System Specifications

- **Role**: Target victim endpoint, host for live telemetry capture and volatile memory acquisition.
- **Operating System**: Windows 11 Pro (preferred) or Windows 10 Pro (x64, Version 22H2+).
- **vCPU Allocation**: 4 vCPUs.
- **Memory Allocation**: 8 GB RAM (sufficient for modern Windows and partial/full memory forensics).
- **Virtual Disk**: 80 GB (NVMe virtual controller).
- **Firmware**: UEFI with Secure Boot enabled (or standard BIOS for Windows 10).

---

## 2. Network Configuration

- **Network Adapter**: 1 virtual network adapter.
- **Connection Type**: **Host-Only / Custom Internal Virtual Network** (strictly internal to host).
- **PROHIBITION**: Bridged and NAT adapters are **strictly forbidden**.
- **IP Addressing**: Static IPv4.
  - **IP Address**: `192.168.100.20`
  - **Subnet Mask**: `255.255.255.0` (`/24`)
  - **Default Gateway**: None.
  - **DNS**: None.

```powershell
# Set static IP on internal interface
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 192.168.100.20 -PrefixLength 24
```

---

## 3. Hypervisor Isolation & Hardening

Explicitly disabled in virtual machine settings:
- **Shared Folders**: Disabled.
- **Bidirectional Clipboard**: Disabled.
- **Drag and Drop**: Disabled.
- **Host Time Synchronization**: Enabled for timestamp correlation with network and host-level execution logs (see `sandbox/README.md` §4).

---

## 4. Forensic Telemetry & Logging Configuration

To capture telemetry across the **Process**, **Command**, and **Network** domains:

### 4.1 Sysmon Configuration
Install Microsoft Sysmon with an event-filtering configuration tailored to fileless techniques:
- **Event ID 1**: Process Creation (captures full command lines, hashes, parent-child PID/PPID relationships).
- **Event ID 3**: Network Connections (captures destination IPs, ports, initiating process IDs).
- **Event ID 7**: Image / DLL Loaded (detects DLL hijacking and anomalous AppData module loads).
- **Event ID 8**: CreateRemoteThread (detects thread injection into remote processes).
- **Event ID 10**: ProcessAccess (detects `PROCESS_VM_READ` and `PROCESS_VM_WRITE` access masks).
- **Event ID 12 / 13**: Registry Object Added / Value Set (monitors persistence keys).

### 4.2 PowerShell ScriptBlock & Transcription Logging
Configure via Local Group Policy (`gpedit.msc`) or registry keys:
```powershell
# Enable PowerShell ScriptBlock Logging (Event ID 4104)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

# Enable PowerShell Transcription (Logs decoded command text to evidence path)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\ForensicEvidence\Transcripts" -Type String
```

---

## 5. Volatile Memory Acquisition Tooling

Place the following tools in `C:\ForensicTools\` (to be used during execution sessions):
- `DumpIt.exe` (Comae / Magnet DumpIt x64 raw memory capture utility)
- `winpmem_mini_x64.exe` (WinPMEM raw memory acquisition fallback)
- Volatility3 Symbol Tables (downloaded during initial VM prep and pre-cached)

---

## 6. Baseline Snapshot Protocol

1. Complete OS installation, updates, and configuration of Sysmon, PowerShell logging, and memory acquisition tools.
2. Confirm network adapter is set to **Host-Only**.
3. Flush event logs and temporary files:
   ```powershell
   wevtutil cl "Microsoft-Windows-Sysmon/Operational"
   wevtutil cl "Microsoft-Windows-PowerShell/Operational"
   ```
4. Shut down the VM and take snapshot: `Windows_Clean_Baseline_v1`.
5. This snapshot is the immutable baseline to which the VM must be reverted after every single execution run.
