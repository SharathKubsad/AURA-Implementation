# Sandbox Infrastructure for Fileless Malware Forensics (Task A1)

This directory defines the operational blueprints, virtual machine specifications, network topology, logging plans, and snapshot recovery policies for the isolated malware analysis sandbox.

---

## 1. Sandbox Purpose & Safety Philosophy

The sandbox exists to provide a strictly contained, repeatable, and non-destructive environment to execute fileless malware techniques and capture volatile forensic evidence across **all four feature modalities** (Process, Command, Network, Memory).

### Core Safety Rules
1. **Strict Host-Only Isolation**: All virtual machines connect exclusively to an isolated internal virtual network (`192.168.100.0/24`). Bridged and NAT networking are **strictly prohibited** to prevent any possibility of Internet egress or local area network (LAN) contamination.
2. **Zero Guest Integration**: Shared folders, bidirectional clipboard sharing, and drag-and-drop integration are permanently disabled on all VMs.
3. **Clean Snapshot Revert Discipline**: Target virtual machines are reverted to an untouched baseline snapshot after **every single execution session**. No VM is ever reused across multiple samples.
4. **No Live Malware in Git**: Raw malware payloads, memory dumps, and PCAP captures must never be committed to Git; they are stored in external evidence storage or strictly gitignored locations per `AGENTS.md` §6.

---

## 2. VM Roles & Topology Summary

| VM Role | Operating System | Network Role | IP Address | Primary Function |
|---|---|---|---|---|
| **Attacker / C2** | Kali Linux (x64) | Host-Only | `192.168.100.10` | C2 server, listener, and attack orchestration endpoint |
| **Primary Target** | Windows 10/11 (x64) | Host-Only | `192.168.100.20` | Monitored victim endpoint; memory dumps and telemetry acquired here |
| **Secondary Target** | Ubuntu 22.04 LTS | Host-Only | `192.168.100.30` | Linux victim endpoint for Linux LOLBins and shell injection evaluation |

---

## 3. Four-Modality Telemetry Support

Every sandbox execution captures all four domains mapped to the canonical `sample_id` contract defined in `data/schemas/`:

```
Execution Session (sample_id: EXEC_YYYYMMDD_NNN)
├── Process Modality ──▶ Volatility3 (pslist, pstree, threads, handles) + Sysmon EID 1
├── Command Modality ──▶ PowerShell ScriptBlock (EID 4104) + Transcription + Cmdline
├── Network Modality ──▶ tshark capture (.pcap) on virtual interface + netscan
└── Memory Modality  ──▶ Volatility3 (vadinfo, malfind, ldrmodules, page entropy)
```

---

## 4. Time Synchronization Policy

To ensure high-precision forensic correlation across Sysmon events, PowerShell logs, network packet captures, and memory acquisition timestamps, **guest clock synchronization with the host is maintained during initial baseline collection**. 

> [!NOTE]
> Synchronized clocks ensure that a packet arriving at `T0` in a Wireshark capture precisely aligns with a Process Create event at `T0` in Sysmon. Future specialized anti-evasion experiments may explore time-skew testing, but baseline multi-modal data correlation requires synchronized clocks.

---

## 5. Directory Structure

```
sandbox/
├── README.md                 # This overview document
├── vm-configs/               # Individual VM specifications & hardening guides
│   ├── attacker-kali.md      # Kali Linux C2 endpoint specifications
│   ├── target-windows.md     # Windows 10/11 target endpoint specifications
│   └── target-linux.md       # Ubuntu Linux target endpoint specifications
├── network/
│   └── NETWORK_DESIGN.md     # Isolated virtual switch topology & RFC 1918 plan
├── logging/
│   └── LOGGING_PLAN.md       # Sysmon, PowerShell, and auditd configurations
├── snapshots/
│   └── SNAPSHOT_POLICY.md    # Baseline creation, revert protocol, & evidence chain
└── execution-logs/           # CSV execution metadata logs (NOT payloads)
```
