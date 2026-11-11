# Network Evidence & Telemetry Inventory

**Date:** 2026-09-22  
**Investigation Scope:** Comprehensive audit of all network artifacts in `Dataset/`, including socket snapshots (`network_connections.csv`), Volatility memory scans (`netscan.txt`), Sysmon connection events (`sysmon.evtx` Event ID 3), and verification of PCAP absence.  
**Status:** COMPLETE — NO FABRICATED PCAP DATA.

---

## 1. Executive Forensic Summary

A strict inventory of network evidence across all 45 execution runs confirms:
1. **Packet Capture Evidence (`.pcap` / `.pcapng`):** **0 FILES EXIST**. No network packet traces were recorded during VM execution.
2. **Socket Snapshot Evidence (`network_connections.csv`):** **45 files exist** (1 per run). However, 99.5% of records represent the idle Windows 11 host baseline (`State == 'Listen'`, `RemotePort == 0`).
3. **Volatility Kernel Sockets (`netscan.txt`):** **45 files exist** (1 per run). Recovers kernel socket structures (`_IN_ADDR`, `_SOCKADDR_IN`) from memory.
4. **Sysmon Network Connection Telemetry (`sysmon.evtx` Event ID 3):** **45 files exist** (1 per run). Contains **243 to 404 active network connection events per run**, including genuine outbound HTTP/TCP C2 callbacks initiated by `powershell.exe` to sandbox listeners on port 8000 and 4444.

---

## 2. Explicit Availability Determination

### 2.1 EVIDENCE NOT AVAILABLE (Genuinely Absent — Must NOT Be Fabricated)

The following 5 features from the project's original schema **have zero source evidence** and cannot be computed:

| Feature Name | Theoretical Meaning | Source Required | Dataset Status | Recommendation |
|---|---|---|---|---|
| `dns_query_count` | Number of DNS queries generated | PCAP capture or Sysmon EID 22 | **ABSENT** (PCAP missing; Sysmon DNS logging disabled) | **RETIRE / DO NOT IMPUTE** |
| `avg_interpacket_interval_ms` | Mean packet inter-arrival time | PCAP timestamps | **ABSENT** (No packet timestamps exist) | **RETIRE / DO NOT IMPUTE** |
| `beacon_regularity_score` | Autocorrelation / periodicity of C2 packets | PCAP packet stream | **ABSENT** (No packet stream exists) | **RETIRE / DO NOT IMPUTE** |
| `total_bytes_sent` | Total payload data transmitted | PCAP packet payload lengths | **ABSENT** (Socket CSV does not record byte counters) | **RETIRE / DO NOT IMPUTE** |
| `total_bytes_received`| Total payload data received | PCAP packet payload lengths | **ABSENT** (Socket CSV does not record byte counters) | **RETIRE / DO NOT IMPUTE** |

> [!CAUTION]
> The previous Network model (`models/network/train.py`) filled all 5 missing features with `0.0` and appended missingness indicator columns. Because 100% of samples were missing these values, the indicator columns were identical constants (1 for all samples), and LightGBM collapsed to guessing the prior probability (ROC-AUC 0.50). These fields must be formally excised from the active feature schema.

---

### 2.2 EVIDENCE AVAILABLE (Genuine & Verifiable)

#### Source A: Sysmon Event ID 3 (`sysmon.evtx`) — 243 to 404 events per run

| Field Name | Datatype | Example | Variability Across Runs | Benign vs Malware Difference | Forensic Utility |
|---|---|---|---|---|---|
| `DestinationIp` | `string` | `192.168.100.1`, `192.168.100.20` | HIGH | Malware runs connect to listener IPs `192.168.100.10` and `192.168.100.20`; benign runs connect only to local gateway/multicast. | **VERY HIGH** |
| `DestinationPort` | `integer` | `8000`, `4444`, `5355` | HIGH | Malware connects to non-standard HTTP/C2 ports (`8000`, `4444`, `8443`); benign traffic uses `5355` (LLMNR), `5353` (mDNS), `137` (NetBIOS). | **VERY HIGH** |
| `Image` | `string` | `...\powershell.exe`, `...\svchost.exe` | HIGH | Sockets initiated by `powershell.exe`, `cmd.exe`, or `rundll32.exe` are exclusively found in malware runs! | **VERY HIGH** |
| `Protocol` | `string` | `tcp`, `udp` | MODERATE | Malware beacons use TCP; benign background uses UDP multicast. | **HIGH** |
| `Initiated` | `boolean` | `true` | LOW | Outbound initiation flag. | MODERATE |

#### Source B: `network_connections.csv` — 15 to 19 rows per run

| Field Name | Datatype | Example | Variability Across Runs | Benign vs Malware Difference | Forensic Utility |
|---|---|---|---|---|---|
| `LocalAddress` | `string` | `::`, `0.0.0.0` | **ZERO** (Constant) | None | Unusable |
| `LocalPort` | `integer` | `135`, `445`, `49669` | **ZERO** (Identical 10 ports) | None (Windows 11 baseline) | Unusable for classification |
| `OwningProcess` | `integer` | `808` (`svchost`) | MODERATE | None | Useful only as join key |
| `State` | `string` | `Listen` | **ZERO** (99.5% Listen) | None | Unusable |

#### Source C: Volatility `netscan.txt` — 18 to 25 rows per run

| Field Name | Datatype | Example | Variability Across Runs | Benign vs Malware Difference | Forensic Utility |
|---|---|---|---|---|---|
| `Offset` | `hex` | `0xb800a12e80` | HIGH | Kernel object address | Pointer verification |
| `Proto` | `string` | `TCPv4`, `UDPv4`, `TCPv6` | MODERATE | Protocol distribution | Moderate |
| `LocalAddr` / `Port` | `string` / `int` | `0.0.0.0:135` | LOW | Baseline host listeners | Baseline verification |
| `ForeignAddr` / `Port`| `string` / `int`| `192.168.100.20:8000` | HIGH | Captures terminated/unlinked sockets in memory! | **HIGH** |
| `PID` / `Owner` | `int` / `str` | `4896` / `powershell.exe` | HIGH | Maps kernel socket structure to process | **HIGH** |

---

## 3. Recommended Genuine Network Features

Rather than imputing absent PCAP metrics, the Network model should be trained on the following 6 legitimate features extracted from Sysmon Event ID 3 and Volatility `netscan`:

1. `outbound_connection_count` (int): Number of outbound TCP/UDP connection events initiated during the execution window.
2. `unique_remote_ips` (int): Number of distinct destination IPs contacted (excluding loopback and broadcast `224.0.0.x`).
3. `suspicious_port_usage` (int): Count of outbound connections to non-standard ports (e.g. 4444, 8000, 8080, 8443, 9001).
4. `non_system_network_connections` (int): Count of connection events initiated by userland or scripting processes (`powershell.exe`, `cmd.exe`, `rundll32.exe`, `wscript.exe`) rather than core OS services (`svchost.exe`, `System`).
5. `c2_subnet_connection_count` (int): Number of connections directed to private sandbox host listener IPs (`192.168.100.0/24`).
6. `listening_port_anomaly_count` (int): Listening ports present in `netscan.txt` outside the standard 10-port Windows baseline.
