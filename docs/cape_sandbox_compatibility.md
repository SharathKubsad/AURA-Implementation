# CAPEv2 Dynamic Sandbox Feature Compatibility Report & Semantics Audit

## 1. Executive Summary

This audit evaluates the semantic and technical compatibility of **CAPEv2 Dynamic Sandbox Behavioral Reports** against the canonical four-modality feature schemas of the Real-Time Fileless Malware Detection framework.

### Core Findings:
1. **Command Modality (EXCELLENT COMPATIBILITY - 8 Direct, 1 Transformed, 0 Missing)**: CAPEv2 captures authentic process creation command strings (`cmdline`), including obfuscated PowerShell, Base64 payloads, and LOLBins invocations. This provides the exact telemetry needed to train the Command model (`CommandModel` DistilBERT).
2. **Network Modality (HIGH COMPATIBILITY - 3 Direct, 4 Transformed, 3 Missing)**: CAPEv2 provides detailed socket and DNS summaries (`network.tcp`, `network.dns`, `network.hosts`). Consistent with our custom dataset, packet timing features (`interpacket`, `beacon`) are unmeasured (100% NaN) and natively preserved as missing.
3. **Process Modality (CONDITIONAL - 1 Direct, 3 Transformed, 6 Missing)**: Sandbox reports record cumulative processes over 60-120 seconds rather than instantaneous snapshots. Lineage features (`anomalous_ppid_count`) are valid, but Volatility-specific metrics (unlinked DLLs, privileges) are missing.
4. **Memory Modality (INCOMPATIBLE - 0/8 Features Available)**: CAPEv2 does not generate full RAM memory dumps for Volatility forensics. Memory features are 100% unmeasured (`NOT_COMPARABLE`).

---

## 2. Modality Compatibility Summary

| Modality | Direct | Transformed | Proxy | Not Comparable | Verdict | Recommended Role |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **COMMAND** | 8 | 1 | 0 | 0 | **APPROVED** | Scale Command DistilBERT Benchmark & Zero-Shot |
| **NETWORK** | 3 | 4 | 0 | 3 | **APPROVED** | Scale Network LightGBM Benchmark & Zero-Shot |
| **PROCESS** | 1 | 3 | 0 | 6 | **CONDITIONAL** | Auxiliary analysis; cumulative vs snapshot distortion |
| **MEMORY** | 0 | 0 | 0 | 8 | **REJECTED** | Omit entirely (backed by CIC-MalMem) |

---

## 3. Four-Modality Feature Compatibility Matrix

| Feature | Modality | Status | Source Field | Transformation / Extraction | Limitations |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `total_process_count` | PROCESS | **COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION** | `behavior.summary.process_count / len(behavior.processes)` | `int(behavior.summary.process_count)` | Cumulative count is an upper bound on concurrent instantaneous active processes. |
| `hidden_process_count` | PROCESS | **NOT_COMPARABLE** | `None` | `None (unmeasured)` | 100% missing in dynamic sandbox telemetry. |
| `anomalous_ppid_count` | PROCESS | **DIRECTLY_COMPARABLE** | `behavior.summary.anomalous_ppid_count` | `int(behavior.summary.anomalous_ppid_count)` | PPID spoofing via explicit startup info attributes may conceal true creator. |
| `avg_threads_per_process` | PROCESS | **NOT_COMPARABLE** | `None` | `None (unmeasured)` | 100% missing in CAPEv2 summary reports. |
| `max_threads_in_single_process` | PROCESS | **NOT_COMPARABLE** | `None` | `None (unmeasured)` | 100% missing in CAPEv2 summary reports. |
| `total_handle_count` | PROCESS | **COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION** | `behavior.summary.handles_count` | `int(behavior.summary.handles_count)` | Measures monitored processes only, not system-wide total handles. |
| `suspicious_dll_count` | PROCESS | **COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION** | `behavior.processes[].loaded_modules` | `sum(1 for m in loaded_modules if is_staging_path(m))` | Manual mapping / reflective DLL loads without LoadLibrary will be missed. |
| `malfind_process_count` | PROCESS | **NOT_COMPARABLE** | `None` | `None (unmeasured)` | 100% missing in dynamic execution reports. |
| `elevated_privilege_count` | PROCESS | **NOT_COMPARABLE** | `None` | `None (unmeasured)` | 100% missing in summary reports. |
| `unlinked_dll_count` | PROCESS | **NOT_COMPARABLE** | `None` | `None (unmeasured)` | 100% missing in dynamic execution reports. |
| `raw_command_text` | COMMAND | **DIRECTLY_COMPARABLE** | `behavior.summary.commands[0] / behavior.processes[].command_line` | `str(command_line).strip()` | Traces that execute zero commands cannot produce command telemetry. |
| `command_length` | COMMAND | **DIRECTLY_COMPARABLE** | `len(raw_command_text)` | `len(raw_command_text)` | None. |
| `shannon_entropy` | COMMAND | **DIRECTLY_COMPARABLE** | `calculate_shannon_entropy(raw_command_text)` | `calculate_shannon_entropy(raw_command_text)` | None. |
| `is_base64_encoded` | COMMAND | **DIRECTLY_COMPARABLE** | `BASE64_COMMAND_FLAGS.search(raw_command_text)` | `1 if any(p.search(cmd) for p in BASE64_COMMAND_FLAGS) else 0` | None. |
| `has_download_cradle` | COMMAND | **DIRECTLY_COMPARABLE** | `DOWNLOAD_CRADLE_PATTERNS.search(raw_command_text)` | `1 if any(p.search(cmd) for p in DOWNLOAD_CRADLE_PATTERNS) else 0` | None. |
| `has_bypass_execution_policy` | COMMAND | **DIRECTLY_COMPARABLE** | `BYPASS_POLICY_PATTERNS.search(raw_command_text)` | `1 if any(p.search(cmd) for p in BYPASS_POLICY_PATTERNS) else 0` | None. |
| `has_hidden_window` | COMMAND | **DIRECTLY_COMPARABLE** | `HIDDEN_WINDOW_PATTERNS.search(raw_command_text)` | `1 if any(p.search(cmd) for p in HIDDEN_WINDOW_PATTERNS) else 0` | None. |
| `uses_lolbins` | COMMAND | **DIRECTLY_COMPARABLE** | `any(lb in cmd_lower for lb in LOLBINS_HIGH_RISK)` | `1 if any(lb in cmd.lower() for lb in LOLBINS_HIGH_RISK) else 0` | Renamed binaries without path verification may bypass simple string matching. |
| `registry_persistence_count` | COMMAND | **COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION** | `behavior.summary.registry / REGISTRY_PERSISTENCE_PATTERNS` | `sum(1 for p in REGISTRY_PERSISTENCE_PATTERNS if p.search(cmd))` | Direct kernel registry writes not visible on command line. |
| `active_connection_count` | NETWORK | **COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION** | `len(network.tcp)` | `len(network.get('tcp', []))` | Cumulative connections exceed instantaneous socket table snapshot. |
| `listening_port_count` | NETWORK | **NOT_COMPARABLE** | `None` | `None (unmeasured)` | 100% missing in standard CAPEv2 network summaries. |
| `outbound_connection_count` | NETWORK | **COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION** | `len([c for c in network.tcp if not is_local(c['dst'])])` | `len([c for c in network.get('tcp', []) if not is_local(c.get('dst', ''))])` | Cumulative outbound count. |
| `dns_query_count` | NETWORK | **DIRECTLY_COMPARABLE** | `len(network.dns)` | `len(network.get('dns', []))` | Direct-to-IP connections generate 0 DNS queries. |
| `unique_remote_ips` | NETWORK | **DIRECTLY_COMPARABLE** | `len(set(network.hosts))` | `len(set(network.get('hosts', [])))` | None. |
| `avg_interpacket_interval_ms` | NETWORK | **NOT_COMPARABLE** | `None` | `None (preserved as NaN)` | 100% missing in JSON reports. Faithfully matches custom-domain host-only missingness. |
| `beacon_regularity_score` | NETWORK | **NOT_COMPARABLE** | `None` | `None (preserved as NaN)` | 100% missing in JSON reports. Faithfully matches custom-domain host-only missingness. |
| `total_bytes_sent` | NETWORK | **COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION** | `network.total_bytes_sent` | `int(network.get('total_bytes_sent', 0))` | Cumulative volume over 120s vs instantaneous point-in-time bytes. |
| `total_bytes_received` | NETWORK | **COMPARABLE_WITH_DOCUMENTED_TRANSFORMATION** | `network.total_bytes_received` | `int(network.get('total_bytes_received', 0))` | Cumulative volume over 120s vs instantaneous point-in-time bytes. |
| `suspicious_port_usage` | NETWORK | **DIRECTLY_COMPARABLE** | `network.tcp[].dport` | `1 if any(c.get('dport') in SUSPICIOUS_PORTS for c in network.get('tcp', [])) else 0` | None. |
| `rwx_page_count` | MEMORY | **NOT_COMPARABLE** | `None` | `None (unmeasured)` | 100% missing in CAPEv2 dynamic reports. |
| `injected_code_regions` | MEMORY | **NOT_COMPARABLE** | `None` | `None (unmeasured)` | 100% missing in CAPEv2 dynamic reports. |
| `unmapped_executable_pages` | MEMORY | **NOT_COMPARABLE** | `None` | `None (unmeasured)` | 100% missing in CAPEv2 dynamic reports. |
| `vad_protection_anomaly_count` | MEMORY | **NOT_COMPARABLE** | `None` | `None (unmeasured)` | 100% missing in CAPEv2 dynamic reports. |
| `ldrmodules_inconsistencies` | MEMORY | **NOT_COMPARABLE** | `None` | `None (unmeasured)` | 100% missing in CAPEv2 dynamic reports. |
| `yara_shellcode_matches` | MEMORY | **NOT_COMPARABLE** | `None` | `None (unmeasured)` | 100% missing in CAPEv2 dynamic reports. |
| `mean_memory_entropy` | MEMORY | **NOT_COMPARABLE** | `None` | `None (unmeasured)` | 100% missing in CAPEv2 dynamic reports. |
| `max_memory_entropy` | MEMORY | **NOT_COMPARABLE** | `None` | `None (unmeasured)` | 100% missing in CAPEv2 dynamic reports. |

---

## 4. Semantic Validation & Examples

### Command Modality Example:
- **Source (`behavior.processes[].command_line`)**: `powershell.exe -w hidden -ep bypass -enc SQBFAFgA...`
- **Transformation**: Sanitized string extraction and deterministic regex extraction for `is_base64_encoded` (1), `has_download_cradle` (1), `has_bypass_execution_policy` (1), `has_hidden_window` (1).
- **Canonical Output**: Valid `CommandFeatures` object.
- **Forensic Rationale**: Perfect semantic parity with Sysmon Event ID 1 telemetry.

### Network Modality Example:
- **Source (`network.tcp`)**: `[{'dst': '192.168.1.100', 'dport': 8080, 'proto': 'tcp'}]`
- **Transformation**: Count outbound sockets (`outbound_connection_count=1`), check suspicious port (`suspicious_port_usage=1`), count unique IPs (`unique_remote_ips=1`).
- **PCAP Fields**: `avg_interpacket_interval_ms=None`, `beacon_regularity_score=None` (preserved as NaN, zero fabrication).
- **Forensic Rationale**: Captures genuine external connection activity.

---
*Document generated by `tools/generate_cape_compatibility.py`.*