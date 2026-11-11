# Rich Forensic Feature Dictionary (Phase 4)
**Project:** Real-Time AI-Based Fileless Malware Detection and Classification System  
**Date:** 2026-09-24  
**Authoritative Basis:** Derived exclusively from `data/forensic/`  

---

## 1. Feature Design Principles
- **No Identity Leakage:** Features never encode `run_id`, `sample_id`, `family`, `label`, or source folder paths.
- **Contextual Grounding:** Aggregations capture behavior and structural anomalies across processes, memory pages, command lines, and network endpoints.
- **Harness Exclusion:** Operator capture scripts (`DumpIt.exe`, `collect_run_windows.ps1`, `scp.exe`) tagged as `COLLECTION_HARNESS` are strictly excluded from all command and process features.
- **Strict Null Semantics:** Missing PCAP metrics (`packet_count`, `byte_count`, `flow_duration_sec`, `beacon_periodicity_sec`) are preserved strictly as `None` (`null`) and never fabricated as `0`.
- **Baseline Awareness:** Benign Defender memory findings (`MsMpEng.exe` RWX) are contextualized and separated from suspicious non-baseline findings.

---

## 2. Process Modality Features (`data/features/process/`)

| Feature Name | Description | Source Forensic Entity | Aggregation Window / Method | Null Semantics | Rationale |
|---|---|---|---|---|---|
| `proc_total_count` | Total processes discovered across all plugins | `entities/processes/` | Run-level total count | Observed int | High-level system workload sizing |
| `proc_active_count` | Active processes linked in EPROCESS list | `volatility/pslist.txt` | Run-level count (`is_in_pslist=True`) | Observed int | Baseline live process workload |
| `proc_carved_count` | Processes recovered only from pool memory | `volatility/psscan.txt` | Run-level count (`is_in_psscan and not is_in_pslist`) | Observed int | Terminated or unlinked stealth processes |
| `proc_hidden_unlinked_count` | Processes hidden from psxview or unlinked | `psxview.txt + psscan.txt` | Run-level sum of unlinked flags | Observed int | Rootkit and DKOM process hiding signal |
| `proc_wow64_count` | 32-bit processes running on 64-bit Windows | `entities/processes/` | Run-level sum of `wow64=True` | Observed int | Malware often executes in 32-bit subsystem |
| `proc_tree_max_depth` | Maximum lineage depth of process tree | `relationships/process_tree/` | Graph traversal max depth | Observed int | Deep execution chains (e.g. LOLBin chains) |
| `proc_tree_mean_depth` | Mean lineage depth across process tree | `relationships/process_tree/` | Graph traversal mean depth | Observed float | Overall system process nesting |
| `proc_orphan_parent_count` | Processes whose parent exited before dump | `relationships/process_tree/` | Count of PPIDs missing from live processes | Observed int | Background launchers or severed process parentage |
| `proc_max_children_single_proc` | Maximum children spawned by any single process | `relationships/process_tree/` | Max children over parent PIDs | Observed int | Spawner concentration (e.g. explorer vs attacker script) |
| `proc_spawning_concentration` | Ratio of max children to total spawned children | `relationships/process_tree/` | Max children / total children | Observed float | Concentrated process spawning behavior |
| `proc_thread_count_total` | Total threads running across all processes | `entities/threads/` | Run-level count of ThreadEntities | Observed int | System thread volume |
| `proc_thread_count_mean` | Mean threads per process | `entities/threads/` | Total threads / total processes | Observed float | Multi-threading density |
| `proc_handle_count_total` | Total handles held across all processes | `entities/handles/` | Run-level count of HandleEntities | Observed int | Resource allocation density |
| `proc_handle_count_mean` | Mean handles per process | `entities/handles/` | Total handles / total processes | Observed float | Average handle occupancy |
| `proc_working_set_bytes_mean` | Mean working set physical memory in bytes | `process_snapshot.csv` | Mean across snapshot records | `None` if snapshot unavailable | Memory consumption footprint |
| `proc_cpu_utilization_mean` | Mean CPU utilization percentage | `process_snapshot.csv` | Mean across snapshot records | `None` if snapshot unavailable | Workload compute intensity |
| `proc_user_writable_path_count` | Processes executing from user-writable directories | `entities/processes/` | Count of paths in `Users`, `AppData`, `Temp` | Observed int | Fileless payloads executing from staging directories |
| `proc_system_directory_count` | Processes executing from System32/SysWOW64 | `entities/processes/` | Count of paths in `System32`, `SysWOW64` | Observed int | Legitimate Windows system execution baseline |
| `proc_temp_directory_count` | Processes executing from Temp directory | `entities/processes/` | Count of paths containing `\Temp\` | Observed int | Dropped or staged script payloads |
| `proc_unusual_executable_location_count` | Processes executing outside standard Windows dirs | `entities/processes/` | Count of non-system non-program-files paths | Observed int | Anomaly detection for unusual binaries |
| `proc_elevated_privilege_count` | Count of high-impact token privileges present | `entities/privileges/` | Count of present high-impact privileges | Observed int | Token privilege escalation signal |
| `proc_processes_with_sedebug` | Processes holding `SeDebugPrivilege` | `entities/privileges/` | Count of distinct PIDs with SeDebug | Observed int | Memory inspection and injection capability |

---

## 3. Memory Modality Features (`data/features/memory/`)

| Feature Name | Description | Source Forensic Entity | Aggregation Window / Method | Null Semantics | Rationale |
|---|---|---|---|---|---|
| `mem_rwx_region_count` | Total memory regions with PAGE_EXECUTE_READWRITE | `entities/memory_regions/` | Count of VADs with RWX protection | Observed int | Classic shellcode/injection indicator |
| `mem_executable_private_count` | Private memory regions marked executable | `entities/memory_regions/` | VADs where `private_memory > 0 and EXECUTE in prot` | Observed int | Unmapped shellcode allocation |
| `mem_executable_writable_count` | Executable memory regions that are also writable | `entities/memory_regions/` | VADs with `EXECUTE` and (`READWRITE` or `WRITECOPY`) | Observed int | Dynamic code modification / hooking |
| `mem_vad_total_count` | Total Virtual Address Descriptors | `entities/memory_regions/` | Count of VAD entries | Observed int | Overall process virtual address space scale |
| `mem_vad_private_count` | Private (non-file-backed) VAD allocations | `entities/memory_regions/` | VADs where `private_memory > 0` | Observed int | Heap and custom memory allocation volume |
| `mem_vad_mapped_count` | File-backed mapped VAD allocations | `entities/memory_regions/` | VADs where `private_memory == 0` | Observed int | Normal binary and DLL memory mappings |
| `mem_commit_charge_total` | Total committed memory pages | `entities/memory_regions/` | Sum of commit_charge across VADs | Observed int | Physical RAM commitment footprint |
| `mem_commit_charge_mean` | Mean commit charge per VAD | `entities/memory_regions/` | Mean commit_charge across VADs | Observed float | Average allocation granularity |
| `mem_region_size_bytes_total` | Total virtual memory region size in bytes | `entities/memory_regions/` | Sum of region sizes across VADs | Observed int | Total virtual address space footprint |
| `mem_region_size_bytes_mean` | Mean virtual memory region size in bytes | `entities/memory_regions/` | Mean region size across VADs | Observed float | Granularity of memory allocations |
| `mem_malfind_total_findings` | Total malfind injection findings | `events/memory/` | Count of all MalfindFinding records | Observed int | Volatility malfind detection volume |
| `mem_malfind_baseline_exception_count` | Legitimate Defender (MsMpEng) RWX findings | `events/memory/` | Count where `is_known_baseline_exception=True` | Observed int | Benign JIT signature scanner baseline |
| `mem_malfind_suspicious_non_baseline_count` | Non-baseline suspicious injection findings | `events/memory/` | Count where `is_known_baseline_exception=False` | Observed int | True suspicious injected code regions |
| `mem_malfind_affected_processes_count` | Distinct processes with suspicious malfind findings | `events/memory/` | Unique non-baseline PIDs | Observed int | Scope of memory compromise |
| `mem_malfind_max_findings_single_proc` | Max injection findings in any single process | `events/memory/` | Max findings over non-baseline PIDs | Observed int | Concentration of injected code |
| `mem_unlinked_modules_count` | Modules with inconsistent loader table entries | `entities/modules/` | Count where `in_load/init/mem` is False | Observed int | Hidden DLL injection or unlinked PEB |
| `mem_total_loaded_modules` | Total DLL modules loaded across all processes | `entities/modules/` | Count of ModuleEntities | Observed int | Loaded library volume |
| `mem_modules_per_process_mean` | Mean DLL modules loaded per process | `entities/modules/` | Total modules / unique PIDs | Observed float | Standard DLL footprint per process |

---

## 4. Command Modality Features (`data/features/command/`)

| Feature Name | Description | Source Forensic Entity | Aggregation Window / Method | Null Semantics | Rationale |
|---|---|---|---|---|---|
| `cmd_total_events_count` | Total non-harness command events executed | `events/commands/` | Count excluding `COLLECTION_HARNESS` | Observed int | Command-line execution intensity |
| `cmd_unique_commands_count` | Unique command line invocations | `events/commands/` | Set of unique command strings | Observed int | Command diversity |
| `cmd_mean_command_length` | Mean character length of command lines | `events/commands/` | Mean string length | Observed float | Obfuscated commands tend to be longer |
| `cmd_max_command_length` | Maximum character length of any command line | `events/commands/` | Max string length | Observed int | Encoded payloads produce very long commands |
| `cmd_ps_scriptblock_count` | Total PowerShell EID 4104 ScriptBlocks | `events/powershell/` | Count excluding `COLLECTION_HARNESS` | Observed int | PowerShell activity intensity |
| `cmd_ps_unique_scriptblocks` | Unique PowerShell script block GUIDs | `events/powershell/` | Set of unique script block IDs | Observed int | Distinct scripts executed |
| `cmd_ps_mean_script_length` | Mean character length of script blocks | `events/powershell/` | Mean length of script block text | Observed float | PowerShell script complexity |
| `cmd_ps_max_script_length` | Maximum character length of any script block | `events/powershell/` | Max length of script block text | Observed int | Large multi-part payload injection |
| `cmd_encoded_command_count` | Invocations with Base64 encoding parameters | `events/commands/ + powershell/` | Count of `-enc`, `-encodedcommand` | Observed int | Standard fileless payload delivery technique |
| `cmd_execution_policy_bypass_count` | PowerShell execution policy bypass attempts | `events/commands/ + powershell/` | Count of `-ep bypass`, `unrestricted` | Observed int | Attacker security control evasion |
| `cmd_hidden_window_count` | Commands executed with hidden windows | `events/commands/ + powershell/` | Count of `-w hidden`, `-windowstyle hidden` | Observed int | Stealth execution without user visibility |
| `cmd_download_cradle_count` | Web download cradle invocations | `events/commands/ + powershell/` | Count of WebClient, IWR, curl cradles | Observed int | Remote payload fetching |
| `cmd_lolbin_execution_count` | Invocations of Living-off-the-Land Binaries | `events/commands/ + powershell/` | Count of powershell, wmic, mshta, etc. | Observed int | Execution via legitimate system tools |
| `cmd_registry_modification_count` | Commands modifying Windows registry | `events/commands/ + powershell/` | Count of `reg add`, `Set-ItemProperty` | Observed int | Persistence and configuration tampering |
| `cmd_diversity_ratio` | Ratio of unique commands to total commands | `events/commands/` | Unique commands / total commands | Observed float | Automated repetitive vs dynamic activity |

In addition, raw textual sequences are preserved in `data/features/command/text_sequences.jsonl` for fine-tuning RoBERTa and DistilBERT models.

---

## 5. Network Modality Features (`data/features/network/`)

| Feature Name | Description | Source Forensic Entity | Aggregation Window / Method | Null Semantics | Rationale |
|---|---|---|---|---|---|
| `net_total_observations_count` | Total network socket & connection records | `events/network/` | Total observations | Observed int | Total network telemetry volume |
| `net_snapshot_count` | Netstat snapshot records | `network_connections.csv` | Count where source is netstat | Observed int | Point-in-time socket listening state |
| `net_sysmon_eid3_count` | Dynamic Sysmon connection events | `sysmon.evtx (EID 3)` | Count where source is Sysmon | Observed int | Dynamic outbound connection activity |
| `net_established_connections_count` | Active connections in Established state | `events/network/` | Count where `state=Established` | Observed int | Active communication sessions |
| `net_listening_sockets_count` | Sockets in Listening state | `events/network/` | Count where `state=Listen` | Observed int | Local services and bind shell ports |
| `net_unique_remote_ips_count` | Distinct remote non-loopback IP addresses | `events/network/` | Set of remote IPs (excl 127.0.0.1, 0.0.0.0) | Observed int | External communication breadth |
| `net_unique_destination_ports_count` | Distinct remote destination ports | `events/network/` | Set of destination ports (> 0) | Observed int | Multi-port beaconing or C2 channels |
| `net_outbound_remote_connection_count` | Connections directed to external addresses | `events/network/` | Count of non-local remote endpoints | Observed int | Outbound C2 communication |
| `net_non_standard_http_ssl_ports_count` | Remote connections to non-80/443/53 ports | `events/network/` | Count where remote port not in standard | Observed int | Non-standard C2 port usage |
| `net_privileged_ports_count` | Connections to privileged ports (< 1024) | `events/network/` | Count where 0 < port < 1024 | Observed int | Traditional server service connections |
| `net_ephemeral_ports_count` | Connections to ephemeral high ports (>= 49152) | `events/network/` | Count where port >= 49152 | Observed int | Dynamic port allocations |
| `net_network_enabled_process_count` | Processes initiating network connections | `events/network/` | Unique owning PIDs | Observed int | Breadth of network usage across processes |
| `net_max_connections_single_process` | Max connections initiated by any single PID | `events/network/` | Max connections over PIDs | Observed int | Heavy network beaconing concentration |
| `net_packet_count` | Unsupported PCAP metric | N/A | None (PCAP not collected) | **EXPLICIT NULL** | Strictly preserves null semantics |
| `net_byte_count` | Unsupported PCAP metric | N/A | None (PCAP not collected) | **EXPLICIT NULL** | Strictly preserves null semantics |
| `net_flow_duration_sec` | Unsupported PCAP metric | N/A | None (PCAP not collected) | **EXPLICIT NULL** | Strictly preserves null semantics |
| `net_beacon_periodicity_sec` | Unsupported PCAP metric | N/A | None (PCAP not collected) | **EXPLICIT NULL** | Strictly preserves null semantics |

---

## 6. Cross-Modal Features (`data/features/cross_modal/`)

| Feature Name | Description | Source Relationships | Aggregation Method | Null Semantics | Rationale |
|---|---|---|---|---|---|
| `cross_proc_with_memory_and_command` | Processes with memory injection AND command lines | `process_memory + process_command` | Count of PIDs in both sets | Observed int | Injected process executing shell commands |
| `cross_proc_with_command_and_network` | Processes with command activity AND network conns | `process_command + process_network` | Count of PIDs in both sets | Observed int | Shell or script initiating network communication |
| `cross_proc_with_injection_and_network` | Processes with memory injection AND network conns | `process_memory + process_network` | Count of PIDs in both sets | Observed int | Injected process acting as C2 beacon |
| `cross_proc_with_suspicious_memory_and_tree` | Processes with memory injection that spawned children | `process_memory + process_tree` | Count of PIDs in both sets | Observed int | Injected staging process launching sub-tasks |
| `cross_high_privilege_network_processes` | Processes with SeDebugPrivilege connecting to network | `process_privilege + process_network` | Count of PIDs in both sets | Observed int | High-privilege processes communicating externally |
| `cross_suspicious_memory_process_ratio` | Ratio of injection-compromised PIDs to total procs | `process_memory + entities/processes` | Compromised PIDs / Total PIDs | Observed float | Proportion of process space compromised |
| `cross_network_enabled_process_ratio` | Ratio of network-active PIDs to total processes | `process_network + entities/processes` | Network PIDs / Total PIDs | Observed float | Proportion of processes making network calls |
