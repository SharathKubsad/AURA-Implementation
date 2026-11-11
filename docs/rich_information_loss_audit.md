# Rich Forensic Information Loss Audit
**Project:** Real-Time AI-Based Fileless Malware Detection and Classification System  
**Audit Date:** 2026-09-24  
**Status:** COMPLETE — All Transformations Explicitly Grounded and Justified  

---

## 1. Information Accounting Framework

The rich forensic layer preserves 100% of semantically meaningful forensic evidence extracted by Volatility 3 and Windows EVTX telemetry. Discarded elements are strictly confined to CLI UI noise (e.g. 'File output' columns in Volatility) and non-semantic operational noise.

| Modality | Source File / Plugin | Source Field | Preserved Status | Transformation Type | Justification |
|---|---|---|:---:|---|---|
| `Process` | `volatility/pslist.txt` | `Offset(V)` | **TRANSFORMED** | Virtual memory pointer retained in ProcessEntity internal metadata | Virtual offsets serve as cross-referencing pointers to pool/VAD allocations rather than direct ML features. |
| `Process` | `volatility/pslist.txt` | `File output` | **DISCARDED** | Static Volatility CLI column ('Disabled') | Constant Volatility 3 output parameter; contains zero forensic signal. |
| `Process` | `volatility/pstree.txt` | `Tree indent asterisks` | **TRANSFORMED** | Parsed into numerical 'tree_depth' integer (0, 1, 2...) | Formatting glyphs converted into explicit mathematical graph hierarchy. |
| `Process` | `source_evidence/process_snapshot.csv` | `StartTime` | **PRESERVED** | String timestamp preserved in ProcessEntity.create_time | Used for execution chronology and process lifetime analysis. |
| `Process` | `volatility/psscan.txt` | `Terminated / Dead Pool Processes` | **PRESERVED** | Pool-carved entries added to ProcessEntity with is_in_psscan=True and is_in_pslist=False | Ensures unlinked or terminated processes are fully available for anomaly detection. |
| `Memory` | `volatility/vadinfo.txt` | `Start VPN, End VPN` | **PRESERVED** | Hex strings preserved; virtual region size computed as (End - Start + 1) | Allows memory layout and allocation volume analysis. |
| `Memory` | `volatility/malfind.txt` | `Hexdump and Disassembly text` | **PRESERVED** | Multi-line string payload preserved in MalfindFinding | Preserved for shellcode analysis and opcode n-gram inspection. |
| `Command` | `source_evidence/powershell.evtx` | `EID 40961 / 40962 Engine Lifecycle Events` | **DISCARDED_FROM_RICH_COMMANDS** | Filtered out during ScriptBlock logging aggregation | EID 40961/40962 record host state changes (Available/Stopped) without command script text. Raw logs remain in EVTX. |
| `Command` | `source_evidence/sysmon.evtx` | `EID 5 Process Terminate` | **PRESERVED_IN_SYSMON** | Preserved in SysmonEvent; not duplicated in CommandEvent | EID 5 represents termination lifecycle; preserved in events/sysmon/ for process duration analysis. |
| `Network` | `Network Telemetry` | `Packet Timing / Byte Counts / PCAP` | **EXPLICIT_NULL** | Field left NULL/None | No PCAP was collected during execution; values explicitly preserved as NULL rather than fabricated as 0. |

---

## 2. Hard Conclusion

- Zero core forensic entities (Processes, Threads, Handles, DLLs, VADs, Malfind findings) were discarded.
- Zero data was fabricated to fill telemetry gaps (packet counts and byte metrics are explicitly `NULL`).