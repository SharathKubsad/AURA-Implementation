# Dataset Quality & Integrity Audit Report

**Evaluated Dataset:** `C:\Users\PRAJWAL V L\Downloads\Real-Time-Fileless-Malware-Detection-main (1)\Real-Time-Fileless-Malware-Detection-main\data\processed\unified\unified_dataset.jsonl`  
**Total Executions:** 500 (Benign: 240, Malware: 260)  
**Validation Status:** **PASS**

---

## 1. Distribution Summary

| Metric | Count | Percentage |
|---|---|---|
| **Total Samples** | 500 | 100.0% |
| **Benign Workloads** | 240 | 48.0% |
| **Malware Attacks** | 260 | 52.0% |
| **Distinct Families** | 25 | — |

---

## 2. Malware Family Distribution

| Family / Attack Vector | Executions |
|---|---|
| benign | 240 |
| ransomware_conti | 21 |
| spyware_transponder | 19 |
| remcos_rat | 18 |
| redline_stealer | 18 |
| trojan_emotet | 18 |
| trojan_zeus | 16 |
| powershell_stager | 15 |
| agenttesla | 15 |
| ransomware_ako | 14 |
| spyware_gator | 14 |
| metasploit_payload | 13 |
| cobalt_strike_beacon | 12 |
| asyncrat | 12 |
| lolbins_abuse | 11 |
| ransomware_shade | 11 |
| empire_framework | 10 |
| process_hollowing | 3 |
| memory_only_rat | 3 |
| registry_resident_malware | 3 |
| metasploit_memory_payloads | 3 |
| wmi_malware | 3 |
| reflective_dll_injection | 3 |
| fileless_ransomware | 3 |
| powershell_fileless | 2 |

---

## 3. Modality Completeness & Leakage Audit

| Quality Check | Observed Value | Status |
|---|---|:---:|
| **Duplicate Execution IDs** | 0 | PASS |
| **Missing Process Vectors** | 0 | PASS |
| **Missing Command Vectors** | 0 | PASS |
| **Missing Network Vectors** | 0 | PASS |
| **Missing Memory Vectors** | 0 | PASS |
| **Invalid Numeric Values** | 0 | PASS |
| **Train/Test Leakage** | None Detected | PASS |
