"""Deterministic Feature Harmonization and Taxonomy Mapping Engine."""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

# Tactical Cluster Category Taxonomy (Tier 1)
TACTICAL_TAXONOMY = {
    # Process Injection
    "process_hollowing": "Process_Injection",
    "reflective_dll_injection": "Process_Injection",
    "memory_only_rat": "Process_Injection",
    "metasploit_memory_payloads": "Process_Injection",
    "metasploit": "Process_Injection",
    "asyncrat": "Process_Injection",
    "remcos": "Process_Injection",
    "agenttesla": "Process_Injection",
    "redline": "Process_Injection",
    # Script & Living off the Land
    "powershell_fileless": "Script_LOLBins",
    "powershell_stager": "Script_LOLBins",
    "wmi_malware": "Script_LOLBins",
    "lolbins_abuse": "Script_LOLBins",
    "empire_framework": "Script_LOLBins",
    "empire": "Script_LOLBins",
    # Persistence & Ransomware
    "registry_resident_malware": "Persistence_Ransomware",
    "fileless_ransomware": "Persistence_Ransomware",
    "ransomware_ako": "Persistence_Ransomware",
    "ransomware_conti": "Persistence_Ransomware",
    "ransomware_shade": "Persistence_Ransomware",
    "ransomware_wannacry": "Persistence_Ransomware",
    # C2 & Beaconing
    "cobalt_strike_beacon": "C2_Beacon",
    "cobalt_strike": "C2_Beacon",
    # Spyware & Trojan Forensics
    "spyware_transponder": "Spyware_Trojan",
    "spyware_gator": "Spyware_Trojan",
    "spyware_tibs": "Spyware_Trojan",
    "trojan_emotet": "Spyware_Trojan",
    "trojan_zeus": "Spyware_Trojan",
    "trojan_reconyc": "Spyware_Trojan",
    "trojan_refroso": "Spyware_Trojan",
    "benign": "Benign",
}

LOLBINS_LIST = [
    "certutil",
    "mshta",
    "rundll32",
    "regsvr32",
    "cscript",
    "wscript",
    "bitsadmin",
    "wmic",
    "powershell",
    "hh.exe",
    "schtasks",
]


def calculate_shannon_entropy(text: str) -> float:
    """Calculate exact Shannon entropy H(X) = -sum(p * log2(p))."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return float(-sum((c / length) * math.log2(c / length) for c in counts.values()))


def extract_command_indicators(cmd: str) -> dict[str, Any]:
    """Derive deterministic command behavior flags from raw command text."""
    if not cmd:
        return {
            "command_length": 0,
            "shannon_entropy": 0.0,
            "is_base64_encoded": 0,
            "has_download_cradle": 0,
            "has_bypass_execution_policy": 0,
            "has_hidden_window": 0,
            "uses_lolbins": 0,
            "registry_persistence_count": 0,
        }

    cmd_lower = cmd.lower()
    entropy = calculate_shannon_entropy(cmd)
    base64_match = (
        1
        if re.search(r"-[eE](?:nc|ncode|ncodedCommand)?\s+[A-Za-z0-9+/=]{16,}", cmd)
        or re.search(r"[A-Za-z0-9+/=]{40,}", cmd)
        else 0
    )
    cradle_match = (
        1
        if any(
            x in cmd_lower
            for x in [
                "downloadstring",
                "webrequest",
                "iwr",
                "curl",
                "wget",
                "bitstransfer",
                "urlcache",
            ]
        )
        else 0
    )
    ep_bypass = (
        1
        if any(
            x in cmd_lower
            for x in ["-executionpolicy bypass", "-ep bypass", "bypass", "unrestricted"]
        )
        else 0
    )
    hidden_win = (
        1
        if any(
            x in cmd_lower
            for x in ["-windowstyle hidden", "-w hidden", "hidden", "noninteractive"]
        )
        else 0
    )
    lolbins = 1 if any(b in cmd_lower for b in LOLBINS_LIST) else 0

    return {
        "command_length": len(cmd),
        "shannon_entropy": round(entropy, 4),
        "is_base64_encoded": base64_match,
        "has_download_cradle": cradle_match,
        "has_bypass_execution_policy": ep_bypass,
        "has_hidden_window": hidden_win,
        "uses_lolbins": lolbins,
        "registry_persistence_count": 1 if "reg add" in cmd_lower or "run" in cmd_lower else 0,
    }


def calculate_memory_injection_score(rwx: int, inj: int, vad: int) -> float:
    """Calculate MemoryInjectionScore = 2.0*RWX + 3.0*Inj + 1.5*VAD."""
    return float(2.0 * rwx + 3.0 * inj + 1.5 * vad)


def normalize_family_slug(raw_family: str) -> tuple[str, str]:
    """Map raw family name to canonical slug and tactical category."""
    raw_lower = raw_family.lower().replace("-", "_").replace(" ", "_")
    slug = raw_lower
    for k in TACTICAL_TAXONOMY:
        if k in raw_lower:
            slug = k
            break
    tactical = TACTICAL_TAXONOMY.get(slug, "Unknown_Tactical")
    return slug, tactical
