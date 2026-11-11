"""Label and malware family taxonomy mapping module."""

from __future__ import annotations

from typing import Any

# Canonical 11 Malware Families
FAMILY_TO_LABEL: dict[str, int] = {
    "PowerShell Fileless": 0,
    "WMI Malware": 1,
    "Process Hollowing": 2,
    "Reflective DLL Injection": 3,
    "Registry Malware": 4,
    "Cobalt Strike Beacon": 5,
    "Metasploit Memory Payloads": 6,
    "LOLBins Abuse": 7,
    "Fileless Ransomware": 8,
    "Memory-only RAT": 9,
    "Empire Framework": 10,
}

LABEL_TO_FAMILY: dict[int, str] = {v: k for k, v in FAMILY_TO_LABEL.items()}

# Slugs mapping
SLUG_MAP: dict[str, str] = {
    "powershell_fileless": "PowerShell Fileless",
    "wmi_malware": "WMI Malware",
    "process_hollowing": "Process Hollowing",
    "reflective_dll_injection": "Reflective DLL Injection",
    "registry_resident_malware": "Registry Malware",
    "registry_malware": "Registry Malware",
    "cobalt_strike_beacon": "Cobalt Strike Beacon",
    "metasploit_memory_payloads": "Metasploit Memory Payloads",
    "lolbins_abuse": "LOLBins Abuse",
    "fileless_ransomware": "Fileless Ransomware",
    "memory_only_rat": "Memory-only RAT",
    "empire_framework": "Empire Framework",
    "benign": "Benign",
}


def normalize_family_name(raw_name: str) -> str:
    """Normalize input family slug or raw name to canonical family name."""
    clean = raw_name.strip().lower().replace("-", "_").replace(" ", "_")
    if clean in SLUG_MAP:
        return SLUG_MAP[clean]
    for slug, canonical in SLUG_MAP.items():
        if slug in clean or clean in slug:
            return canonical
    return "Benign" if "benign" in clean else "PowerShell Fileless"


def get_binary_label(family_name: str) -> int:
    """Return 0 for Benign, 1 for Malware."""
    return 0 if normalize_family_name(family_name) == "Benign" else 1


def get_multiclass_label(family_name: str) -> int | None:
    """Return 0-10 multi-class integer label, or None if Benign."""
    norm = normalize_family_name(family_name)
    return FAMILY_TO_LABEL.get(norm, None)
