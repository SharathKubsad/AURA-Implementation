import sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))
from framework.command_samples import BUILTIN_SAMPLE_COMMANDS

failing = [
    "Cobalt Strike - Direct Socket Beacon",
    "Cobalt Strike - DNS Egress Tunnel S",
    "Metasploit - Meterpreter Reverse TC",
    "Metasploit - Meterpreter Reverse HT",
    "Metasploit - In-Memory Allocation R",
    "Metasploit - Web Delivery Script St",
    "LOLBin Abuse - BITSAdmin Background",
    "Fileless Ransomware - Encryption Ke",
    "Fileless Ransomware - Database & Se",
    "Memory RAT - Interactive Reverse Sh",
    "Memory RAT - MiniDumpWriteDump Memo",
    "Empire Framework - Base64 Agent Lau",
    "Empire Framework - Dynamic Agent Ta",
    "Empire Framework - In-Memory Creden",
]

for s in BUILTIN_SAMPLE_COMMANDS:
    name = s["name"]
    for f in failing:
        if f in name:
            print(f"\n[{name}] (Cat: {s['category']}, Theme: {s['family_theme']})")
            print("Command:", s["command"])
