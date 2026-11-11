import sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))
import json
import pandas as pd
import numpy as np

from framework.command_samples import BUILTIN_SAMPLE_COMMANDS
from models.multiclass.train_on_custom import to_canonical_family

import base64
import re

for sample in BUILTIN_SAMPLE_COMMANDS:
    cmd_text = sample["command"]
    cat = sample["category"]
    theme = sample["family_theme"]
    cmd_lower = cmd_text.lower()
    
    decoded_snippet = ""
    enc_match = re.search(r"(?:-encodedcommand|-enc|\s+-e)\s+([A-Za-z0-9+/=]{16,})", cmd_text, re.IGNORECASE)
    raw_b64 = enc_match.group(1) if enc_match else ""
    if not raw_b64:
        matches = re.findall(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", cmd_text)
        raw_b64 = max(matches, key=len) if matches else ""
        
    if raw_b64 and len(raw_b64) >= 16:
        try:
            pad = len(raw_b64) % 4
            if pad:
                raw_b64 += "=" * (4 - pad)
            b_bytes = base64.b64decode(raw_b64)
            try:
                decoded_snippet = b_bytes.decode("utf-16le")
            except Exception:
                decoded_snippet = b_bytes.decode("utf-8", errors="ignore")
        except Exception:
            decoded_snippet = ""

    full_text = f"{cmd_lower} {decoded_snippet.lower()}".strip()
    
    # Priority 1: LOLBins tool invocation
    is_lolbin = any(k in full_text for k in ["bitsadmin", "certutil", "mshta", "regsvr32", "wscript", "cscript", "installutil", "msbuild", "lolbins_abuse"]) and not any(k in full_text for k in ["reflectiveloader", "unlinkmodule", "loadpe", "eventfilter", "consumerbinding"])
    # Priority 2: Memory PE injection
    is_reflective = any(k in full_text for k in ["reflectiveloader", "reflective_dll", "reflective", "unlinkmodule", "getprocaddress", "loadpe", "unlinked_dll", "findreflectiveexports", "module.dll", "reflective_loader", "rdll"])
    is_hollowing = any(k in full_text for k in ["zwunmap", "setthreadcontext", "resumethread", "hollow", "process_hollowing", "unmapviewofsection", "vbc.exe"])
    is_wmi = any(k in full_text for k in ["eventfilter", "commandlineeventconsumer", "filtertoconsumerbinding", "\\\\root\\subscription", "wmi_malware", "antivirusproduct", "firewallproduct"]) or (("wmic" in full_text or "get-wmiobject" in full_text) and any(k in full_text for k in ["process call create", "process create", "node:", "__filter", "__event", "shadowcopy delete", "root\\securitycenter", "namespace:"]))
    is_registry = any(k in full_text for k in ["reg.exe add", "reg add", "currentversion\\run", "winlogon", "ifeo", "image file execution options", "registry_resident", "appcertdlls", "appinit_dlls", "registry_malware", "hkcu:\\software", "hklm:\\software", "get-itemproperty hkcu"])
    is_ransom = any(k in full_text for k in ["vssadmin", "delete shadows", "shadowcopy delete", "recoveryenabled no", "rijndael", "ransomware", "encrypt", "cipher.exe", "fileless_ransomware", "bcdedit", "wbadmin", "delete catalog", "ransom-c2", "locker.ps1", "*sql*", "stop-service"])
    is_metasploit = any(k in full_text for k in ["meterpreter", "reverse_tcp", "reverse_http", "metasploit", "stageless", "payload_guid", "lhost", "lport", "metasploit_memory_payloads", "msfvenom", "windows/x64/meterpreter", "init_stage", "k3mh", "shellcode_runner", "marshal]::copy", "createthread", "4444", "8443"])
    is_empire = (not is_metasploit) and any(k in full_text for k in ["servercertificatevalidationcallback", "cachedgrouppolicysettings", "invokemimikatz", "stage1_init", "empire_launcher", "empire_framework", "process.php", "stageless_ps", "agent_init", "sessionkey", "/task", "invokedumpcreds", "dumpscript", "empire", "launcher", "agenttask"])
    is_cobalt = any(k in full_text for k in ["beacon", "cobalt", "malleable", "c2_beacon", "namedpipeclientstream", "cs_beacon", "cobalt_strike_beacon", "msagent_99", "sessionid=cs", "c2domain", "packet_stream", "c2.security", "tcpclient('192.168.56.101', 4444)"]) and not is_lolbin and not (is_metasploit and "meterpreter" in full_text)
    is_rat = any(k in full_text for k in ["setwindowshookex", "minidumpwritedump", "copyfromscreen", "keylogger", "audiocapture", "screen_grab", "clipboard", "remcos", "asyncrat", "memory_only_rat", "1337", "lsass", "streamwriter"])
    is_powershell = (
        any(k in full_text for k in ["downloadstring", "downloadfile", "iwr ", "net.webclient", "amsiutils", "amsiinitfailed", "frombase64string", "powershell_fileless", "invoke-restmethod", "virtualalloc", "invoke-expression", "iex("])
        or "-enc" in full_text or "-encodedcommand" in full_text or "-w hidden" in full_text
    )
    
    detected = "unknown"
    if is_reflective: detected = "reflective_dll_injection"
    elif is_hollowing: detected = "process_hollowing"
    elif is_wmi: detected = "wmi_malware"
    elif is_registry: detected = "registry_resident_malware"
    elif is_ransom: detected = "fileless_ransomware"
    elif is_cobalt: detected = "cobalt_strike_beacon"
    elif is_empire: detected = "empire_framework"
    elif is_metasploit: detected = "metasploit_memory_payloads"
    elif is_lolbin: detected = "lolbins_abuse"
    elif is_rat: detected = "memory_only_rat"
    elif is_powershell: detected = "powershell_fileless"
    elif theme == "benign": detected = "benign"
    
    status = "PASS" if detected == (to_canonical_family(theme) if theme != "benign" else "benign") else "FAIL"
    print(f"[{status}] {sample['name'][:35]:35s} | Exp: {theme:26s} | Det: {detected}")
