"""Command feature extraction engine for Sysmon, PowerShell, and process telemetry (Track B)."""

from __future__ import annotations

import argparse
import base64
import contextlib
import csv
import logging
import math
import re
from collections import Counter
from pathlib import Path

from forensics.schemas.command import CommandFeatures

logger = logging.getLogger(__name__)


def calculate_shannon_entropy(data: bytes | str | list[int]) -> float:
    """Calculate Shannon entropy for a sequence of bytes or characters (0.0 to 8.0)."""
    if not data:
        return 0.0
    if isinstance(data, str):
        byte_data = data.encode("utf-8", errors="ignore")
    elif isinstance(data, list):
        byte_data = bytes(data)
    else:
        byte_data = data

    length = len(byte_data)
    if length == 0:
        return 0.0

    counts = Counter(byte_data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(min(max(entropy, 0.0), 8.0), 4)


# Harness scripts and tools used during sandbox collection that must NOT be attributed to the workload
HARNESS_FILTERS: list[str] = [
    "collect_run_windows.ps1",
    "collect_run_windows.bat",
    "fmd-collector",
    "fmd-windows-collector",
    "dumpit.exe",
    "dumpit",
    "collection_orchestrator.py",
    "hash-evidence",
    "wevtutil.exe",
    "wevtutil",
    "scp.exe",
    "ssh.exe",
    "import sys; sys.exit(0)",
    "ensurepip",
    "runpy.run_module",
    "pip-26.2.1",
    "python.exe -i -w ignore::deprecationwarning",
    "python.exe --version",
    "py.exe --version",
    "where.exe python",
    "where.exe py",
    "get-nettcpconnection",
    "get-process",
    "vol.py",
]

# Living-off-the-Land Binaries (LOLBins) frequently abused in fileless & living-off-the-land attacks
LOLBINS_HIGH_RISK: set[str] = {
    "certutil",
    "bitsadmin",
    "mshta",
    "regsvr32",
    "installutil",
    "msbuild",
    "cmstp",
    "regasm",
    "regsvcs",
    "psexec",
    "vssadmin",
    "hh",
    "fodhelper",
    "msiexec",
}

# Signatures for download cradles
DOWNLOAD_CRADLE_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)\.(?:downloadstring|downloadfile|downloaddata|openread)\s*\("),
    re.compile(r"(?i)\b(?:invoke-webrequest|iwr|curl|wget)\b.*https?://"),
    re.compile(r"(?i)new-object\s+(?:net\.webclient|system\.net\.webclient)"),
    re.compile(
        r"(?i)createobject\s*\(\s*['\"](?:msxml2\.(?:server)?xmlhttp|winhttp\.winhttprequest)['\"]"
    ),
    re.compile(r"(?i)\bstart-bitstransfer\b"),
    re.compile(r"(?i)\bbitsadmin(?:\.exe)?\s+/transfer\b"),
    re.compile(r"(?i)\bcertutil(?:\.exe)?\s+.*-urlcache\b"),
]

# Signatures for execution policy bypass
BYPASS_POLICY_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)-(?:executionpolicy|ep)\s+(?:bypass|unrestricted)"),
    re.compile(r"(?i)set-executionpolicy\s+(?:bypass|unrestricted)"),
]

# Signatures for hidden window execution
HIDDEN_WINDOW_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)-(?:windowstyle|w)\s+(?:hidden|1\b)"),
    re.compile(r"(?i)createobject\s*\(\s*['\"]wscript\.shell['\"]\s*\)\.run.*,\s*0"),
    re.compile(r"(?i)start-process.*-(?:windowstyle|w)\s+hidden"),
    re.compile(r"(?i)processwindowstyle\.hidden"),
    re.compile(r"(?i)\bshowwindow\s*\(\s*0\s*\)"),
]

# Signatures for Base64 execution flags in command lines
BASE64_COMMAND_FLAGS: list[re.Pattern] = [
    re.compile(r"(?i)-(?:encodedcommand|encode|enc|ec|e)\s+([A-Za-z0-9+/=]{12,})"),
    re.compile(r"(?i)\[system\.convert\]::frombase64string\s*\("),
    re.compile(
        r"(?i)\[system\.text\.encoding\]::.*getstring\s*\(\s*\[system\.convert\]::frombase64string"
    ),
    re.compile(r"(?i)frombase64transform"),
]

# Registry persistence path fragments
REGISTRY_PERSISTENCE_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)\\currentversion\\run(?:once)?"),
    re.compile(r"(?i)\\winlogon\\(?:userinit|shell)"),
    re.compile(r"(?i)\\system\\currentcontrolset\\services\\"),
    re.compile(r"(?i)\\software\\microsoft\\windows\\currentversion\\policies\\explorer\\run"),
    re.compile(r"(?i)reg\s+add\s+.*\\(?:run|runonce)", re.IGNORECASE),
    re.compile(r"(?i)set-itemproperty\s+.*\\(?:run|runonce)", re.IGNORECASE),
]

# Patterns characteristic of normal, built-in PowerShell module initialization
# Normal PowerShell starts by executing these internal scripts, which must NOT be flagged as malware.
POWERSHELL_MODULE_INIT_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)\$__cmdletization"),
    re.compile(r"(?i)\bcmdletization\b"),
    re.compile(r"(?i)\b(?:export-)?modulemember\b"),
    re.compile(r"(?i)-alias\s+['\"]?\*['\"]?"),
    re.compile(r"(?i)\bset-strictmode\b"),
    re.compile(r"(?i)#requires\s+-version"),
    re.compile(r"(?i)\b(?:associatednet|associatedip)\b"),
    re.compile(r"(?i)\b(?:deadgatewaydetection|chimney|routemetric|localportstart)\b"),
    re.compile(r"(?i)\b(?:get|set)-psreadlineoption\b"),
    re.compile(r"(?i)function\s+prompt\s*\{"),
    re.compile(r"(?i)param\s*\(\s*\[parametersetname="),
    re.compile(r"(?i)\[microsoft\.powershell\.cmdletization\."),
    re.compile(r"(?i)microsoft\.powershell\.\w+"),
    re.compile(r"(?i)\$psversiontable"),
    re.compile(r"(?i)import-localizeddata"),
    re.compile(r"(?i)powershell_ise\.exe"),
]

# Background Windows tasks to deprioritize when searching for salient user/attack commands
BACKGROUND_PROCESS_NOISE: set[str] = {
    "searchprotocolhost.exe",
    "searchindexer.exe",
    "searchfilterhost.exe",
    "searchhost.exe",
    "ngen.exe",
    "ngentask.exe",
    "mscorsvw.exe",
    "compattelrunner.exe",
    "devicecensus.exe",
    "dismhost.exe",
    "wermgr.exe",
    "consent.exe",
    "sedlauncher.exe",
    "usoclient.exe",
    "mousocoreworker.exe",
    "appidcertstorecheck.exe",
    "tiworker.exe",
    "trustedinstaller.exe",
    "dllhost.exe",
    "unsecapp.exe",
    "autochk.exe",
    "smss.exe",
    "csrss.exe",
    "logonui.exe",
    "openconsole.exe",
    "windowsterminal.exe",
    "appactions.exe",
    "microsoft.photos.exe",
    "filecoauth.exe",
    "onedrive.exe",
    "onedrivelauncher.exe",
    "onedrivestandaloneupdater.exe",
    "sysmon64.exe",
    "wininit.exe",
    "winlogon.exe",
    "lsass.exe",
    "fontdrvhost.exe",
    "sihost.exe",
    "userinit.exe",
    "explorer.exe",
    "upfc.exe",
    "slui.exe",
    "hpatchmontask.cmd",
    "systemsettings.exe",
    "wmiprvse.exe",
    "ctfmon.exe",
    "audiodg.exe",
    "smartscreen.exe",
    "mpcmdrun.exe",
    "conhost.exe",
    "taskhostw.exe",
    "svchost.exe",
    "aggregatorhost.exe",
    "services.exe",
    "crossdeviceresume.exe",
    "securityhealthhost.exe",
    "runtimebroker.exe",
    "backgroundtaskhost.exe",
    "shellexperiencehost.exe",
    "startmenuexperiencehost.exe",
    "microsoftedgeupdate.exe",
    "msedge.exe",
    "msedgewebview2.exe",
    "winsat.exe",
    "srtasks.exe",
    "wsqmcons.exe",
    "sdbinst.exe",
    "vssvc.exe",
    "monotificationux.exe",
    "dwm.exe",
    "dxgiadaptercache.exe",
    "spoolsv.exe",
    "sppsvc.exe",
    "cliprenew.exe",
    "shellhost.exe",
    "widgets.exe",
    "sppextcomobj.exe",
    "wlrmdr.exe",
    "appidpolicyconverter.exe",
    "provtool.exe",
    "elevation_service.exe",
    "verclsid.exe",
    "snippingtool.exe",
    "appinstallerpythonredirector.exe",
    "chxsmartscreen.exe",
    "where.exe",
    "ucpdmgr.exe",
    "defrag.exe",
    "dataexchangehost.exe",
    "calculatorapp.exe",
    "applicationframehost.exe",
    "sihclient.exe",
    "uieorchestratorstub.exe",
    "uieorchestrator.exe",
    "microsoft.sharepoint.exe",
    "speechmodeldownload.exe",
    "disksnapshot.exe",
    "dstokenclean.exe",
    "dmclient.exe",
    "apphostregistrationverifier.exe",
    "cleanmgr.exe",
    "microsoft.lightbox.exe",
    "openwith.exe",
    "lpremove.exe",
    "midisrv.exe",
    "microsoft.data.usageandqualityinsights.maintenancetask.exe",
    "msmpeng.exe",
    "nissrv.exe",
    "securityhealthservice.exe",
    "securityhealthsystray.exe",
    "wmiadap.exe",
    "identity_helper.exe",
    "pickerhost.exe",
    "cookie_exporter.exe",
}


def _extract_exe_name(path_or_cmd: str) -> str:
    """Extract executable binary name from path or command line safely on any OS."""
    cleaned = path_or_cmd.strip()
    if cleaned.startswith('"'):
        end_idx = cleaned.find('"', 1)
        token = cleaned[1:end_idx] if end_idx != -1 else cleaned[1:]
    elif cleaned.startswith("'"):
        end_idx = cleaned.find("'", 1)
        token = cleaned[1:end_idx] if end_idx != -1 else cleaned[1:]
    else:
        token = cleaned.split()[0] if cleaned else ""
    token = token.replace("\\", "/")
    return token.rsplit("/", 1)[-1].lower()


def is_bare_shell(cmd: str) -> bool:
    """Check if command is just launching an interactive shell without arguments or script."""
    cleaned = cmd.strip().strip("\"'").replace("\\", "/")
    parts = cleaned.split()
    if not parts:
        return True
    exe = parts[0].rsplit("/", 1)[-1].lower()
    if exe in {"powershell.exe", "powershell", "cmd.exe", "cmd"}:
        return len(parts) == 1
    return False


def is_background_process(cmd: str, img: str = "") -> bool:
    """Determine if command or binary represents benign Windows OS background process noise."""
    if img:
        img_name = _extract_exe_name(img)
        if img_name in BACKGROUND_PROCESS_NOISE:
            return True
    low = cmd.lower().strip()
    if not low:
        return False
    if low.startswith("/quitinfo:"):
        return True
    if is_bare_shell(cmd):
        return True
    if any(
        flag in low
        for flag in [
            "--type=renderer",
            "--type=utility",
            "--type=gpu-process",
            "--type=crashpad-handler",
        ]
    ):
        return True
    if any(
        token in low
        for token in [
            "hpatchmon",
            "hotpatch",
            "pushtoinstall",
            "w32time",
            "acproxy.dll",
            "pcasvc.dll",
            "appxdeploymentclient.dll",
            "capabilityaccessmanager.dll",
            "startupscan.dll",
            "staterepositoryclient.dll",
            "sysmain.dll",
            "shell32.dll,shcreatelocalserverrundll",
            "sysmon-config.xml",
        ]
    ):
        return True
    exe_name = _extract_exe_name(cmd)
    return exe_name in BACKGROUND_PROCESS_NOISE


def is_telemetry_script(cmd: str, parent: str = "") -> bool:
    """Detect Windows compatibility telemetry scripts like CompatTelRunner invocations."""
    low_p = parent.lower()
    low_c = cmd.lower()
    if "compattelrunner" in low_p:
        return True
    return "final result:" in low_c


def is_harness_command(cmd: str) -> bool:
    """Check if command belongs to the A6 collection harness itself."""
    lower = cmd.lower()
    return any(h in lower for h in HARNESS_FILTERS)


def is_powershell_module_init(text: str) -> bool:
    """Determine if a PowerShell script block is standard internal module initialization."""
    clean = text.strip()
    if not clean:
        return True
    return any(pat.search(clean) for pat in POWERSHELL_MODULE_INIT_PATTERNS)


def is_command_base64(blob: str) -> bool:
    """Validate if string is legitimate encoded script or payload Base64."""
    if len(blob) < 16:
        return False
    try:
        raw = base64.b64decode(blob, validate=True)
        if len(raw) < 8:
            return False
        # MZ header (PE executable)
        if raw.startswith(b"MZ"):
            return True
        # UTF-16LE text (PowerShell -EncodedCommand standard)
        try:
            u16 = raw.decode("utf-16le")
            if any(
                k in u16.lower()
                for k in [
                    "http",
                    "download",
                    "invoke",
                    "powershell",
                    "cmd",
                    "iex",
                    "new-object",
                    "function",
                    "$",
                    "script",
                ]
            ):
                return True
        except Exception:
            pass
        # UTF-8 / ASCII script text
        try:
            u8 = raw.decode("utf-8")
            if any(
                k in u8.lower()
                for k in [
                    "http",
                    "download",
                    "invoke",
                    "powershell",
                    "cmd",
                    "iex",
                    "new-object",
                    "function",
                    "$",
                    "script",
                ]
            ):
                return True
        except Exception:
            pass
    except Exception:
        pass
    return False


def parse_process_snapshot_csv(snapshot_path: Path) -> list[dict[str, str]]:
    """Parse process_snapshot.csv into normalized process records."""
    if not snapshot_path.is_file():
        return []
    content = snapshot_path.read_text(encoding="utf-8-sig", errors="replace").strip()
    if not content:
        return []
    records = []
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    if not lines:
        return []
    reader = csv.DictReader(lines)
    if not reader.fieldnames:
        return []
    for row in reader:
        records.append({k.strip("\"'"): (v or "").strip("\"'") for k, v in row.items() if k})
    return records


class CommandExtractor:
    """Track B Command Feature Extractor.

    Extracts command-line strings, script blocks, and structural metrics from:
    - Sysmon EVTX (Event ID 1 process creation CommandLine, Event ID 12/13/14 registry)
    - PowerShell EVTX (Event ID 4104 ScriptBlockText)
    - process_snapshot.csv (process inventory)
    """

    def __init__(self) -> None:
        pass

    def extract(self, evidence_dir: Path | str, sample_id: str = "EXEC_RUN-001") -> CommandFeatures:
        """Extract CommandFeatures from evidence directory.

        Args:
            evidence_dir: Directory containing sysmon.evtx, powershell.evtx, or process_snapshot.csv.
            sample_id: Canonical sample identifier.

        Returns:
            CommandFeatures: Validated Pydantic model for command modality.
        """
        dir_path = Path(evidence_dir)
        if not dir_path.is_dir():
            if dir_path.is_file():
                dir_path = dir_path.parent
            else:
                raise FileNotFoundError(f"Evidence path does not exist: {evidence_dir}")

        # 1. Locate evidence files
        sysmon_files = list(dir_path.glob("sysmon.evtx")) + list(dir_path.glob("**/sysmon.evtx"))
        powershell_files = list(dir_path.glob("powershell.evtx")) + list(
            dir_path.glob("**/powershell.evtx")
        )
        process_csv_files = list(dir_path.glob("process_snapshot.csv")) + list(
            dir_path.glob("**/process_snapshot.csv")
        )

        # Also support pre-extracted xml / txt logs if present
        sysmon_xml_files = list(dir_path.glob("sysmon*.xml")) + list(
            dir_path.glob("**/sysmon*.xml")
        )
        powershell_xml_files = list(dir_path.glob("powershell*.xml")) + list(
            dir_path.glob("**/powershell*.xml")
        )

        sysmon_events: list[dict[str, str]] = []
        script_blocks: list[str] = []
        process_names: list[str] = []
        active_paths: list[str] = []
        registry_events_count = 0

        # 2. Extract from Sysmon EVTX
        if sysmon_files:
            sys_evs, reg_count = self._parse_sysmon_events(sysmon_files[0])
            sysmon_events.extend(sys_evs)
            registry_events_count += reg_count
        elif sysmon_xml_files:
            sys_evs, reg_count = self._parse_sysmon_xml(sysmon_xml_files[0])
            sysmon_events.extend(sys_evs)
            registry_events_count += reg_count

        # 3. Extract from PowerShell EVTX
        if powershell_files:
            ps_blocks = self._parse_powershell_events(powershell_files[0])
            script_blocks.extend(ps_blocks)
        elif powershell_xml_files:
            ps_blocks = self._parse_powershell_xml(powershell_xml_files[0])
            script_blocks.extend(ps_blocks)

        # 4. Extract from process_snapshot.csv
        all_paths: list[str] = []
        if process_csv_files:
            proc_records = parse_process_snapshot_csv(process_csv_files[0])
            for pr in proc_records:
                p_name = pr.get("ProcessName") or ""
                p_path = pr.get("Path") or ""
                if p_name:
                    process_names.append(p_name)
                if p_path and not is_harness_command(p_path):
                    all_paths.append(p_path)
                    if not is_background_process(p_path, p_path):
                        active_paths.append(p_path)

        commands = [
            e["command"]
            for e in sysmon_events
            if not is_harness_command(e["command"])
            and not is_background_process(e["command"], e.get("image", ""))
            and not is_telemetry_script(e["command"], e.get("parent_command", ""))
        ]
        script_blocks = [
            s
            for s in script_blocks
            if not is_harness_command(s) and not is_powershell_module_init(s)
        ]

        # 5. Synthesize primary salient command line
        raw_cmd = self._synthesize_salient_command(
            sysmon_events, script_blocks, process_names, active_paths, all_paths
        )

        # 6. Derive structured features
        cmd_len = len(raw_cmd)
        entropy = calculate_shannon_entropy(raw_cmd) if raw_cmd else 0.0
        is_b64 = self._detect_base64(raw_cmd, commands, script_blocks)
        has_cradle = self._detect_download_cradle(raw_cmd, commands, script_blocks)
        has_bypass = self._detect_bypass_policy(raw_cmd, commands, script_blocks)
        has_hidden = self._detect_hidden_window(raw_cmd, commands, script_blocks)
        uses_lolbin = self._detect_lolbins(raw_cmd, commands, process_names)
        reg_persistence = registry_events_count + self._detect_registry_persistence(
            commands, script_blocks
        )

        return CommandFeatures(
            sample_id=sample_id,
            raw_command_text=raw_cmd,
            command_length=cmd_len,
            shannon_entropy=entropy,
            is_base64_encoded=is_b64,
            has_download_cradle=has_cradle,
            has_bypass_execution_policy=has_bypass,
            has_hidden_window=has_hidden,
            uses_lolbins=uses_lolbin,
            registry_persistence_count=reg_persistence,
        )

    def _parse_sysmon_events(self, evtx_path: Path) -> tuple[list[dict[str, str]], int]:
        """Parse Sysmon EVTX for Event ID 1 (CommandLine, Image, Parent) and 12/13/14 (Registry)."""
        sys_events: list[dict[str, str]] = []
        reg_persistence_count = 0

        # Try win32evtlog on Windows
        try:
            import xml.etree.ElementTree as ET

            import win32evtlog

            q = win32evtlog.EvtQuery(str(evtx_path.resolve()), win32evtlog.EvtQueryFilePath)
            ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
            try:
                while True:
                    events = win32evtlog.EvtNext(q, 100)
                    if not events:
                        break
                    for e in events:
                        xml_str = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
                        root = ET.fromstring(xml_str)
                        eid_node = root.find("ns:System/ns:EventID", ns)
                        if eid_node is None or not eid_node.text:
                            continue
                        eid = eid_node.text.strip()

                        # Event 1: Process Creation
                        if eid == "1":
                            cmd, img, parent = "", "", ""
                            for data in root.findall(".//ns:Data", ns):
                                n = data.attrib.get("Name")
                                if n == "CommandLine" and data.text:
                                    cmd = data.text.strip()
                                elif n == "Image" and data.text:
                                    img = data.text.strip()
                                elif n == "ParentCommandLine" and data.text:
                                    parent = data.text.strip()
                            if cmd:
                                sys_events.append(
                                    {"command": cmd, "image": img, "parent_command": parent}
                                )

                        # Event 12, 13, 14: Registry Object Created, Value Set, Key Deleted
                        elif eid in ("12", "13", "14"):
                            for data in root.findall(".//ns:Data", ns):
                                if data.attrib.get("Name") == "TargetObject" and data.text:
                                    target = data.text.strip()
                                    for pat in REGISTRY_PERSISTENCE_PATTERNS:
                                        if pat.search(target):
                                            reg_persistence_count += 1
                                            break
                        with contextlib.suppress(Exception):
                            e.close()
            finally:
                with contextlib.suppress(Exception):
                    q.close()
            return sys_events, reg_persistence_count
        except Exception as err:
            logger.debug("win32evtlog query failed or unavailable: %s; falling back", err)

        # Fallback to python-evtx or raw string scanner
        return self._fallback_parse_sysmon(evtx_path)

    def _fallback_parse_sysmon(self, evtx_path: Path) -> tuple[list[dict[str, str]], int]:
        """Fallback scanner for Sysmon EVTX files on non-Windows platforms."""
        sys_events: list[dict[str, str]] = []
        reg_persistence_count = 0
        try:
            content = evtx_path.read_bytes()
            text_ascii = content.decode("ascii", errors="ignore")
            for match in re.finditer(r'Name=["\']CommandLine["\']>([^<]+)<', text_ascii):
                cmd = match.group(1).strip()
                if cmd and len(cmd) > 2:
                    sys_events.append({"command": cmd, "image": "", "parent_command": ""})

            for match in re.finditer(r'Name=["\']TargetObject["\']>([^<]+)<', text_ascii):
                tgt = match.group(1).strip()
                for pat in REGISTRY_PERSISTENCE_PATTERNS:
                    if pat.search(tgt):
                        reg_persistence_count += 1
                        break
        except Exception:
            pass
        return sys_events, reg_persistence_count

    def _parse_powershell_events(self, evtx_path: Path) -> list[str]:
        """Parse PowerShell EVTX for Event ID 4104 (ScriptBlockText), ignoring module inits."""
        script_blocks: list[str] = []

        try:
            import xml.etree.ElementTree as ET

            import win32evtlog

            q = win32evtlog.EvtQuery(str(evtx_path.resolve()), win32evtlog.EvtQueryFilePath)
            ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
            try:
                while True:
                    events = win32evtlog.EvtNext(q, 100)
                    if not events:
                        break
                    for e in events:
                        xml_str = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
                        root = ET.fromstring(xml_str)
                        eid_node = root.find("ns:System/ns:EventID", ns)
                        if eid_node is not None and eid_node.text == "4104":
                            for data in root.findall(".//ns:Data", ns):
                                if data.attrib.get("Name") == "ScriptBlockText" and data.text:
                                    text = data.text.strip()
                                    # Filter out normal PowerShell module initialization and harness
                                    if (
                                        text
                                        and not is_powershell_module_init(text)
                                        and not is_harness_command(text)
                                    ):
                                        script_blocks.append(text)
                        with contextlib.suppress(Exception):
                            e.close()
            finally:
                with contextlib.suppress(Exception):
                    q.close()
            return script_blocks
        except Exception as err:
            logger.debug("win32evtlog query failed for powershell.evtx: %s", err)

        # Fallback string scanner
        try:
            content = evtx_path.read_bytes()
            text_ascii = content.decode("ascii", errors="ignore")
            for match in re.finditer(r'Name=["\']ScriptBlockText["\']>([^<]+)<', text_ascii):
                block = match.group(1).strip()
                if block and not is_powershell_module_init(block) and not is_harness_command(block):
                    script_blocks.append(block)
        except Exception:
            pass

        return script_blocks

    def _parse_sysmon_xml(self, xml_path: Path) -> tuple[list[dict[str, str]], int]:
        """Parse pre-exported Sysmon XML."""
        import xml.etree.ElementTree as ET

        sys_events: list[dict[str, str]] = []
        reg_count = 0
        try:
            tree = ET.parse(xml_path)
            for event in tree.iter():
                if event.tag.endswith("Event"):
                    cmd, img, parent = "", "", ""
                    for data in event.iter():
                        name = data.attrib.get("Name")
                        if name == "CommandLine" and data.text:
                            cmd = data.text.strip()
                        elif name == "Image" and data.text:
                            img = data.text.strip()
                        elif name == "ParentCommandLine" and data.text:
                            parent = data.text.strip()
                        elif name == "TargetObject" and data.text:
                            for pat in REGISTRY_PERSISTENCE_PATTERNS:
                                if pat.search(data.text):
                                    reg_count += 1
                                    break
                    if cmd:
                        sys_events.append({"command": cmd, "image": img, "parent_command": parent})
        except Exception:
            pass
        return sys_events, reg_count

    def _parse_powershell_xml(self, xml_path: Path) -> list[str]:
        """Parse pre-exported PowerShell XML."""
        import xml.etree.ElementTree as ET

        script_blocks = []
        try:
            tree = ET.parse(xml_path)
            for event in tree.iter():
                for data in event.iter():
                    if data.attrib.get("Name") == "ScriptBlockText" and data.text:
                        txt = data.text.strip()
                        if (
                            txt
                            and not is_powershell_module_init(txt)
                            and not is_harness_command(txt)
                        ):
                            script_blocks.append(txt)
        except Exception:
            pass
        return script_blocks

    def _synthesize_salient_command(
        self,
        sysmon_events: list[dict[str, str]] | list[str],
        script_blocks: list[str],
        process_names: list[str],
        active_paths: list[str] | None = None,
        all_paths: list[str] | None = None,
    ) -> str:
        """Select or construct the most informative raw command string for NLP representation."""
        normalized_sys_events: list[dict[str, str]] = []
        for item in sysmon_events:
            if isinstance(item, dict):
                normalized_sys_events.append(item)
            elif isinstance(item, str):
                normalized_sys_events.append({"command": item, "image": "", "parent_command": ""})

        active_paths = active_paths or []
        active_set_lower = {p.lower() for p in process_names}
        candidates: list[tuple[float, str]] = []

        n_sys = len(normalized_sys_events)
        for idx, ev in enumerate(normalized_sys_events):
            cmd = ev.get("command", "")
            img = ev.get("image", "")
            parent = ev.get("parent_command", "")

            clean = " ".join(cmd.split())
            if not clean or is_harness_command(clean):
                continue
            if is_background_process(clean, img):
                continue
            if is_telemetry_script(clean, parent):
                continue

            score = 1.0  # Baseline score for genuine non-noise command
            if any(pat.search(clean) for pat in DOWNLOAD_CRADLE_PATTERNS):
                score += 10.0
            if any(pat.search(clean) for pat in BASE64_COMMAND_FLAGS):
                score += 8.0
            if any(pat.search(clean) for pat in BYPASS_POLICY_PATTERNS):
                score += 6.0
            if any(pat.search(clean) for pat in HIDDEN_WINDOW_PATTERNS):
                score += 6.0
            if any(re.search(rf"(?i)\b{lb}(?:\.exe)?\b", clean) for lb in LOLBINS_HIGH_RISK):
                score += 5.0
            if re.search(
                r"(?i)\b(?:powershell|cmd\.exe|wscript|cscript|mshta)\b", clean
            ) and not is_bare_shell(clean):
                score += 4.0

            # Substantive arguments bonus
            if len(clean.split()) > 1:
                score += 2.0

            # Active process snapshot bonus
            img_base = _extract_exe_name(img) if img else _extract_exe_name(clean)
            if img_base and (
                img_base in active_set_lower or Path(img_base).stem in active_set_lower
            ):
                score += 2.0

            # Recency factor: later events are closer to workload execution
            recency = idx / max(n_sys, 1)
            score += recency * 2.0

            # Shannon entropy bonus (capped to prevent noisy GUIDs/hashes from dominating)
            ent = calculate_shannon_entropy(clean)
            score += min(ent, 4.5) * 0.2

            candidates.append((score, clean))

        for blk in script_blocks:
            clean = " ".join(blk.split())
            if not clean or is_harness_command(clean) or is_powershell_module_init(clean):
                continue
            score = 5.0  # High baseline for non-init script blocks
            if any(pat.search(clean) for pat in DOWNLOAD_CRADLE_PATTERNS):
                score += 10.0
            if any(pat.search(clean) for pat in BASE64_COMMAND_FLAGS):
                score += 8.0
            if any(pat.search(clean) for pat in BYPASS_POLICY_PATTERNS):
                score += 6.0
            if any(pat.search(clean) for pat in HIDDEN_WINDOW_PATTERNS):
                score += 6.0

            ent = calculate_shannon_entropy(clean)
            score += min(ent, 4.5) * 0.2
            candidates.append((score, clean))

        if candidates:
            candidates.sort(key=lambda x: x[0], reverse=True)
            return candidates[0][1][:2048]

        if active_paths:
            return active_paths[0][:2048]

        if all_paths:
            return all_paths[0][:2048]

        # Genuine null semantics: when no workload command or script block was executed,
        # return empty string without fabricating fallback text.
        return ""

    def _detect_base64(self, raw_cmd: str, commands: list[str], script_blocks: list[str]) -> int:
        """Detect Base64 encoding in command lines or script blocks."""
        non_harness_cmds = [c for c in commands if not is_harness_command(c)]
        combined = " ".join([raw_cmd] + non_harness_cmds + script_blocks)
        for pat in BASE64_COMMAND_FLAGS:
            if pat.search(combined):
                return 1
        # Also check for base64 strings that decode to executable or script content
        for token in re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", combined):
            if is_command_base64(token):
                return 1
        return 0

    def _detect_download_cradle(
        self, raw_cmd: str, commands: list[str], script_blocks: list[str]
    ) -> int:
        """Detect web download cradles."""
        non_harness_cmds = [c for c in commands if not is_harness_command(c)]
        combined = " ".join([raw_cmd] + non_harness_cmds + script_blocks)
        for pat in DOWNLOAD_CRADLE_PATTERNS:
            if pat.search(combined):
                return 1
        return 0

    def _detect_bypass_policy(
        self, raw_cmd: str, commands: list[str], script_blocks: list[str]
    ) -> int:
        """Detect PowerShell execution policy bypass."""
        non_harness_cmds = [c for c in commands if not is_harness_command(c)]
        combined = " ".join([raw_cmd] + non_harness_cmds + script_blocks)
        for pat in BYPASS_POLICY_PATTERNS:
            if pat.search(combined):
                return 1
        return 0

    def _detect_hidden_window(
        self, raw_cmd: str, commands: list[str], script_blocks: list[str]
    ) -> int:
        """Detect hidden window execution flags."""
        non_harness_cmds = [c for c in commands if not is_harness_command(c)]
        combined = " ".join([raw_cmd] + non_harness_cmds + script_blocks)
        for pat in HIDDEN_WINDOW_PATTERNS:
            if pat.search(combined):
                return 1
        return 0

    def _detect_lolbins(self, raw_cmd: str, commands: list[str], process_names: list[str]) -> int:
        """Detect usage of Living-off-the-Land Binaries."""
        non_harness_cmds = [c for c in commands if not is_harness_command(c)]
        combined = " ".join([raw_cmd] + non_harness_cmds + process_names).lower()

        # Always-suspicious LOLBins
        for lb in LOLBINS_HIGH_RISK:
            if re.search(rf"\b{lb}(?:\.exe)?\b", combined):
                return 1

        # Context-dependent LOLBins: rundll32, wmic, cscript, wscript
        for cmd in [raw_cmd] + non_harness_cmds:
            cmd_lower = cmd.lower()
            if "rundll32" in cmd_lower:
                # Suspicious if loading from user-writable locations, temp, url, or using script protocols
                has_suspicious_rundll = (
                    any(
                        loc in cmd_lower
                        for loc in [
                            "\\appdata\\",
                            "\\temp\\",
                            "\\users\\",
                            "\\programdata\\",
                            "http:",
                            "https:",
                            "javascript:",
                            "vbscript:",
                            "scrobj.dll",
                        ]
                    )
                    or re.search(r",\s*#\d+", cmd_lower)  # Ordinal invocation
                    or (
                        not any(
                            sys_dir in cmd_lower
                            for sys_dir in [
                                "c:\\windows\\system32\\",
                                "c:\\windows\\syswow64\\",
                                "system32\\",
                            ]
                        )
                        and any(ext in cmd_lower for ext in [".dll", ".ocx"])
                    )
                )
                if has_suspicious_rundll:
                    return 1
            if "wmic" in cmd_lower and any(
                sus in cmd_lower for sus in ["process call", "create", "/node:", "shadowcopy"]
            ):
                return 1
            if any(s in cmd_lower for s in ["cscript", "wscript"]) and any(
                ext in cmd_lower for ext in [".vbs", ".js", ".wsf", "/e:"]
            ):
                return 1

        return 0

    def _detect_registry_persistence(self, commands: list[str], script_blocks: list[str]) -> int:
        """Detect explicit registry persistence command patterns."""
        count = 0
        combined = commands + script_blocks
        for text in combined:
            for pat in REGISTRY_PERSISTENCE_PATTERNS:
                if pat.search(text):
                    count += 1
                    break
        return count


def extract_command_features(
    evidence_dir: Path | str, sample_id: str = "EXEC_RUN-001"
) -> CommandFeatures:
    """Functional convenience entry point for Command feature extraction."""
    extractor = CommandExtractor()
    return extractor.extract(evidence_dir=evidence_dir, sample_id=sample_id)


def main() -> None:
    """CLI interface for Command feature extraction."""
    parser = argparse.ArgumentParser(description="Extract Track B Command features from evidence")
    parser.add_argument(
        "--input-dir",
        "-i",
        type=Path,
        required=True,
        help="Directory containing sysmon.evtx / powershell.evtx / process_snapshot.csv",
    )
    parser.add_argument(
        "--sample-id",
        "-s",
        type=str,
        default="EXEC_RUN-001",
        help="Sample identifier",
    )
    parser.add_argument(
        "--output-file",
        "-o",
        type=Path,
        default=None,
        help="Optional output JSON file path",
    )
    args = parser.parse_args()

    features = extract_command_features(args.input_dir, sample_id=args.sample_id)
    out_json = features.model_dump_json(indent=2)
    if args.output_file:
        args.output_file.parent.mkdir(parents=True, exist_ok=True)
        args.output_file.write_text(out_json, encoding="utf-8")
        print(f"[+] Wrote command features to {args.output_file}")
    else:
        print(out_json)


if __name__ == "__main__":
    main()
