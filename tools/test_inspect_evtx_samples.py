import sys
from pathlib import Path
import xml.etree.ElementTree as ET

try:
    import win32evtlog
    has_win32 = True
except ImportError:
    has_win32 = False

print(f"win32evtlog available: {has_win32}")

dataset_root = Path("Dataset")

sample_runs = [
    ("custom_powershell_fileless", "RUN-001"),
    ("custom_powershell_fileless", "RUN-002"),
    ("custom_process_hollowing", "RUN-100"),
    ("custom_cobalt_strike_beacon", "RUN-400"),
    ("custom_benign_batch", "RUN-1100"),
    ("custom_benign_batch", "RUN-1105"),
]

for cat, run_id in sample_runs:
    run_dir = dataset_root / cat / "source_evidence" / run_id
    sysmon_f = run_dir / "sysmon.evtx"
    ps_f = run_dir / "powershell.evtx"
    
    print("\n" + "="*50)
    print(f"Sample: {cat}/{run_id}")
    print(f"  sysmon.evtx: {sysmon_f.stat().st_size} bytes")
    print(f"  powershell.evtx: {ps_f.stat().st_size} bytes")
    
    if has_win32:
        # Check Sysmon
        q = win32evtlog.EvtQuery(str(sysmon_f.resolve()), win32evtlog.EvtQueryFilePath)
        ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        e_count = 0
        cmd_events = []
        try:
            events = win32evtlog.EvtNext(q, 100)
            while events:
                for e in events:
                    e_count += 1
                    xml_str = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
                    root = ET.fromstring(xml_str)
                    eid = root.find("ns:System/ns:EventID", ns)
                    if eid is not None and eid.text == "1":
                        cmd, img, parent = "", "", ""
                        for d in root.findall(".//ns:Data", ns):
                            n = d.attrib.get("Name")
                            if n == "CommandLine" and d.text:
                                cmd = d.text.strip()
                            elif n == "Image" and d.text:
                                img = d.text.strip()
                            elif n == "ParentCommandLine" and d.text:
                                parent = d.text.strip()
                        if cmd:
                            cmd_events.append({"cmd": cmd, "img": img, "parent": parent})
                    e.close()
                events = win32evtlog.EvtNext(q, 100)
        finally:
            q.close()
        print(f"  Sysmon total events: {e_count}, Event 1 (ProcessCreate): {len(cmd_events)}")
        if cmd_events:
            print("  First 3 process creations:")
            for ce in cmd_events[:3]:
                print(f"    [{Path(ce['img']).name}] {ce['cmd'][:120]}")
            print("  Last 3 process creations:")
            for ce in cmd_events[-3:]:
                print(f"    [{Path(ce['img']).name}] {ce['cmd'][:120]}")

        # Check PowerShell
        q_ps = win32evtlog.EvtQuery(str(ps_f.resolve()), win32evtlog.EvtQueryFilePath)
        ps_count = 0
        script_blocks = []
        try:
            events = win32evtlog.EvtNext(q_ps, 100)
            while events:
                for e in events:
                    ps_count += 1
                    xml_str = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
                    root = ET.fromstring(xml_str)
                    eid = root.find("ns:System/ns:EventID", ns)
                    if eid is not None and eid.text == "4104":
                        for d in root.findall(".//ns:Data", ns):
                            if d.attrib.get("Name") == "ScriptBlockText" and d.text:
                                script_blocks.append(d.text.strip())
                    e.close()
                events = win32evtlog.EvtNext(q_ps, 100)
        finally:
            q_ps.close()
        print(f"  PowerShell total events: {ps_count}, Event 4104 (ScriptBlock): {len(script_blocks)}")
        if script_blocks:
            print("  First 2 script blocks:")
            for sb in script_blocks[:2]:
                print(f"    {sb[:120]!r}")
