import sys
from pathlib import Path
import xml.etree.ElementTree as ET
import win32evtlog

dataset_root = Path("Dataset")

sample_runs = [
    ("custom_powershell_fileless", "RUN-002"),
    ("custom_process_hollowing", "RUN-100"),
    ("custom_cobalt_strike_beacon", "RUN-400"),
]

system_imgs = {
    "sysmon64.exe", "unsecapp.exe", "taskhostw.exe", "svchost.exe", "services.exe",
    "conhost.exe", "dllhost.exe", "ctfmon.exe", "audiodg.exe", "smartscreen.exe",
    "microsoftedgeupdate.exe", "msedge.exe", "searchindexer.exe", "tiworker.exe",
    "trustedinstaller.exe", "wmiprvse.exe", "lsass.exe", "csrss.exe"
}

harness_frags = [
    "fmd-collector", "collect_run", "dumpit", "wevtutil", "hash-evidence"
]

for cat, run_id in sample_runs:
    run_dir = dataset_root / cat / "source_evidence" / run_id
    sysmon_f = run_dir / "sysmon.evtx"
    
    print("\n" + "="*60)
    print(f"SEARCHING PAYLOAD IN: {cat}/{run_id}")
    
    q = win32evtlog.EvtQuery(str(sysmon_f.resolve()), win32evtlog.EvtQueryFilePath)
    ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
    
    survivors = []
    try:
        events = win32evtlog.EvtNext(q, 100)
        while events:
            for e in events:
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
                    img_name = Path(img).name.lower()
                    if img_name not in system_imgs:
                        # Check harness
                        if not any(hf in cmd.lower() for hf in harness_frags):
                            survivors.append({"cmd": cmd, "img": img, "parent": parent})
                e.close()
            events = win32evtlog.EvtNext(q, 100)
    finally:
        q.close()
        
    print(f"Non-system, non-harness commands found: {len(survivors)}")
    for s in survivors[:15]:
        print(f"  [{Path(s['img']).name}] {s['cmd']}")
