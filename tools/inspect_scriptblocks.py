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

for cat, run_id in sample_runs:
    ps_f = dataset_root / cat / "source_evidence" / run_id / "powershell.evtx"
    q_ps = win32evtlog.EvtQuery(str(ps_f.resolve()), win32evtlog.EvtQueryFilePath)
    ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
    non_inits = []
    try:
        events = win32evtlog.EvtNext(q_ps, 100)
        while events:
            for e in events:
                xml_str = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
                root = ET.fromstring(xml_str)
                eid = root.find("ns:System/ns:EventID", ns)
                if eid is not None and eid.text == "4104":
                    for d in root.findall(".//ns:Data", ns):
                        if d.attrib.get("Name") == "ScriptBlockText" and d.text:
                            txt = d.text.strip()
                            if "$__cmdletization" not in txt and "Set-StrictMode" not in txt and "prompt" not in txt:
                                if not any(h in txt.lower() for h in ["fmd-collector", "collect_run", "get-nettcpconnection"]):
                                    non_inits.append(txt)
                e.close()
            events = win32evtlog.EvtNext(q_ps, 100)
    finally:
        q_ps.close()
    print(f"\n{cat}/{run_id} non-init script blocks: {len(non_inits)}")
    for s in non_inits[:5]:
        print("  --- BLOCK ---")
        print(" ", s[:200].replace("\n", " "))
