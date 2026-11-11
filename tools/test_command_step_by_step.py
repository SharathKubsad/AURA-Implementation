import sys
import tarfile
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(".").resolve()))
from forensics.command.command_extractor import CommandExtractor

archives_dir = Path("C:/FMD-Dataset/archives")

print("Investigating Command extraction from source evidence...")

# Unpack RUN-001 and RUN-1100 source evidence to tempdir and run CommandExtractor with debug logging
def test_sample(archive_name, run_id):
    a_path = archives_dir / archive_name
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        # extract source_evidence for run_id
        with tarfile.open(a_path, "r:gz") as tar:
            for m in tar.getmembers():
                if f"source_evidence/{run_id}/" in m.name.replace("\\", "/"):
                    tar.extract(m, tmp)
        
        ev_dir = None
        for p in tmp.rglob(run_id):
            if p.is_dir() and (p / "process_snapshot.csv").exists():
                ev_dir = p
                break
                
        if not ev_dir:
            print(f"Could not find unpacked evidence dir for {run_id}")
            return
            
        print(f"\n--- Testing {run_id} ({archive_name}) ---")
        print("Files present in evidence dir:", [f.name for f in ev_dir.iterdir()])
        
        ext = CommandExtractor()
        # Test sysmon parsing directly
        sysmon_files = list(ev_dir.glob("*sysmon*.evtx"))
        if sysmon_files:
            try:
                import win32evtlog
                print("win32evtlog module is present.")
                q = win32evtlog.EvtQuery(str(sysmon_files[0].resolve()), win32evtlog.EvtQueryFilePath)
                print("EvtQuery succeeded:", q)
            except Exception as e:
                print("win32evtlog.EvtQuery error:", type(e), e)
            sys_evs, reg_cnt = ext._parse_sysmon_events(sysmon_files[0])
            print(f"Sysmon events parsed: {len(sys_evs)}, reg_cnt: {reg_cnt}")
            if sys_evs:
                print("First 3 sysmon events:", sys_evs[:3])
        
        # Test powershell parsing directly
        ps_files = list(ev_dir.glob("*powershell*.evtx"))
        if ps_files:
            ps_blocks = ext._parse_powershell_events(ps_files[0])
            print(f"PowerShell script blocks parsed: {len(ps_blocks)}")
            if ps_blocks:
                print("First 2 script blocks:", [b[:100] for b in ps_blocks[:2]])
                
        # Test full extraction
        feat = ext.extract(ev_dir, sample_id=f"EXEC_{run_id}")
        print(f"Extracted raw_command_text: {repr(feat.raw_command_text)}")
        print(f"Extracted command_length: {feat.command_length}")
        print(f"Extracted uses_lolbins: {feat.uses_lolbins}")
        print(f"Extracted has_bypass: {feat.has_bypass_execution_policy}")

test_sample("custom_powershell_fileless.tar.gz", "RUN-001")
test_sample("custom_benign_batch.tar.gz", "RUN-1100")
