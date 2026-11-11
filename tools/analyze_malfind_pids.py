import sys
import tarfile
from pathlib import Path
sys.path.insert(0, str(Path(".").resolve()))
from forensics.extraction.parser_utils import parse_malfind_output
import io

archives_dir = Path("C:/FMD-Dataset/archives")

runs_to_inspect = [
    ("custom_benign_batch.tar.gz", "volatility/RUN-1100/malfind.txt", "RUN-1100 (Benign)"),
    ("custom_benign_batch.tar.gz", "volatility/RUN-1101/malfind.txt", "RUN-1101 (Benign)"),
    ("custom_benign_batch.tar.gz", "volatility/RUN-1102/malfind.txt", "RUN-1102 (Benign)"),
    ("custom_powershell_fileless.tar.gz", "volatility/RUN-001/malfind.txt", "RUN-001 (PS Fileless)"),
    ("custom_process_hollowing.tar.gz", "volatility/RUN-100/malfind.txt", "RUN-100 (Process Hollowing)"),
    ("custom_cobalt_strike_beacon.tar.gz", "volatility/RUN-400/malfind.txt", "RUN-400 (Cobalt Strike)"),
]

for arch, pth, label in runs_to_inspect:
    a_path = archives_dir / arch
    with tarfile.open(a_path, "r:gz") as tar:
        for m in tar.getmembers():
            if m.name.endswith(pth):
                f = tar.extractfile(m)
                lines = f.read().decode("utf-8", errors="replace").splitlines()
                # Parse entries: find lines with PID and Process
                findings = []
                for line in lines:
                    parts = line.split("\t")
                    if len(parts) >= 6 and parts[0].isdigit():
                        findings.append({
                            "pid": int(parts[0]),
                            "process": parts[1],
                            "vpn": parts[2],
                            "tag": parts[4],
                            "protection": parts[5]
                        })
                pids = {f["pid"]: f["process"] for f in findings}
                print(f"{label}:")
                print(f"  Total malfind injection records: {len(findings)}")
                print(f"  Unique PIDs in malfind: {pids}")
                for pid, proc in pids.items():
                    cnt = sum(1 for f in findings if f["pid"] == pid)
                    print(f"    PID {pid} ({proc}): {cnt} regions")
