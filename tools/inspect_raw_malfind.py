import tarfile
from pathlib import Path

archives_dir = Path("C:/FMD-Dataset/archives")

def extract_file_content(archive_name, relative_path):
    a_path = archives_dir / archive_name
    with tarfile.open(a_path, "r:gz") as tar:
        for m in tar.getmembers():
            if m.name.endswith(relative_path):
                f = tar.extractfile(m)
                if f:
                    return f.read().decode("utf-8", errors="replace")
    return None

samples_to_check = [
    # 3 Benign
    ("custom_benign_batch.tar.gz", "volatility/RUN-1100/malfind.txt", "RUN-1100 (Benign)"),
    ("custom_benign_batch.tar.gz", "volatility/RUN-1101/malfind.txt", "RUN-1101 (Benign)"),
    ("custom_benign_batch.tar.gz", "volatility/RUN-1102/malfind.txt", "RUN-1102 (Benign)"),
    # 3 Malware
    ("custom_powershell_fileless.tar.gz", "volatility/RUN-001/malfind.txt", "RUN-001 (PowerShell Fileless)"),
    ("custom_process_hollowing.tar.gz", "volatility/RUN-100/malfind.txt", "RUN-100 (Process Hollowing)"),
    ("custom_cobalt_strike_beacon.tar.gz", "volatility/RUN-400/malfind.txt", "RUN-400 (Cobalt Strike)"),
]

for arch, path, desc in samples_to_check:
    print("="*60)
    print(f"CHECKING: {desc}")
    print(f"Path: {arch} -> {path}")
    content = extract_file_content(arch, path)
    if content:
        lines = content.strip().split("\n")
        print(f"Total lines: {len(lines)}")
        print("First 30 lines:")
        for l in lines[:30]:
            print(f"  {l}")
    else:
        print("FILE NOT FOUND!")
