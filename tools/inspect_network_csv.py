import tarfile
from pathlib import Path

archives_dir = Path("C:/FMD-Dataset/archives")

def check_network_csv(archive_name, run_id):
    a_path = archives_dir / archive_name
    with tarfile.open(a_path, "r:gz") as tar:
        for m in tar.getmembers():
            if f"source_evidence/{run_id}/network_connections.csv" in m.name.replace("\\", "/"):
                f = tar.extractfile(m)
                lines = f.read().decode("utf-8", errors="replace").splitlines()
                print(f"--- {run_id} ({archive_name}) network_connections.csv ({len(lines)} lines) ---")
                for l in lines[:15]:
                    print("  ", l)
                # Count listening ports
                import csv
                reader = csv.DictReader(lines)
                listen_ports = set()
                for r in reader:
                    st = r.get("State", "").upper()
                    if "LISTEN" in st:
                        listen_ports.add(r.get("LocalPort"))
                print(f"  Total listening ports found: {len(listen_ports)} -> {sorted(list(listen_ports))}")

check_network_csv("custom_powershell_fileless.tar.gz", "RUN-001")
check_network_csv("custom_process_hollowing.tar.gz", "RUN-100")
check_network_csv("custom_benign_batch.tar.gz", "RUN-1100")
