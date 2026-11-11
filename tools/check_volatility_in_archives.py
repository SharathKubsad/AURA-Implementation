import tarfile
from pathlib import Path
import json

archives_dir = Path("C:/FMD-Dataset/archives")

print("Checking Volatility plugin files inside all 12 archives...")

all_runs_vol = {}

for a in sorted(archives_dir.glob("*.tar.gz")):
    with tarfile.open(a, "r:gz") as tar:
        for m in tar.getmembers():
            # typical pattern: <pkg>/volatility/<RUN-ID>/... or <pkg>/volatility/...
            if "volatility" in m.name and m.isfile():
                parts = m.name.split("/")
                # find where volatility is
                idx = parts.index("volatility")
                run_id = parts[idx+1] if len(parts) > idx + 1 else "root"
                fname = parts[-1]
                if run_id not in all_runs_vol:
                    all_runs_vol[run_id] = {}
                all_runs_vol[run_id][fname] = m.size

print(f"Total runs found in volatility directories across archives: {len(all_runs_vol)}")
for run_id in sorted(all_runs_vol.keys())[:10]:
    plugins = all_runs_vol[run_id]
    print(f"Run {run_id} ({len(plugins)} files):")
    for p, sz in sorted(plugins.items()):
        print(f"   {p}: {sz} bytes")
