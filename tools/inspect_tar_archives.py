import tarfile
from pathlib import Path

archives_dir = Path("C:/FMD-Dataset/archives")
if archives_dir.exists():
    archives = list(archives_dir.glob("*.tar.gz"))
    print(f"Found {len(archives)} archives in {archives_dir}:")
    for a in sorted(archives):
        try:
            with tarfile.open(a, "r:gz") as tar:
                members = tar.getnames()
                print(f"  {a.name}: {len(members)} files/dirs. Sample members:")
                for m in members[:8]:
                    print(f"    - {m}")
        except Exception as e:
            print(f"  {a.name}: Error opening - {e}")
else:
    print(f"{archives_dir} does not exist!")
