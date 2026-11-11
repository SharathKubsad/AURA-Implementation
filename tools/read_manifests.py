import json
from pathlib import Path

dataset_root = Path("Dataset")
for m_path in sorted(dataset_root.glob("*/manifest.json")):
    with open(m_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    print(f"{m_path.parent.name}:")
    print(f"  dataset: {data.get('dataset')}")
    print(f"  label: {data.get('label')}")
    print(f"  family: {data.get('family')}")
    print(f"  runs list ({len(data.get('runs', []))}): {data.get('runs', [])}")
    print(f"  pipeline flags: {data.get('pipeline')}")
    print(f"  notes: {data.get('notes')}")
