import json
import sys
from pathlib import Path
import pandas as pd
import numpy as np
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from models.multiclass.train_on_custom import to_canonical_family
from preprocessing.pipeline import ALL_NUMERIC_FEATURE_COLS

rows = [json.loads(line) for line in Path("data/processed/unified/unified_dataset.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
df = pd.DataFrame(rows)
mal = df[df["binary_label"] == 1].copy()
mal["canon_family"] = mal["family"].apply(to_canonical_family)

print("Distribution of canonical families:")
print(mal["canon_family"].value_counts())

for fam, g in mal.groupby("canon_family"):
    print(f"\n=================== {fam} ({len(g)} samples) ===================")
    for col in ALL_NUMERIC_FEATURE_COLS:
        if col in g:
            val = g[col].mean()
            if not np.isnan(val) and abs(val) > 0.001:
                print(f"  {col:30s}: {val:.2f}")
