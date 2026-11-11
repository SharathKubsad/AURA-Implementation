import sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))

import json
import pandas as pd
import numpy as np
from xgboost import XGBClassifier
from preprocessing.pipeline import ALL_NUMERIC_FEATURE_COLS

with open("models/multiclass/artifacts/label_mapping.json") as f:
    label_map = json.load(f)

clf = XGBClassifier()
clf.load_model("models/multiclass/artifacts/multiclass_model.xgb")

print("Classes in model:", clf.n_classes_)
print("Label mapping:", label_map)

# Check training data predictions with the model
rows = [json.loads(line) for line in Path("data/processed/unified/unified_dataset.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
df = pd.DataFrame(rows)
mal = df[df["binary_label"] == 1].copy()

from models.multiclass.train_on_custom import to_canonical_family
mal["canon_family"] = mal["family"].apply(to_canonical_family)

cols = [c for c in ALL_NUMERIC_FEATURE_COLS if c in df.columns]
X = mal[cols].fillna(0.0)

probs = clf.predict_proba(X)
preds = np.argmax(probs, axis=1)
pred_names = [label_map[str(p)] for p in preds]
mal["pred_family"] = pred_names

print("\nConfusion Matrix on Training Data:")
ct = pd.crosstab(mal["canon_family"], mal["pred_family"], margins=True)
print(ct.to_string())
