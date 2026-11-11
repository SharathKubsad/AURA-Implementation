import sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))
import json
import pandas as pd
import numpy as np
from framework.command_samples import BUILTIN_SAMPLE_COMMANDS
from framework.detection_service import DetectionService
from models.multiclass.train_on_custom import to_canonical_family
from preprocessing.pipeline import ALL_NUMERIC_FEATURE_COLS

svc = DetectionService()

# Load training data mean per canonical family
rows = [json.loads(line) for line in Path("data/processed/unified/unified_dataset.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
df = pd.DataFrame(rows)
mal = df[df["binary_label"] == 1].copy()
mal["canon_family"] = mal["family"].apply(to_canonical_family)
cols = [c for c in ALL_NUMERIC_FEATURE_COLS if c in df.columns]

for sample in BUILTIN_SAMPLE_COMMANDS:
    cat = sample["category"]
    theme = sample["family_theme"]
    cmd_text = sample["command"]
    
    # Extract command features
    cmd_feat = svc.cmd_collector.collect(command_override=cmd_text)
    
    # Get ground truth canonical mean features for this theme if malware
    expected_canon = to_canonical_family(theme) if theme != "benign" else "benign"
    
    # Predict using analyze_command
    res = svc.analyze_command(cmd_text)
    pred_fam = res.get("family")
    pred_conf = res.get("family_confidence")
    
    print(f"\n=======================================================")
    print(f"Preset Category: {cat}")
    print(f"Expected Theme : {theme} (canonical: {expected_canon})")
    print(f"Verdict        : {res['verdict']} (Confidence: {res['confidence']:.3f})")
    print(f"Predicted Fam  : {pred_fam} (Conf: {pred_conf})")
    
    # If not matching and malware, test feeding canonical mean features into multiclass model
    if expected_canon != "benign":
        mean_row = mal[mal["canon_family"] == expected_canon][cols].mean().fillna(0.0)
        p = svc.multiclass_model.predict_proba(pd.DataFrame([mean_row]))[0]
        arg = np.argmax(p)
        direct_pred = svc.multiclass_label_map.get(arg)
        print(f"Direct Canonical Mean Prediction: {direct_pred} (Conf: {p[arg]:.3f})")
