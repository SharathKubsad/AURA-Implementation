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

for sample in BUILTIN_SAMPLE_COMMANDS:
    cat = sample["category"]
    theme = sample["family_theme"]
    cmd_text = sample["command"]
    
    res = svc.analyze_command(cmd_text)
    pred_fam = res.get("family")
    pred_conf = res.get("family_confidence")
    probs = res.get("family_probabilities", {})
    top3 = sorted(probs.items(), key=lambda x: x[1], reverse=True)[:3]
    top3_str = ", ".join([f"{k}: {v}" for k, v in top3])
    print(f"[{cat[:20]:20s}] Theme: {theme:26s} -> Pred: {str(pred_fam):26s} (conf: {pred_conf}) | Top3: {top3_str}")
