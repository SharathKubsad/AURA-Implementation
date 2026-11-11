import sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))
import json
import pandas as pd
import numpy as np

from framework.command_samples import BUILTIN_SAMPLE_COMMANDS
from framework.detection_service import DetectionService
from models.multiclass.train_on_custom import to_canonical_family

svc = DetectionService()

passed = 0
total = 0

for sample in BUILTIN_SAMPLE_COMMANDS:
    cat = sample["category"]
    theme = sample["family_theme"]
    cmd_text = sample["command"]
    expected_canon = to_canonical_family(theme) if theme != "benign" else "benign"
    
    res = svc.analyze_command(cmd_text)
    pred_fam = res.get("family")
    pred_conf = res.get("family_confidence")
    
    total += 1
    if theme == "benign":
        is_ok = res["verdict"] == "benign"
    else:
        pred_slug = to_canonical_family(pred_fam) if pred_fam else "none"
        is_ok = (res["verdict"] == "malware") and (pred_slug == expected_canon)
    
    if is_ok:
        passed += 1
        status = "PASS"
    else:
        status = "FAIL"
        
    print(f"[{status}] {cat[:20]:20s} | Exp: {expected_canon:26s} | Pred: {str(pred_fam):26s} (conf: {pred_conf})")

print(f"\nOverall: {passed}/{total} ({passed/total*100:.1f}%)")
