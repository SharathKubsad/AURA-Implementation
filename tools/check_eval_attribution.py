import sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))
import pandas as pd
import numpy as np
from xgboost import XGBClassifier
import json

from framework.command_samples import BUILTIN_SAMPLE_COMMANDS
from framework.detection_service import DetectionService

svc = DetectionService()

for sample in BUILTIN_SAMPLE_COMMANDS:
    res = svc.analyze_command(sample["command"])
    print(f"Cat: {sample['category'][:22]:22s} | Expected: {sample['family_theme']:25s} -> Verdict: {res['verdict']} | Family: {res.get('family')} ({res.get('family_confidence')})")
