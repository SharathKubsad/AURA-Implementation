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

# Find reflective dll sample
sample = [s for s in BUILTIN_SAMPLE_COMMANDS if s["category"] == "Reflective DLL Injection"][0]
res = svc.analyze_command(sample["command"])

fused_sim = {
    **res["observed_telemetry"]["process"],
    **res["extracted_features"],
    **res["observed_telemetry"]["network"],
    **res["observed_telemetry"]["memory"],
}

rows = [json.loads(line) for line in Path("data/processed/unified/unified_dataset.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
df = pd.DataFrame(rows)
mal = df[df["binary_label"] == 1].copy()
mal["canon_family"] = mal["family"].apply(to_canonical_family)
cols = [c for c in ALL_NUMERIC_FEATURE_COLS if c in df.columns]

mean_row = mal[mal["canon_family"] == "reflective_dll_injection"][cols].mean().fillna(0.0)

print("Feature comparison for Reflective DLL Injection:")
print(f"{'Feature':32s} | {'Simulated':10s} | {'Canonical Mean':15s}")
print("-" * 65)
for c in cols:
    sim_v = fused_sim.get(c, 0.0)
    mean_v = mean_row.get(c, 0.0)
    diff = abs(sim_v - mean_v)
    flag = " <--- DIFF" if diff > 0.1 else ""
    print(f"{c:32s} | {sim_v:10.2f} | {mean_v:15.2f}{flag}")
