import json
from pathlib import Path

models_info = {}

for m in ["process", "command", "network", "memory"]:
    meta_p = Path(f"models/artifacts/{m}/metadata.json")
    if meta_p.exists():
        with open(meta_p, "r", encoding="utf-8") as f:
            models_info[m] = json.load(f)

# Multiclass
mc_meta_p = Path("models/multiclass/artifacts/metrics.json")
if mc_meta_p.exists():
    with open(mc_meta_p, "r", encoding="utf-8") as f:
        models_info["multiclass"] = json.load(f)

with open("evaluation/dataset_inventory/all_models_metadata.json", "w", encoding="utf-8") as f:
    json.dump(models_info, f, indent=2)

print("Saved all models metadata to evaluation/dataset_inventory/all_models_metadata.json")
for m, info in models_info.items():
    print(f"\n--- {m.upper()} ---")
    for k in ["model_type", "algorithm", "dataset_source", "dataset_path", "train_sample_count", "total_samples", "feature_names", "features", "hyperparameters"]:
        if k in info:
            v = info[k]
            if isinstance(v, list) and len(v) > 5:
                print(f"  {k}: [{len(v)} features: {v[:3]}...]")
            else:
                print(f"  {k}: {v}")
