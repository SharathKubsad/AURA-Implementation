import json
from pathlib import Path
import os
import datetime

models_dir = Path("models/artifacts")
model_types = ["process", "command", "network", "memory"]

print("=== AUDITING EXISTING BINARY MODELS ===")
for m in model_types:
    m_dir = models_dir / m
    meta_f = m_dir / "metadata.json"
    feat_f = m_dir / "features.json"
    print(f"\nModel: {m.upper()}")
    if meta_f.exists():
        with open(meta_f, "r", encoding="utf-8") as f:
            meta = json.load(f)
        print("  Algorithm:", meta.get("model_type") or meta.get("algorithm"))
        print("  Trained on:", meta.get("training_dataset_path") or meta.get("dataset"))
        print("  Training samples:", meta.get("train_samples") or meta.get("num_samples"))
        print("  Val / Test samples:", meta.get("val_samples"), "/", meta.get("test_samples"))
        print("  Timestamp:", meta.get("trained_at_utc") or meta.get("timestamp"))
        print("  Metrics:", meta.get("test_metrics") or meta.get("metrics"))
    if feat_f.exists():
        with open(feat_f, "r", encoding="utf-8") as f:
            feats = json.load(f)
        print(f"  Features ({len(feats) if isinstance(feats, list) else len(feats.get('features', []))}):", feats)

print("\n=== AUDITING MULTICLASS MODEL ===")
mc_dir = Path("models/multiclass/artifacts")
mc_meta = mc_dir / "metrics.json"
mc_feat = mc_dir / "features.json"
mc_map = mc_dir / "family_label_map.json"
if mc_meta.exists():
    with open(mc_meta, "r", encoding="utf-8") as f:
        meta = json.load(f)
    print("  Algorithm: XGBClassifier (Multi-class)")
    print("  Trained on:", meta.get("dataset_path"))
    print("  Total samples:", meta.get("total_samples"))
    print("  Num classes:", meta.get("num_classes"))
    print("  Accuracy:", meta.get("accuracy"))
    print("  LOO Accuracy:", meta.get("leave_one_out_accuracy"))
if mc_feat.exists():
    with open(mc_feat, "r", encoding="utf-8") as f:
        feats = json.load(f)
    print(f"  Features count ({len(feats)}):", feats)
if mc_map.exists():
    with open(mc_map, "r", encoding="utf-8") as f:
        fmap = json.load(f)
    print("  Classes:", fmap)
