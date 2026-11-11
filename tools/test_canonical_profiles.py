import sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))
import json
import pandas as pd
import numpy as np

from framework.command_samples import BUILTIN_SAMPLE_COMMANDS
from models.multiclass.train_on_custom import to_canonical_family
from preprocessing.pipeline import ALL_NUMERIC_FEATURE_COLS
from xgboost import XGBClassifier

with open("models/multiclass/artifacts/label_mapping.json") as f:
    label_map = json.load(f)

clf = XGBClassifier()
clf.load_model("models/multiclass/artifacts/multiclass_model.xgb")

cols = [
    "total_process_count", "hidden_process_count", "anomalous_ppid_count",
    "avg_threads_per_process", "max_threads_in_single_process", "total_handle_count",
    "suspicious_dll_count", "malfind_process_count", "elevated_privilege_count",
    "unlinked_dll_count", "rwx_page_count", "injected_code_regions",
    "unmapped_executable_pages", "vad_protection_anomaly_count",
    "ldrmodules_inconsistencies", "yara_shellcode_matches",
    "mean_memory_entropy", "max_memory_entropy", "command_length",
    "shannon_entropy", "is_base64_encoded", "has_download_cradle",
    "has_bypass_execution_policy", "has_hidden_window", "uses_lolbins",
    "registry_persistence_count", "active_connection_count", "listening_port_count",
    "outbound_connection_count", "dns_query_count", "unique_remote_ips",
    "avg_interpacket_interval_ms", "beacon_regularity_score", "total_bytes_sent",
    "total_bytes_received", "suspicious_port_usage"
]

# Load mean feature row per canonical family from training data
rows = [json.loads(line) for line in Path("data/processed/unified/unified_dataset.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
df = pd.DataFrame(rows)
mal = df[df["binary_label"] == 1].copy()
mal["canon_family"] = mal["family"].apply(to_canonical_family)

canonical_profiles = {}
for fam, g in mal.groupby("canon_family"):
    canonical_profiles[fam] = g[[c for c in cols if c in g.columns]].mean().fillna(0.0).to_dict()

print(f"Loaded {len(canonical_profiles)} canonical profiles.")

# Test each profile with clf
for fam, prof in canonical_profiles.items():
    raw_df = pd.DataFrame([prof])
    for c in cols:
        if c not in raw_df.columns:
            raw_df[c] = 0.0
    df_row = raw_df[cols].fillna(0.0)
    
    probs = clf.predict_proba(df_row)[0]
    arg = np.argmax(probs)
    pred_slug = label_map[str(arg)]
    print(f"Family: {fam:26s} -> Model Pred: {pred_slug:26s} (Prob: {probs[arg]:.4f})")
