"""Full training and evaluation pipeline for the 6,000 sample fileless malware dataset.

Trains:
1. Process Model (XGBoost) on Process features
2. Command Model (Enhanced GBDT with TF-IDF + Command Telemetry) on Command telemetry
3. Network Model (LightGBM) on Network features with native missing value support
4. Memory Model (CatBoost) on Memory forensics features
5. Multi-Class Family Classifier (XGBoost) on fused 4-modality feature vector
6. Hybrid Fusion Detection Engine (Objective 2) with stage-1 suspicion and memory triggering

Outputs detailed final evaluation metrics, confusion matrices, and per-class reports.
"""

import json
import os
import sys
from pathlib import Path

# Ensure UTF-8 output encoding for Windows PowerShell/cmd
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib

import xgboost as xgb
from xgboost import XGBClassifier
import lightgbm as lgb
from lightgbm import LGBMClassifier
import catboost as cb
from catboost import CatBoostClassifier

# Anchor paths to repository root
_REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = _REPO_ROOT / "Dataset" / "fileless_malware_6000_synthetic_samples.csv"
OUTPUT_DIR = _REPO_ROOT / "models" / "artifacts"
EVAL_DIR = _REPO_ROOT / "evaluation" / "binary"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
EVAL_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 80)
print("   FILELESS MALWARE DETECTION & ATTRIBUTION ON 6,000 SAMPLE DATASET")
print("=" * 80)

# 1. Load Dataset
with open(DATA_PATH, "r", encoding="utf-8") as f:
    df = pd.read_csv(f)
print(f"[*] Loaded Dataset: {len(df)} total samples from {DATA_PATH}")

# Print Dataset Summary
print("\n--- [1] DATASET DISTRIBUTION ---")
total_count = len(df)
benign_count = int((df["binary_label"] == 0).sum())
malware_count = int((df["binary_label"] == 1).sum())
print(f"Total Runs:       {total_count}")
print(f"  |-- Benign:      {benign_count} ({benign_count/total_count*100:.1f}%)")
print(f"  +-- Malware:     {malware_count} ({malware_count/total_count*100:.1f}%)")

print("\nMalware Family Distribution:")
family_counts = df[df["binary_label"] == 1]["family"].value_counts()
for fam, cnt in family_counts.items():
    print(f"  * {fam:<30}: {cnt} samples ({cnt/malware_count*100:.1f}%)")

# Feature columns definition
PROCESS_COLS = [
    "total_process_count", "hidden_process_count", "anomalous_ppid_count",
    "avg_threads_per_process", "max_threads_in_single_process", "total_handle_count",
    "suspicious_dll_count", "malfind_process_count", "elevated_privilege_count",
    "unlinked_dll_count"
]

COMMAND_NUM_COLS = [
    "command_length", "shannon_entropy", "is_base64_encoded",
    "has_download_cradle", "has_bypass_execution_policy", "has_hidden_window",
    "uses_lolbins", "registry_persistence_count"
]

NETWORK_COLS = [
    "active_connection_count", "listening_port_count", "outbound_connection_count",
    "dns_query_count", "unique_remote_ips", "avg_interpacket_interval_ms",
    "beacon_regularity_score", "total_bytes_sent", "total_bytes_received",
    "suspicious_port_usage"
]

MEMORY_COLS = [
    "rwx_page_count", "injected_code_regions", "unmapped_executable_pages",
    "vad_protection_anomaly_count", "ldrmodules_inconsistencies", "yara_shellcode_matches",
    "mean_memory_entropy", "max_memory_entropy"
]

# Ensure numeric columns are cleaned
for c in PROCESS_COLS + COMMAND_NUM_COLS + NETWORK_COLS + MEMORY_COLS:
    if c in df.columns:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)

df["raw_command_text"] = df["raw_command_text"].fillna("")

# 2. Stratified Train / Val / Test Split (70 / 15 / 15)
# Use combination of binary_label and family for stratification
df["strat_key"] = df["binary_label"].astype(str) + "_" + df["family"].astype(str)
df_train, df_temp = train_test_split(df, test_size=0.30, random_state=42, stratify=df["strat_key"])
df_val, df_test = train_test_split(df_temp, test_size=0.50, random_state=42, stratify=df_temp["strat_key"])

print(f"\n--- [2] TRAIN / VAL / TEST SPLIT (70% / 15% / 15%) ---")
print(f"Train samples:      {len(df_train)} (Benign: {(df_train['binary_label']==0).sum()}, Malware: {(df_train['binary_label']==1).sum()})")
print(f"Validation samples: {len(df_val)} (Benign: {(df_val['binary_label']==0).sum()}, Malware: {(df_val['binary_label']==1).sum()})")
print(f"Test samples:       {len(df_test)} (Benign: {(df_test['binary_label']==0).sum()}, Malware: {(df_test['binary_label']==1).sum()})")

y_train = df_train["binary_label"].values
y_val = df_val["binary_label"].values
y_test = df_test["binary_label"].values

def calc_metrics(y_true, y_pred, y_prob):
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    auc = roc_auc_score(y_true, y_prob) if len(np.unique(y_true)) > 1 else 1.0
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "roc_auc": auc,
        "fpr": fpr,
        "fnr": fnr,
        "confusion_matrix": cm.tolist(),
        "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn)
    }

# ==============================================================================
# 3. Model 1: Process Model (XGBoost)
# ==============================================================================
print("\n" + "=" * 60)
print("  [1/4] Training Process Model (XGBoost)")
print("=" * 60)

# Feature engineering: thread_to_process_ratio
def prep_proc(d):
    X = d[PROCESS_COLS].copy()
    X["thread_to_process_ratio"] = X["avg_threads_per_process"] / X["total_process_count"].replace(0, 1.0)
    return X

X_proc_train = prep_proc(df_train)
X_proc_val = prep_proc(df_val)
X_proc_test = prep_proc(df_test)
proc_features = list(X_proc_train.columns)

proc_scaler = StandardScaler()
X_proc_train_s = proc_scaler.fit_transform(X_proc_train)
X_proc_val_s = proc_scaler.transform(X_proc_val)
X_proc_test_s = proc_scaler.transform(X_proc_test)

proc_xgb = XGBClassifier(
    n_estimators=200,
    max_depth=4,
    learning_rate=0.05,
    subsample=0.85,
    colsample_bytree=0.85,
    random_state=42,
    eval_metric="logloss"
)
proc_xgb.fit(X_proc_train_s, y_train, eval_set=[(X_proc_val_s, y_val)], verbose=False)

# Save Process Model
proc_dir = OUTPUT_DIR / "process"
proc_dir.mkdir(parents=True, exist_ok=True)
proc_xgb.save_model(str(proc_dir / "model.json"))
joblib.dump(proc_scaler, proc_dir / "scaler.joblib")
with open(proc_dir / "features.json", "w", encoding="utf-8") as f:
    json.dump({"feature_names": proc_features}, f, indent=2)

proc_test_prob = proc_xgb.predict_proba(X_proc_test_s)[:, 1]
proc_test_pred = (proc_test_prob >= 0.5).astype(int)
proc_metrics = calc_metrics(y_test, proc_test_pred, proc_test_prob)

print(f"Process Model -> Accuracy: {proc_metrics['accuracy']:.4f} | F1: {proc_metrics['f1']:.4f} | AUC: {proc_metrics['roc_auc']:.4f} | FPR: {proc_metrics['fpr']:.4f} | FNR: {proc_metrics['fnr']:.4f}")

# ==============================================================================
# 4. Model 2: Command Model (Enhanced GBDT with TF-IDF + Command Telemetry)
# ==============================================================================
print("\n" + "=" * 60)
print("  [2/4] Training Command Model (TF-IDF + Telemetry GBDT)")
print("=" * 60)

cmd_tfidf = TfidfVectorizer(max_features=256, ngram_range=(1, 3), token_pattern=r"(?u)\b\w+\b|[\\/:\.\-_]")
X_cmd_text_train = cmd_tfidf.fit_transform(df_train["raw_command_text"]).toarray()
X_cmd_text_val = cmd_tfidf.transform(df_val["raw_command_text"]).toarray()
X_cmd_text_test = cmd_tfidf.transform(df_test["raw_command_text"]).toarray()

X_cmd_num_train = df_train[COMMAND_NUM_COLS].values
X_cmd_num_val = df_val[COMMAND_NUM_COLS].values
X_cmd_num_test = df_test[COMMAND_NUM_COLS].values

X_cmd_train = np.hstack([X_cmd_text_train, X_cmd_num_train])
X_cmd_val = np.hstack([X_cmd_text_val, X_cmd_num_val])
X_cmd_test = np.hstack([X_cmd_text_test, X_cmd_num_test])

cmd_lgb = LGBMClassifier(
    n_estimators=100,
    max_depth=3,
    num_leaves=8,
    learning_rate=0.05,
    subsample=0.85,
    colsample_bytree=0.85,
    random_state=42,
    verbosity=-1
)
cmd_lgb.fit(X_cmd_train, y_train, eval_set=[(X_cmd_val, y_val)])

# Save Command Model
cmd_dir = OUTPUT_DIR / "command"
cmd_dir.mkdir(parents=True, exist_ok=True)
joblib.dump(cmd_lgb, cmd_dir / "model.joblib")
joblib.dump(cmd_tfidf, cmd_dir / "tfidf.joblib")
with open(cmd_dir / "features.json", "w", encoding="utf-8") as f:
    json.dump({"feature_names": ["raw_command_text"] + COMMAND_NUM_COLS}, f, indent=2)

cmd_test_prob = cmd_lgb.predict_proba(X_cmd_test)[:, 1]
cmd_test_pred = (cmd_test_prob >= 0.5).astype(int)
cmd_metrics = calc_metrics(y_test, cmd_test_pred, cmd_test_prob)

print(f"Command Model -> Accuracy: {cmd_metrics['accuracy']:.4f} | F1: {cmd_metrics['f1']:.4f} | AUC: {cmd_metrics['roc_auc']:.4f} | FPR: {cmd_metrics['fpr']:.4f} | FNR: {cmd_metrics['fnr']:.4f}")

# ==============================================================================
# 5. Model 3: Network Model (LightGBM with native NaN preservation)
# ==============================================================================
print("\n" + "=" * 60)
print("  [3/4] Training Network Model (LightGBM)")
print("=" * 60)

X_net_train = df_train[NETWORK_COLS].copy()
X_net_val = df_val[NETWORK_COLS].copy()
X_net_test = df_test[NETWORK_COLS].copy()

net_lgb = LGBMClassifier(
    n_estimators=100,
    max_depth=3,
    num_leaves=8,
    learning_rate=0.05,
    subsample=0.85,
    colsample_bytree=0.85,
    random_state=42,
    verbosity=-1
)
net_lgb.fit(X_net_train, y_train, eval_set=[(X_net_val, y_val)])

# Save Network Model
net_dir = OUTPUT_DIR / "network"
net_dir.mkdir(parents=True, exist_ok=True)
joblib.dump(net_lgb, net_dir / "model.joblib")
with open(net_dir / "features.json", "w", encoding="utf-8") as f:
    json.dump({"feature_names": NETWORK_COLS}, f, indent=2)

net_test_prob = net_lgb.predict_proba(X_net_test)[:, 1]
net_test_pred = (net_test_prob >= 0.5).astype(int)
net_metrics = calc_metrics(y_test, net_test_pred, net_test_prob)

print(f"Network Model -> Accuracy: {net_metrics['accuracy']:.4f} | F1: {net_metrics['f1']:.4f} | AUC: {net_metrics['roc_auc']:.4f} | FPR: {net_metrics['fpr']:.4f} | FNR: {net_metrics['fnr']:.4f}")

# ==============================================================================
# 6. Model 4: Memory Model (CatBoost on Volatile Memory Telemetry)
# ==============================================================================
print("\n" + "=" * 60)
print("  [4/4] Training Memory Model (CatBoost)")
print("=" * 60)

def prep_mem(d):
    X = d[MEMORY_COLS].copy()
    X["memory_injection_score"] = (
        X["rwx_page_count"] * 2.0 +
        X["injected_code_regions"] * 3.0 +
        X["vad_protection_anomaly_count"] * 1.5
    )
    return X

X_mem_train = prep_mem(df_train)
X_mem_val = prep_mem(df_val)
X_mem_test = prep_mem(df_test)
mem_features = list(X_mem_train.columns)

mem_cb = CatBoostClassifier(
    iterations=250,
    depth=4,
    learning_rate=0.05,
    random_seed=42,
    nan_mode="Min",
    verbose=False
)
mem_cb.fit(X_mem_train, y_train, eval_set=(X_mem_val, y_val), verbose=False)

# Save Memory Model
mem_dir = OUTPUT_DIR / "memory"
mem_dir.mkdir(parents=True, exist_ok=True)
mem_cb.save_model(str(mem_dir / "model.cbm"))
with open(mem_dir / "features.json", "w", encoding="utf-8") as f:
    json.dump({"feature_names": mem_features}, f, indent=2)

mem_test_prob = mem_cb.predict_proba(X_mem_test)[:, 1]
mem_test_pred = (mem_test_prob >= 0.5).astype(int)
mem_metrics = calc_metrics(y_test, mem_test_pred, mem_test_prob)

print(f"Memory Model  -> Accuracy: {mem_metrics['accuracy']:.4f} | F1: {mem_metrics['f1']:.4f} | AUC: {mem_metrics['roc_auc']:.4f} | FPR: {mem_metrics['fpr']:.4f} | FNR: {mem_metrics['fnr']:.4f}")

# ==============================================================================
# 7. Model 5: Multi-Class Malware Family Attribution (Objective 3)
# ==============================================================================
print("\n" + "=" * 60)
print("  [5/5] Training Multi-Class Family Classifier (Objective 3)")
print("=" * 60)

# Train on all malware samples with 4-modality fused vector
df_malware = df[df["binary_label"] == 1].reset_index(drop=True)
ALL_FUSED_NUMERIC = PROCESS_COLS + COMMAND_NUM_COLS + NETWORK_COLS + MEMORY_COLS

X_fused = df_malware[ALL_FUSED_NUMERIC].values
le_family = LabelEncoder()
y_fam = le_family.fit_transform(df_malware["family"])

X_fam_train, X_fam_test, y_fam_train, y_fam_test = train_test_split(
    X_fused, y_fam, test_size=0.20, random_state=42, stratify=y_fam
)

multi_xgb = XGBClassifier(
    n_estimators=150,
    max_depth=4,
    learning_rate=0.08,
    objective="multi:softprob",
    num_class=len(le_family.classes_),
    subsample=0.85,
    colsample_bytree=0.85,
    random_state=42,
    eval_metric="mlogloss"
)
multi_xgb.fit(X_fam_train, y_fam_train)

# Save Multi-Class Model
multi_dir = _REPO_ROOT / "models" / "multiclass" / "artifacts"
multi_dir.mkdir(parents=True, exist_ok=True)
multi_xgb.save_model(str(multi_dir / "multiclass_model.ubj"))
multi_xgb.save_model(str(multi_dir / "multiclass_model.xgb"))

label_mapping = {int(i): str(name) for i, name in enumerate(le_family.classes_)}
with open(multi_dir / "label_mapping.json", "w", encoding="utf-8") as f:
    json.dump(label_mapping, f, indent=2)

with open(multi_dir / "features.json", "w", encoding="utf-8") as f:
    json.dump({"features": ALL_FUSED_NUMERIC}, f, indent=2)

y_fam_pred = multi_xgb.predict(X_fam_test)
fam_acc = accuracy_score(y_fam_test, y_fam_pred)
fam_macro_f1 = f1_score(y_fam_test, y_fam_pred, average="macro", zero_division=0)
fam_weighted_f1 = f1_score(y_fam_test, y_fam_pred, average="weighted", zero_division=0)
fam_report = classification_report(y_fam_test, y_fam_pred, target_names=le_family.classes_, output_dict=True, zero_division=0)

print(f"Multi-Class Family Attribution -> Accuracy: {fam_acc:.4f} | Macro F1: {fam_macro_f1:.4f} | Weighted F1: {fam_weighted_f1:.4f}")

# ==============================================================================
# 8. Real-Time Hybrid Detection Pipeline & Fusion Evaluation (Objective 2)
# ==============================================================================
print("\n" + "=" * 60)
print("  [6/6] Evaluating Real-Time Hybrid Fusion Pipeline (Objective 2)")
print("=" * 60)

# Evaluate on test partition (900 samples)
fused_confidences = []
fused_predictions = []
memory_triggered_list = []

# Suspicion thresholds (Configs/thresholds.yaml: stage 1 suspicion threshold ~0.35)
STAGE1_SUSPICION_THRESHOLD = 0.35
FUSION_DECISION_THRESHOLD = 0.60

for i in range(len(df_test)):
    p_proc = float(proc_test_prob[i])
    p_cmd = float(cmd_test_prob[i])
    p_net = float(net_test_prob[i])
    p_mem = float(mem_test_prob[i])
    
    # Stage 1: Lightweight Telemetry
    stage1_score = (p_proc + p_cmd + p_net) / 3.0
    is_suspicious = (p_proc >= STAGE1_SUSPICION_THRESHOLD or 
                     p_cmd >= STAGE1_SUSPICION_THRESHOLD or 
                     p_net >= STAGE1_SUSPICION_THRESHOLD or
                     stage1_score >= STAGE1_SUSPICION_THRESHOLD)
    
    if is_suspicious:
        # Pull Memory Dump & score
        final_conf = (p_proc + p_cmd + p_net + p_mem) / 4.0
        memory_triggered = True
    else:
        # Memory not triggered (quiescent memory baseline)
        final_conf = (p_proc + p_cmd + p_net + 0.05) / 4.0
        memory_triggered = False
        
    is_malware = 1 if final_conf >= FUSION_DECISION_THRESHOLD else 0
    fused_confidences.append(final_conf)
    fused_predictions.append(is_malware)
    memory_triggered_list.append(memory_triggered)

fused_confidences = np.array(fused_confidences)
fused_predictions = np.array(fused_predictions)
fusion_metrics = calc_metrics(y_test, fused_predictions, fused_confidences)

print(f"Hybrid Fusion Pipeline -> Accuracy: {fusion_metrics['accuracy']:.4f} | Precision: {fusion_metrics['precision']:.4f} | Recall: {fusion_metrics['recall']:.4f} | F1: {fusion_metrics['f1']:.4f} | ROC-AUC: {fusion_metrics['roc_auc']:.4f}")
print(f"False Positive Rate (FPR): {fusion_metrics['fpr']:.4f} | False Negative Rate (FNR): {fusion_metrics['fnr']:.4f}")
print(f"Memory Forensics Trigger Rate on Test Set: {np.mean(memory_triggered_list)*100:.1f}%")

# ==============================================================================
# 9. Consolidated Report Generation & Export
# ==============================================================================
comparison_table = [
    {
        "Modality": "Process",
        "Architecture": "XGBoost",
        "Accuracy": round(proc_metrics["accuracy"], 4),
        "Precision": round(proc_metrics["precision"], 4),
        "Recall": round(proc_metrics["recall"], 4),
        "F1-Score": round(proc_metrics["f1"], 4),
        "ROC-AUC": round(proc_metrics["roc_auc"], 4),
        "FPR": round(proc_metrics["fpr"], 4),
        "FNR": round(proc_metrics["fnr"], 4),
    },
    {
        "Modality": "Command",
        "Architecture": "TF-IDF + Telemetry GBDT",
        "Accuracy": round(cmd_metrics["accuracy"], 4),
        "Precision": round(cmd_metrics["precision"], 4),
        "Recall": round(cmd_metrics["recall"], 4),
        "F1-Score": round(cmd_metrics["f1"], 4),
        "ROC-AUC": round(cmd_metrics["roc_auc"], 4),
        "FPR": round(cmd_metrics["fpr"], 4),
        "FNR": round(cmd_metrics["fnr"], 4),
    },
    {
        "Modality": "Network",
        "Architecture": "LightGBM",
        "Accuracy": round(net_metrics["accuracy"], 4),
        "Precision": round(net_metrics["precision"], 4),
        "Recall": round(net_metrics["recall"], 4),
        "F1-Score": round(net_metrics["f1"], 4),
        "ROC-AUC": round(net_metrics["roc_auc"], 4),
        "FPR": round(net_metrics["fpr"], 4),
        "FNR": round(net_metrics["fnr"], 4),
    },
    {
        "Modality": "Memory",
        "Architecture": "CatBoost",
        "Accuracy": round(mem_metrics["accuracy"], 4),
        "Precision": round(mem_metrics["precision"], 4),
        "Recall": round(mem_metrics["recall"], 4),
        "F1-Score": round(mem_metrics["f1"], 4),
        "ROC-AUC": round(mem_metrics["roc_auc"], 4),
        "FPR": round(mem_metrics["fpr"], 4),
        "FNR": round(mem_metrics["fnr"], 4),
    },
    {
        "Modality": "Hybrid Fusion",
        "Architecture": "4-Way Ensemble (Threshold=0.60)",
        "Accuracy": round(fusion_metrics["accuracy"], 4),
        "Precision": round(fusion_metrics["precision"], 4),
        "Recall": round(fusion_metrics["recall"], 4),
        "F1-Score": round(fusion_metrics["f1"], 4),
        "ROC-AUC": round(fusion_metrics["roc_auc"], 4),
        "FPR": round(fusion_metrics["fpr"], 4),
        "FNR": round(fusion_metrics["fnr"], 4),
    }
]

consolidated_results = {
    "dataset": str(DATA_PATH),
    "total_samples": total_count,
    "split": {"train": len(df_train), "val": len(df_val), "test": len(df_test)},
    "binary_models": {
        "process": proc_metrics,
        "command": cmd_metrics,
        "network": net_metrics,
        "memory": mem_metrics,
        "hybrid_fusion": fusion_metrics
    },
    "multiclass_attribution": {
        "accuracy": fam_acc,
        "macro_f1": fam_macro_f1,
        "weighted_f1": fam_weighted_f1,
        "classification_report": fam_report
    },
    "comparison_table": comparison_table
}

with open(EVAL_DIR / "final_6000_evaluation_report.json", "w", encoding="utf-8") as f:
    json.dump(consolidated_results, f, indent=2)

print("\n" + "=" * 80)
print("                   FINAL BENCHMARK EVALUATION METRICS TABLE")
print("=" * 80)
print(f"{'Modality':<15} {'Architecture':<32} {'Accuracy':<10} {'F1-Score':<10} {'ROC-AUC':<10} {'FPR':<8} {'FNR':<8}")
print("-" * 95)
for row in comparison_table:
    print(f"{row['Modality']:<15} {row['Architecture']:<32} {row['Accuracy']:<10.4f} {row['F1-Score']:<10.4f} {row['ROC-AUC']:<10.4f} {row['FPR']:<8.4f} {row['FNR']:<8.4f}")
print("=" * 95)

print("\n" + "=" * 80)
print("              OBJECTIVE 3: MULTI-CLASS MALWARE FAMILY ATTRIBUTION")
print("=" * 80)
print(f"Overall Family Classification Accuracy: {fam_acc:.4f}")
print(f"Macro-Averaged F1-Score:                {fam_macro_f1:.4f}")
print(f"Weighted-Averaged F1-Score:             {fam_weighted_f1:.4f}")
print("\nPer-Family Breakdown:")
print(f"{'Family':<32} {'Precision':<12} {'Recall':<12} {'F1-Score':<12} {'Support':<8}")
print("-" * 76)
for fam in le_family.classes_:
    m = fam_report[fam]
    print(f"{fam:<32} {m['precision']:<12.4f} {m['recall']:<12.4f} {m['f1-score']:<12.4f} {int(m['support']):<8}")
print("=" * 76)
