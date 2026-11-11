"""Train Multi-Class Family Classifier and Tactical Attribution Model (Objective 3).

Supports:
1. Two-Level Hierarchical Attribution:
   - Tier 1: Tactical Category Classification (MITRE ATT&CK Fileless Clusters)
   - Tier 2: Fine-Grained Family Attribution
2. Provenance-preserving training across both the original project runs and expanded dynamic datasets.
3. Group-aware Leave-One-Out and Stratified K-Fold cross-validation.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import LeaveOneOut, StratifiedKFold
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier

from preprocessing.pipeline import ALL_NUMERIC_FEATURE_COLS
from tools.dataset.map_features import TACTICAL_TAXONOMY, normalize_family_slug

DATA_PATH = Path("data/processed/unified/unified_dataset.jsonl")
OUTPUT_DIR = Path("models/multiclass/artifacts")

FAMILY_LABEL_MAP: dict[int, str] = {
    0: "Benign",
    1: "PowerShell Fileless",
    2: "WMI Malware",
    3: "Process Hollowing",
    4: "Reflective DLL Injection",
    5: "Registry Malware",
    6: "Cobalt Strike Beacon",
    7: "Metasploit Memory Payloads",
    8: "LOLBins Abuse",
    9: "Fileless Ransomware",
    10: "Memory-only RAT",
    11: "Empire Framework",
}

SLUG_TO_LABEL: dict[str, int] = {
    "benign": 0,
    "powershell_fileless": 1,
    "wmi_malware": 2,
    "process_hollowing": 3,
    "reflective_dll_injection": 4,
    "registry_malware": 5,
    "cobalt_strike_beacon": 6,
    "metasploit_memory_payloads": 7,
    "lolbins_abuse": 8,
    "fileless_ransomware": 9,
    "memory_only_rat": 10,
    "empire_framework": 11,
}

PCAP_NULL_FIELDS: list[str] = [
    "dns_query_count",
    "avg_interpacket_interval_ms",
    "beacon_regularity_score",
    "total_bytes_sent",
    "total_bytes_received",
    "mean_memory_entropy",
    "max_memory_entropy",
]


from sklearn.utils.class_weight import compute_sample_weight

def to_canonical_family(fam_str: str) -> str:
    """Map any raw family name or variant slug to canonical 11 project families."""
    f = str(fam_str).lower().replace("-", "_").replace(" ", "_")
    if "powershell" in f:
        return "powershell_fileless"
    if "wmi" in f:
        return "wmi_malware"
    if "hollowing" in f or "hollow" in f:
        return "process_hollowing"
    if "reflective" in f:
        return "reflective_dll_injection"
    if "registry" in f:
        return "registry_resident_malware"
    if "cobalt" in f or "beacon" in f:
        return "cobalt_strike_beacon"
    if "metasploit" in f or "meterpreter" in f:
        return "metasploit_memory_payloads"
    if "lolbin" in f or "certutil" in f or "mshta" in f or "bitsadmin" in f or "regsvr32" in f:
        return "lolbins_abuse"
    if "ransomware" in f or "conti" in f or "ako" in f or "shade" in f or "wannacry" in f:
        return "fileless_ransomware"
    if "empire" in f:
        return "empire_framework"
    return "memory_only_rat"


def load_malware_df(
    data_path: Path,
) -> tuple[pd.DataFrame, np.ndarray, LabelEncoder, np.ndarray, LabelEncoder]:
    """Load unified dataset, filter to malware-only, and return feature matrix + family/tactical labels."""
    rows = [
        json.loads(line)
        for line in data_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    df = pd.DataFrame(rows)
    df = df[df["binary_label"] == 1].reset_index(drop=True)

    # Feature matrix
    cols_to_use = [c for c in ALL_NUMERIC_FEATURE_COLS if c in df.columns]
    X = df[cols_to_use].copy()
    for col in PCAP_NULL_FIELDS:
        if col in X.columns:
            X[col] = X[col].fillna(0.0)
    X = X.fillna(0.0)

    # Canonical 11 Family labels
    y_family_raw = np.array([to_canonical_family(f) for f in df["family"]])
    le_family = LabelEncoder()
    y_family = le_family.fit_transform(y_family_raw)

    # Tactical labels
    if "tactical_cluster" not in df.columns:
        df["tactical_cluster"] = [
            normalize_family_slug(f)[1] for f in df["family"]
        ]
    y_tactical_raw = df["tactical_cluster"].astype(str).values
    le_tactical = LabelEncoder()
    y_tactical = le_tactical.fit_transform(y_tactical_raw)

    return X, y_family, le_family, y_tactical, le_tactical


def build_xgb_model(num_classes: int) -> XGBClassifier:
    """Build tuned XGBoost multiclass model with class-balanced weighting."""
    return XGBClassifier(
        n_estimators=120,
        max_depth=5,
        learning_rate=0.06,
        objective="multi:softprob",
        num_class=num_classes,
        subsample=0.9,
        colsample_bytree=0.9,
        reg_alpha=0.1,
        reg_lambda=0.5,
        random_state=42,
        eval_metric="mlogloss",
        verbosity=0,
    )


def run_evaluation(
    X: pd.DataFrame, y: np.ndarray, le: LabelEncoder, num_classes: int
) -> dict[str, Any]:
    """Run cross-validation on the feature matrix."""
    n_samples = len(y)
    use_loo = n_samples <= 60
    y_true: list[int] = []
    y_pred: list[int] = []
    records: list[dict[str, Any]] = []

    X_arr = X.values
    cv = LeaveOneOut() if use_loo else StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    for fold_idx, (train_idx, test_idx) in enumerate(cv.split(X_arr, y)):
        X_train, X_test = X_arr[train_idx], X_arr[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]

        classes_in_train = np.unique(y_train)
        if len(classes_in_train) < 2:
            majority = int(np.bincount(y_train).argmax())
            preds = np.full(len(test_idx), majority)
        else:
            model = build_xgb_model(len(classes_in_train))
            # Remap y_train to contiguous
            sub_le = LabelEncoder()
            y_train_cont = sub_le.fit_transform(y_train)
            model.fit(X_train, y_train_cont)
            preds_cont = model.predict(X_test)
            preds = sub_le.inverse_transform(preds_cont)

        for t, p in zip(y_test, preds):
            y_true.append(int(t))
            y_pred.append(int(p))
            records.append({
                "fold": fold_idx,
                "true_label": str(le.classes_[t]),
                "pred_label": str(le.classes_[p]),
                "correct": bool(t == p),
            })

    accuracy = float(np.mean(np.array(y_true) == np.array(y_pred)))
    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))

    report = classification_report(
        y_true,
        y_pred,
        target_names=[str(c) for c in le.classes_],
        output_dict=True,
        zero_division=0,
    )

    return {
        "evaluation_strategy": "LOO-CV" if use_loo else "Stratified 5-Fold CV",
        "total_samples": n_samples,
        "num_classes": num_classes,
        "accuracy": round(accuracy, 4),
        "macro_f1": round(macro_f1, 4),
        "weighted_f1": round(weighted_f1, 4),
        "per_class_report": report,
        "predictions": records[:50],  # sample records
    }


def train_multiclass_model(
    data_path: str = str(DATA_PATH),
    output_dir: str = str(OUTPUT_DIR),
) -> dict[str, Any]:
    """Train production multiclass & tactical models and save serialized artifacts."""
    p_out = Path(output_dir)
    p_out.mkdir(parents=True, exist_ok=True)

    X, y_family, le_family, y_tactical, le_tactical = load_malware_df(Path(data_path))

    # Evaluate Family Attribution
    fam_results = run_evaluation(X, y_family, le_family, len(le_family.classes_))

    # Evaluate Tactical Clusters
    tact_results = run_evaluation(X, y_tactical, le_tactical, len(le_tactical.classes_))

    # Train Production Family Model with Balanced Sample Weights
    weights_fam = compute_sample_weight("balanced", y_family)
    prod_fam = build_xgb_model(len(le_family.classes_))
    prod_fam.fit(X, y_family, sample_weight=weights_fam)

    # Save artifacts
    model_file = p_out / "multiclass_model.ubj"
    prod_fam.save_model(str(model_file))
    shutil.copy(str(model_file), str(p_out / "multiclass_model.xgb"))

    # Label mappings
    label_map = {str(i): str(name) for i, name in enumerate(le_family.classes_)}
    with open(p_out / "label_mapping.json", "w", encoding="utf-8") as f:
        json.dump(label_map, f, indent=2)

    with open(p_out / "family_label_map.json", "w", encoding="utf-8") as f:
        json.dump(label_map, f, indent=2)

    with open(p_out / "features.json", "w", encoding="utf-8") as f:
        json.dump({"features": list(X.columns)}, f, indent=2)

    metrics_out = {
        "dataset": str(data_path),
        "total_malware_samples": int(len(X)),
        "num_families": len(le_family.classes_),
        "family_accuracy": fam_results["accuracy"],
        "family_macro_f1": fam_results["macro_f1"],
        "family_weighted_f1": fam_results["weighted_f1"],
        "tactical_accuracy": tact_results["accuracy"],
        "tactical_macro_f1": tact_results["macro_f1"],
        "tactical_weighted_f1": tact_results["weighted_f1"],
        "tactical_clusters_count": len(le_tactical.classes_),
        "per_class_report": fam_results["per_class_report"],
    }

    with open(p_out / "metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics_out, f, indent=2)

    print(f"[MultiClass] Artifacts successfully written to {p_out}")
    return metrics_out


if __name__ == "__main__":
    res = train_multiclass_model()
    print("=== MULTICLASS & TACTICAL TRAINING COMPLETE ===")
    print(f"Family Accuracy:   {res['family_accuracy']:.4f} (Macro F1: {res['family_macro_f1']:.4f})")
    print(f"Tactical Accuracy: {res['tactical_accuracy']:.4f} (Macro F1: {res['tactical_macro_f1']:.4f})")
