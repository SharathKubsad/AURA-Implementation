"""Phase 5A: Controlled Binary Modality Model Training Orchestrator.

Trains and evaluates four independent binary modality detectors:
1. PROCESS  -> XGBoost (data/features/process/)
2. MEMORY   -> CatBoost (data/features/memory/)
3. NETWORK  -> LightGBM (data/features/network/)
4. COMMAND  -> DistilBERT (data/features/command/text_sequences.jsonl)

Target:
0 = Benign
1 = Malware

Strict Rules:
- Fixed run-disjoint split: Train (28), Val (9), Test (8).
- Preprocessing fitted on TRAIN only.
- Test set strictly held out until final evaluation.
- No public dataset integration.
- No fusion or API code.
"""

from __future__ import annotations

import csv
import json
import os
import random
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import catboost as cb
import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
import torch
from torch.utils.data import DataLoader, Dataset
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DistilBertForSequenceClassification,
    DistilBertTokenizerFast,
)
import xgboost as xgb

# Set global reproducibility seed
RANDOM_SEED = 42
random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)
torch.manual_seed(RANDOM_SEED)

REPO_ROOT = Path(__file__).resolve().parent.parent
FEATURES_DIR = REPO_ROOT / "data" / "features"
MODELS_DIR = REPO_ROOT / "models" / "rich_binary"
EVAL_DIR = REPO_ROOT / "evaluation"
DOCS_DIR = REPO_ROOT / "docs"


def get_git_commit() -> str:
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=True,
        )
        return res.stdout.strip()
    except Exception:
        return "UNKNOWN_COMMIT"


def load_splits() -> Tuple[List[str], List[str], List[str]]:
    splits_dir = FEATURES_DIR / "splits"
    with open(splits_dir / "train_runs.json", "r", encoding="utf-8") as f:
        train_runs = json.load(f)
    with open(splits_dir / "val_runs.json", "r", encoding="utf-8") as f:
        val_runs = json.load(f)
    with open(splits_dir / "test_runs.json", "r", encoding="utf-8") as f:
        test_runs = json.load(f)
    return train_runs, val_runs, test_runs


def compute_metrics(y_true: np.ndarray, y_proba: np.ndarray, threshold: float = 0.5) -> Dict[str, Any]:
    y_pred = (y_proba >= threshold).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))

    try:
        if len(np.unique(y_true)) > 1:
            auc = float(roc_auc_score(y_true, y_proba))
        else:
            auc = 1.0 if y_true[0] == y_pred[0] else 0.0
    except Exception:
        auc = 0.0

    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    return {
        "threshold": threshold,
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "roc_auc": round(auc, 4),
        "fpr": round(fpr, 4),
        "fnr": round(fnr, 4),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
        "total_samples": int(len(y_true)),
        "benign_count": int(tn + fp),
        "malware_count": int(fn + tp),
    }


# ==============================================================================
# 1. PROCESS MODEL (XGBoost)
# ==============================================================================

def train_process_model(train_runs: List[str], val_runs: List[str], test_runs: List[str]) -> Dict[str, Any]:
    print("\n--- Training Process Model (XGBoost) ---")
    out_dir = MODELS_DIR / "process"
    out_dir.mkdir(parents=True, exist_ok=True)
    eval_sub_dir = EVAL_DIR / "process"
    eval_sub_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_json(FEATURES_DIR / "process" / "process_features.jsonl", lines=True)

    # Split
    train_df = df[df["run_id"].isin(train_runs)].copy()
    val_df = df[df["run_id"].isin(val_runs)].copy()
    test_df = df[df["run_id"].isin(test_runs)].copy()

    metadata_cols = {"sample_id", "run_id", "label"}
    feature_cols = [c for c in df.columns if c not in metadata_cols]

    # Preprocessing on TRAIN only: Drop zero-variance features on train
    train_stds = train_df[feature_cols].std()
    active_features = [col for col in feature_cols if train_stds[col] > 1e-6]
    dropped_features = [col for col in feature_cols if col not in active_features]
    print(f"Process Features: {len(active_features)} active, {len(dropped_features)} dropped (constant on train: {dropped_features})")

    X_train = train_df[active_features].values
    y_train = train_df["label"].values.astype(int)
    X_val = val_df[active_features].values
    y_val = val_df["label"].values.astype(int)
    X_test = test_df[active_features].values
    y_test = test_df["label"].values.astype(int)

    # Class weighting: neg / pos
    scale_pos = (len(y_train) - sum(y_train)) / sum(y_train) if sum(y_train) > 0 else 1.0

    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=3,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos,
        random_state=RANDOM_SEED,
        eval_metric="logloss",
        early_stopping_rounds=15,
    )

    model.fit(
        X_train,
        y_train,
        eval_set=[(X_train, y_train), (X_val, y_val)],
        verbose=False,
    )

    # Save model artifact
    model_path = out_dir / "xgboost_process.json"
    model.save_model(str(model_path))

    # Evaluate predictions
    proba_train = model.predict_proba(X_train)[:, 1]
    proba_val = model.predict_proba(X_val)[:, 1]
    proba_test = model.predict_proba(X_test)[:, 1]

    metrics_050 = {
        "train": compute_metrics(y_train, proba_train, 0.50),
        "val": compute_metrics(y_val, proba_val, 0.50),
        "test": compute_metrics(y_test, proba_test, 0.50),
    }
    metrics_060 = {
        "train": compute_metrics(y_train, proba_train, 0.60),
        "val": compute_metrics(y_val, proba_val, 0.60),
        "test": compute_metrics(y_test, proba_test, 0.60),
    }

    # Save predictions.csv across all 45 runs
    all_df = pd.concat([train_df, val_df, test_df]).reset_index(drop=True)
    all_X = all_df[active_features].values
    all_proba = model.predict_proba(all_X)[:, 1]
    all_df["predicted_probability"] = np.round(all_proba, 4)
    all_df["predicted_label_050"] = (all_proba >= 0.50).astype(int)
    all_df["predicted_label_060"] = (all_proba >= 0.60).astype(int)
    all_df["correct_060"] = all_df["predicted_label_060"] == all_df["label"]

    split_assign = {}
    for r in train_runs: split_assign[r] = "TRAIN"
    for r in val_runs: split_assign[r] = "VAL"
    for r in test_runs: split_assign[r] = "TEST"
    all_df["split"] = all_df["run_id"].map(split_assign)

    pred_csv_cols = ["sample_id", "run_id", "split", "label", "predicted_probability", "predicted_label_050", "predicted_label_060", "correct_060"]
    all_df[pred_csv_cols].to_csv(eval_sub_dir / "predictions.csv", index=False)

    # Save model metadata
    metadata = {
        "modality": "process",
        "algorithm": "XGBoost",
        "model_file": "xgboost_process.json",
        "random_seed": RANDOM_SEED,
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "git_commit": get_git_commit(),
        "active_features": active_features,
        "dropped_features": dropped_features,
        "splits_count": {"train": len(train_runs), "val": len(val_runs), "test": len(test_runs)},
        "metrics_threshold_050": metrics_050,
        "metrics_threshold_060": metrics_060,
    }
    with open(out_dir / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return metadata


# ==============================================================================
# 2. MEMORY MODEL (CatBoost)
# ==============================================================================

def train_memory_model(train_runs: List[str], val_runs: List[str], test_runs: List[str]) -> Dict[str, Any]:
    print("\n--- Training Memory Model (CatBoost) ---")
    out_dir = MODELS_DIR / "memory"
    out_dir.mkdir(parents=True, exist_ok=True)
    eval_sub_dir = EVAL_DIR / "memory"
    eval_sub_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_json(FEATURES_DIR / "memory" / "memory_features.jsonl", lines=True)

    train_df = df[df["run_id"].isin(train_runs)].copy()
    val_df = df[df["run_id"].isin(val_runs)].copy()
    test_df = df[df["run_id"].isin(test_runs)].copy()

    metadata_cols = {"sample_id", "run_id", "label"}
    feature_cols = [c for c in df.columns if c not in metadata_cols]

    # Preprocessing on TRAIN only: Drop zero-variance features on train
    train_stds = train_df[feature_cols].std()
    active_features = [col for col in feature_cols if train_stds[col] > 1e-6]
    dropped_features = [col for col in feature_cols if col not in active_features]
    print(f"Memory Features: {len(active_features)} active, {len(dropped_features)} dropped (constant on train: {dropped_features})")

    X_train = train_df[active_features].values
    y_train = train_df["label"].values.astype(int)
    X_val = val_df[active_features].values
    y_val = val_df["label"].values.astype(int)
    X_test = test_df[active_features].values
    y_test = test_df["label"].values.astype(int)

    model = cb.CatBoostClassifier(
        iterations=100,
        depth=4,
        learning_rate=0.05,
        loss_function="Logloss",
        eval_metric="Logloss",
        random_seed=RANDOM_SEED,
        early_stopping_rounds=15,
        verbose=False,
    )

    model.fit(
        X_train,
        y_train,
        eval_set=(X_val, y_val),
        verbose=False,
    )

    model_path = out_dir / "catboost_memory.cbm"
    model.save_model(str(model_path))

    proba_train = model.predict_proba(X_train)[:, 1]
    proba_val = model.predict_proba(X_val)[:, 1]
    proba_test = model.predict_proba(X_test)[:, 1]

    metrics_050 = {
        "train": compute_metrics(y_train, proba_train, 0.50),
        "val": compute_metrics(y_val, proba_val, 0.50),
        "test": compute_metrics(y_test, proba_test, 0.50),
    }
    metrics_060 = {
        "train": compute_metrics(y_train, proba_train, 0.60),
        "val": compute_metrics(y_val, proba_val, 0.60),
        "test": compute_metrics(y_test, proba_test, 0.60),
    }

    all_df = pd.concat([train_df, val_df, test_df]).reset_index(drop=True)
    all_X = all_df[active_features].values
    all_proba = model.predict_proba(all_X)[:, 1]
    all_df["predicted_probability"] = np.round(all_proba, 4)
    all_df["predicted_label_050"] = (all_proba >= 0.50).astype(int)
    all_df["predicted_label_060"] = (all_proba >= 0.60).astype(int)
    all_df["correct_060"] = all_df["predicted_label_060"] == all_df["label"]

    split_assign = {}
    for r in train_runs: split_assign[r] = "TRAIN"
    for r in val_runs: split_assign[r] = "VAL"
    for r in test_runs: split_assign[r] = "TEST"
    all_df["split"] = all_df["run_id"].map(split_assign)

    pred_csv_cols = ["sample_id", "run_id", "split", "label", "predicted_probability", "predicted_label_050", "predicted_label_060", "correct_060"]
    all_df[pred_csv_cols].to_csv(eval_sub_dir / "predictions.csv", index=False)

    metadata = {
        "modality": "memory",
        "algorithm": "CatBoost",
        "model_file": "catboost_memory.cbm",
        "random_seed": RANDOM_SEED,
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "git_commit": get_git_commit(),
        "active_features": active_features,
        "dropped_features": dropped_features,
        "splits_count": {"train": len(train_runs), "val": len(val_runs), "test": len(test_runs)},
        "metrics_threshold_050": metrics_050,
        "metrics_threshold_060": metrics_060,
    }
    with open(out_dir / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return metadata


# ==============================================================================
# 3. NETWORK MODEL (LightGBM)
# ==============================================================================

def train_network_model(train_runs: List[str], val_runs: List[str], test_runs: List[str]) -> Dict[str, Any]:
    print("\n--- Training Network Model (LightGBM) ---")
    out_dir = MODELS_DIR / "network"
    out_dir.mkdir(parents=True, exist_ok=True)
    eval_sub_dir = EVAL_DIR / "network"
    eval_sub_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_json(FEATURES_DIR / "network" / "network_features.jsonl", lines=True)

    train_df = df[df["run_id"].isin(train_runs)].copy()
    val_df = df[df["run_id"].isin(val_runs)].copy()
    test_df = df[df["run_id"].isin(test_runs)].copy()

    # Exclude PCAP null metrics (100% missing) and metadata
    unsupported_pcap_cols = {
        "net_packet_count",
        "net_byte_count",
        "net_flow_duration_sec",
        "net_beacon_periodicity_sec",
    }
    metadata_cols = {"sample_id", "run_id", "label"}.union(unsupported_pcap_cols)
    feature_cols = [c for c in df.columns if c not in metadata_cols]

    # Preprocessing on TRAIN only: Drop zero-variance features on train
    train_stds = train_df[feature_cols].std()
    active_features = [col for col in feature_cols if train_stds[col] > 1e-6]
    dropped_features = [col for col in feature_cols if col not in active_features] + list(unsupported_pcap_cols)
    print(f"Network Features: {len(active_features)} active, {len(dropped_features)} dropped ({dropped_features})")

    X_train = train_df[active_features].values
    y_train = train_df["label"].values.astype(int)
    X_val = val_df[active_features].values
    y_val = val_df["label"].values.astype(int)
    X_test = test_df[active_features].values
    y_test = test_df["label"].values.astype(int)

    scale_pos = (len(y_train) - sum(y_train)) / sum(y_train) if sum(y_train) > 0 else 1.0

    model = lgb.LGBMClassifier(
        n_estimators=100,
        max_depth=3,
        num_leaves=7,
        learning_rate=0.05,
        scale_pos_weight=scale_pos,
        random_state=RANDOM_SEED,
        verbosity=-1,
    )

    model.fit(
        X_train,
        y_train,
        eval_set=[(X_val, y_val)],
        callbacks=[lgb.early_stopping(stopping_rounds=15, verbose=False)],
    )

    model_path = out_dir / "lightgbm_network.txt"
    model.booster_.save_model(str(model_path))

    proba_train = model.predict_proba(X_train)[:, 1]
    proba_val = model.predict_proba(X_val)[:, 1]
    proba_test = model.predict_proba(X_test)[:, 1]

    metrics_050 = {
        "train": compute_metrics(y_train, proba_train, 0.50),
        "val": compute_metrics(y_val, proba_val, 0.50),
        "test": compute_metrics(y_test, proba_test, 0.50),
    }
    metrics_060 = {
        "train": compute_metrics(y_train, proba_train, 0.60),
        "val": compute_metrics(y_val, proba_val, 0.60),
        "test": compute_metrics(y_test, proba_test, 0.60),
    }

    all_df = pd.concat([train_df, val_df, test_df]).reset_index(drop=True)
    all_X = all_df[active_features].values
    all_proba = model.predict_proba(all_X)[:, 1]
    all_df["predicted_probability"] = np.round(all_proba, 4)
    all_df["predicted_label_050"] = (all_proba >= 0.50).astype(int)
    all_df["predicted_label_060"] = (all_proba >= 0.60).astype(int)
    all_df["correct_060"] = all_df["predicted_label_060"] == all_df["label"]

    split_assign = {}
    for r in train_runs: split_assign[r] = "TRAIN"
    for r in val_runs: split_assign[r] = "VAL"
    for r in test_runs: split_assign[r] = "TEST"
    all_df["split"] = all_df["run_id"].map(split_assign)

    pred_csv_cols = ["sample_id", "run_id", "split", "label", "predicted_probability", "predicted_label_050", "predicted_label_060", "correct_060"]
    all_df[pred_csv_cols].to_csv(eval_sub_dir / "predictions.csv", index=False)

    metadata = {
        "modality": "network",
        "algorithm": "LightGBM",
        "model_file": "lightgbm_network.txt",
        "random_seed": RANDOM_SEED,
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "git_commit": get_git_commit(),
        "active_features": active_features,
        "dropped_features": dropped_features,
        "splits_count": {"train": len(train_runs), "val": len(val_runs), "test": len(test_runs)},
        "metrics_threshold_050": metrics_050,
        "metrics_threshold_060": metrics_060,
    }
    with open(out_dir / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return metadata


# ==============================================================================
# 4. COMMAND MODEL (DistilBERT Sequence Classifier)
# ==============================================================================

class CommandSequenceDataset(Dataset):
    def __init__(self, texts: List[str], labels: List[int], tokenizer, max_len: int = 128):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_len = max_len

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        text = str(self.texts[idx])
        encoding = self.tokenizer(
            text,
            truncation=True,
            padding="max_length",
            max_length=self.max_len,
            return_tensors="pt",
        )
        item = {key: val.squeeze(0) for key, val in encoding.items()}
        item["labels"] = torch.tensor(self.labels[idx], dtype=torch.long)
        return item


def train_command_model(train_runs: List[str], val_runs: List[str], test_runs: List[str]) -> Dict[str, Any]:
    print("\n--- Training Command Model (DistilBERT) ---")
    out_dir = MODELS_DIR / "command"
    out_dir.mkdir(parents=True, exist_ok=True)
    eval_sub_dir = EVAL_DIR / "command"
    eval_sub_dir.mkdir(parents=True, exist_ok=True)

    seq_path = FEATURES_DIR / "command" / "text_sequences.jsonl"
    if not seq_path.exists() and (FEATURES_DIR / "command" / "text_sequences.jsonl.gz").exists():
        seq_path = FEATURES_DIR / "command" / "text_sequences.jsonl.gz"

    # Load and partition text sequences STRICTLY by run_id
    train_texts, train_labels = [], []
    val_texts, val_labels = [], []
    test_texts, test_labels = [], []

    run_text_map: Dict[str, List[str]] = {}
    run_label_map: Dict[str, int] = {}

    print(f"Loading command text sequences from {seq_path.name} and grouping by run...")
    import gzip
    open_fn = gzip.open if str(seq_path).endswith(".gz") else open
    with open_fn(seq_path, "rt", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rec = json.loads(line)
                rid = rec["run_id"]
                txt = rec["text"]
                lbl = int(rec["label"])
                run_text_map.setdefault(rid, []).append(txt)
                run_label_map[rid] = lbl

    # Sample unique/representative sequences per run for efficient CPU training
    # Keeps all distinct commands per run (capped at 60 diverse samples per run)
    for rid, txt_list in run_text_map.items():
        # Deduplicate to focus on distinct command semantics
        unique_txts = list(set(txt_list))
        random.seed(RANDOM_SEED)
        sampled = random.sample(unique_txts, min(len(unique_txts), 60))
        lbl = run_label_map[rid]

        if rid in train_runs:
            train_texts.extend(sampled)
            train_labels.extend([lbl] * len(sampled))
        elif rid in val_runs:
            val_texts.extend(sampled)
            val_labels.extend([lbl] * len(sampled))
        elif rid in test_runs:
            test_texts.extend(sampled)
            test_labels.extend([lbl] * len(sampled))

    print(f"Sampled Command Sequences: Train={len(train_texts)}, Val={len(val_texts)}, Test={len(test_texts)}")

    model_name = "distilbert-base-uncased"
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)

    train_dataset = CommandSequenceDataset(train_texts, train_labels, tokenizer)
    val_dataset = CommandSequenceDataset(val_texts, val_labels, tokenizer)

    train_loader = DataLoader(train_dataset, batch_size=16, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=32, shuffle=False)

    optimizer = torch.optim.AdamW(model.parameters(), lr=3e-5)
    model.train()

    epochs = 2
    print(f"Fine-tuning DistilBERT for {epochs} epochs on CPU...")
    for epoch in range(epochs):
        total_loss = 0.0
        for step, batch in enumerate(train_loader):
            optimizer.zero_grad()
            outputs = model(**batch)
            loss = outputs.loss
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
            if (step + 1) % 25 == 0 or (step + 1) == len(train_loader):
                print(f"Epoch {epoch+1}/{epochs} | Step {step+1}/{len(train_loader)} | Loss: {loss.item():.4f}")

    # Save fine-tuned model and tokenizer
    model.save_pretrained(str(out_dir))
    tokenizer.save_pretrained(str(out_dir))
    print(f"Saved DistilBERT model to {out_dir}")

    # Evaluate at RUN LEVEL using top-k / max probability aggregation
    model.eval()

    def score_run_sequences(run_id: str) -> float:
        texts = list(set(run_text_map.get(run_id, [])))
        if not texts:
            return 0.0
        # Evaluate up to 100 distinct sequences
        eval_texts = texts[:100]
        enc = tokenizer(
            eval_texts,
            truncation=True,
            padding=True,
            max_length=128,
            return_tensors="pt",
        )
        with torch.no_grad():
            logits = model(**enc).logits
            probas = torch.softmax(logits, dim=-1)[:, 1].numpy()
        # Forensic Run-level Aggregation: Max probability across commands
        # If any command is classified as malicious fileless payload, session is flagged
        return float(np.max(probas))

    # Evaluate per-run scores
    train_run_scores = np.array([score_run_sequences(r) for r in train_runs])
    val_run_scores = np.array([score_run_sequences(r) for r in val_runs])
    test_run_scores = np.array([score_run_sequences(r) for r in test_runs])

    train_y = np.array([run_label_map[r] for r in train_runs])
    val_y = np.array([run_label_map[r] for r in val_runs])
    test_y = np.array([run_label_map[r] for r in test_runs])

    metrics_050 = {
        "train": compute_metrics(train_y, train_run_scores, 0.50),
        "val": compute_metrics(val_y, val_run_scores, 0.50),
        "test": compute_metrics(test_y, test_run_scores, 0.50),
    }
    metrics_060 = {
        "train": compute_metrics(train_y, train_run_scores, 0.60),
        "val": compute_metrics(val_y, val_run_scores, 0.60),
        "test": compute_metrics(test_y, test_run_scores, 0.60),
    }

    # Save predictions.csv
    all_runs_ordered = train_runs + val_runs + test_runs
    all_scores = np.concatenate([train_run_scores, val_run_scores, test_run_scores])
    all_y = np.concatenate([train_y, val_y, test_y])
    all_splits = ["TRAIN"] * len(train_runs) + ["VAL"] * len(val_runs) + ["TEST"] * len(test_runs)

    pred_records = []
    for r, split, y_true, p in zip(all_runs_ordered, all_splits, all_y, all_scores):
        pred_records.append({
            "sample_id": f"EXEC_{r}",
            "run_id": r,
            "split": split,
            "label": int(y_true),
            "predicted_probability": round(float(p), 4),
            "predicted_label_050": int(p >= 0.50),
            "predicted_label_060": int(p >= 0.60),
            "correct_060": bool((p >= 0.60) == y_true),
        })

    pd.DataFrame(pred_records).to_csv(eval_sub_dir / "predictions.csv", index=False)

    metadata = {
        "modality": "command",
        "algorithm": "DistilBERT (Sequence Classifier with Max Aggregation)",
        "model_dir": "models/rich_binary/command",
        "random_seed": RANDOM_SEED,
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "git_commit": get_git_commit(),
        "aggregation_method": "max_probability",
        "sampled_sequences_count": {"train": len(train_texts), "val": len(val_texts), "test": len(test_texts)},
        "splits_count": {"train": len(train_runs), "val": len(val_runs), "test": len(test_runs)},
        "metrics_threshold_050": metrics_050,
        "metrics_threshold_060": metrics_060,
    }
    with open(out_dir / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return metadata


# ==============================================================================
# 5. ERROR ANALYSIS & PHASE 5A SUMMARY
# ==============================================================================

def generate_error_analysis(modality: str, metadata: Dict[str, Any]) -> None:
    eval_sub_dir = EVAL_DIR / modality
    pred_path = eval_sub_dir / "predictions.csv"
    if not pred_path.exists():
        return

    df = pd.read_csv(pred_path)
    errors = df[~df["correct_060"]]

    content = f"""# Error Analysis: {modality.upper()} Detector (Phase 5A)
**Project:** Real-Time AI-Based Fileless Malware Detection and Classification System  
**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d')}  
**Operational Threshold:** 0.60  
**Total Runs Evaluated:** 45 (Train: 28, Val: 9, Test: 8)  

---

## 1. Overall Error Rate at 0.60 Threshold

- **Total Misclassifications:** {len(errors)} / 45 runs ({round(len(errors)/45*100, 2)}%)
- **Validation Errors:** {len(df[(df['split']=='VAL') & (~df['correct_060'])])} / 9
- **Test Errors:** {len(df[(df['split']=='TEST') & (~df['correct_060'])])} / 8

---

## 2. Detailed Misclassifications

| Run ID | Split | True Label | Predicted Prob | Error Type | Dominant Context / Forensic Findings |
|---|:---:|:---:|:---:|:---:|---|
"""
    for _, row in errors.iterrows():
        err_type = "False Positive (FP)" if row["label"] == 0 else "False Negative (FN)"
        content += f"| `{row['run_id']}` | {row['split']} | {row['label']} | {row['predicted_probability']} | **{err_type}** | Evaluated on {modality} feature domain. |\n"

    if len(errors) == 0:
        content += "| *None* | *N/A* | *N/A* | *N/A* | *Zero Errors* | Complete empirical discernment across all partitions. |\n"

    content += """
---

## 3. Forensic Interpretation & Telemetry Limitations

- **Small-Data Uncertainty:** The dataset comprises 45 execution runs. Performance on small held-out subsets (N=8 in Test) provides proof-of-concept verification rather than universal generalization.
- **Modality Specificity:** Individual modalities are expected to exhibit blind spots (e.g. process detector on stealthy memory-only RATs, or network detector on dormant runs). The project architecture fuses these 4 modalities in Phase 5B to achieve comprehensive detection.
"""
    with open(eval_sub_dir / "error_analysis.md", "w", encoding="utf-8") as f:
        f.write(content)


def generate_phase5a_summary(all_meta: Dict[str, Dict[str, Any]]) -> None:
    rows = []
    for mod, meta in all_meta.items():
        val_050 = meta["metrics_threshold_050"]["val"]
        val_060 = meta["metrics_threshold_060"]["val"]
        test_050 = meta["metrics_threshold_050"]["test"]
        test_060 = meta["metrics_threshold_060"]["test"]

        rows.append({
            "modality": mod.upper(),
            "algorithm": meta["algorithm"],
            "val_acc_050": val_050["accuracy"],
            "val_f1_050": val_050["f1"],
            "val_acc_060": val_060["accuracy"],
            "val_f1_060": val_060["f1"],
            "test_acc_050": test_050["accuracy"],
            "test_f1_050": test_050["f1"],
            "test_acc_060": test_060["accuracy"],
            "test_f1_060": test_060["f1"],
            "test_precision_060": test_060["precision"],
            "test_recall_060": test_060["recall"],
            "test_roc_auc": test_060["roc_auc"],
        })

    summary_df = pd.DataFrame(rows)
    summary_path = EVAL_DIR / "phase5a_summary.csv"
    summary_df.to_csv(summary_path, index=False)
    print(f"\nGenerated Phase 5A Summary at {summary_path}")


# ==============================================================================
# 6. COMMON INTERFACE IMPLEMENTATION
# ==============================================================================

def generate_model_interface() -> None:
    interface_code = '''"""Common Model Interface for Rich Binary Modality Detectors.

Provides a unified prediction interface across all four trained modalities:
- Process: XGBoost
- Memory: CatBoost
- Network: LightGBM
- Command: DistilBERT with Max Aggregation
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import catboost as cb
import lightgbm as lgb
import numpy as np
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer
import xgboost as xgb

MODELS_DIR = Path(__file__).resolve().parent


class RichProcessDetector:
    def __init__(self, model_dir: Optional[Path] = None):
        self.dir = model_dir or (MODELS_DIR / "process")
        with open(self.dir / "metadata.json", "r", encoding="utf-8") as f:
            self.metadata = json.load(f)
        self.features = self.metadata["active_features"]
        self.model = xgb.XGBClassifier()
        self.model.load_model(str(self.dir / "xgboost_process.json"))

    def predict_proba(self, X: Union[np.ndarray, List[float]]) -> np.ndarray:
        arr = np.asarray(X)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        return self.model.predict_proba(arr)[:, 1]

    def predict(self, X: Union[np.ndarray, List[float]], threshold: float = 0.60) -> np.ndarray:
        return (self.predict_proba(X) >= threshold).astype(int)


class RichMemoryDetector:
    def __init__(self, model_dir: Optional[Path] = None):
        self.dir = model_dir or (MODELS_DIR / "memory")
        with open(self.dir / "metadata.json", "r", encoding="utf-8") as f:
            self.metadata = json.load(f)
        self.features = self.metadata["active_features"]
        self.model = cb.CatBoostClassifier()
        self.model.load_model(str(self.dir / "catboost_memory.cbm"))

    def predict_proba(self, X: Union[np.ndarray, List[float]]) -> np.ndarray:
        arr = np.asarray(X)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        return self.model.predict_proba(arr)[:, 1]

    def predict(self, X: Union[np.ndarray, List[float]], threshold: float = 0.60) -> np.ndarray:
        return (self.predict_proba(X) >= threshold).astype(int)


class RichNetworkDetector:
    def __init__(self, model_dir: Optional[Path] = None):
        self.dir = model_dir or (MODELS_DIR / "network")
        with open(self.dir / "metadata.json", "r", encoding="utf-8") as f:
            self.metadata = json.load(f)
        self.features = self.metadata["active_features"]
        self.booster = lgb.Booster(model_file=str(self.dir / "lightgbm_network.txt"))

    def predict_proba(self, X: Union[np.ndarray, List[float]]) -> np.ndarray:
        arr = np.asarray(X)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        return self.booster.predict(arr)

    def predict(self, X: Union[np.ndarray, List[float]], threshold: float = 0.60) -> np.ndarray:
        return (self.predict_proba(X) >= threshold).astype(int)


class RichCommandDetector:
    def __init__(self, model_dir: Optional[Path] = None):
        self.dir = model_dir or (MODELS_DIR / "command")
        with open(self.dir / "metadata.json", "r", encoding="utf-8") as f:
            self.metadata = json.load(f)
        self.tokenizer = AutoTokenizer.from_pretrained(str(self.dir))
        self.model = AutoModelForSequenceClassification.from_pretrained(str(self.dir))
        self.model.eval()

    def predict_proba(self, text_sequence: str) -> float:
        enc = self.tokenizer(
            text_sequence,
            truncation=True,
            padding=True,
            max_length=128,
            return_tensors="pt",
        )
        with torch.no_grad():
            logits = self.model(**enc).logits
            proba = torch.softmax(logits, dim=-1)[0, 1].item()
        return float(proba)

    def predict_run_texts_proba(self, text_sequences: List[str]) -> float:
        if not text_sequences:
            return 0.0
        # Evaluate batch of unique texts
        unique_texts = list(set(text_sequences))[:100]
        enc = self.tokenizer(
            unique_texts,
            truncation=True,
            padding=True,
            max_length=128,
            return_tensors="pt",
        )
        with torch.no_grad():
            logits = self.model(**enc).logits
            probas = torch.softmax(logits, dim=-1)[:, 1].numpy()
        return float(np.max(probas))

    def predict(self, text_sequence: str, threshold: float = 0.60) -> int:
        return int(self.predict_proba(text_sequence) >= threshold)
'''
    with open(MODELS_DIR / "model_interface.py", "w", encoding="utf-8") as f:
        f.write(interface_code)
    print(f"Generated Common Model Interface at {MODELS_DIR / 'model_interface.py'}")


# ==============================================================================
# MAIN ENTRYPOINT
# ==============================================================================

def main():
    print("=" * 60)
    print("PHASE 5A: CONTROLLED BINARY MODALITY MODEL TRAINING")
    print("=" * 60)

    train_runs, val_runs, test_runs = load_splits()
    print(f"Using Fixed Run Splits: Train={len(train_runs)}, Val={len(val_runs)}, Test={len(test_runs)}")

    # 1. Process
    proc_meta = train_process_model(train_runs, val_runs, test_runs)
    generate_error_analysis("process", proc_meta)

    # 2. Memory
    mem_meta = train_memory_model(train_runs, val_runs, test_runs)
    generate_error_analysis("memory", mem_meta)

    # 3. Network
    net_meta = train_network_model(train_runs, val_runs, test_runs)
    generate_error_analysis("network", net_meta)

    # 4. Command
    cmd_meta = train_command_model(train_runs, val_runs, test_runs)
    generate_error_analysis("command", cmd_meta)

    # 5. Common Interface
    generate_model_interface()

    # 6. Summary CSV
    all_meta = {
        "process": proc_meta,
        "memory": mem_meta,
        "network": net_meta,
        "command": cmd_meta,
    }
    generate_phase5a_summary(all_meta)

    print("\n" + "=" * 60)
    print("ALL 4 BINARY DETECTORS TRAINED AND EVALUATED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
