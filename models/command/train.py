"""Training pipeline for Command Model (DistilBERT).

Trains a DistilBertForSequenceClassification model strictly on raw_command_text using
deterministic stratified splitting (70/15/15) and a lightweight PyTorch training loop.
"""

from __future__ import annotations

import argparse
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader, Dataset
from transformers import (
    DistilBertConfig,
    DistilBertForSequenceClassification,
    DistilBertTokenizer,
)

from models.command.model import CommandModel
from models.common import (
    SMALL_DATASET_WARNING,
    compute_binary_metrics,
    get_git_commit,
    get_package_version,
    stratified_split_dataset,
)

logger = logging.getLogger("train_command")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


class CommandTextDataset(Dataset):
    """PyTorch Dataset for command string sequence classification."""

    def __init__(
        self,
        texts: list[str],
        labels: list[int] | np.ndarray,
        tokenizer: DistilBertTokenizer,
        max_length: int = 128,
    ) -> None:
        self.texts = texts
        self.labels = [int(y) for y in labels]
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self) -> int:
        return len(self.texts)

    def __getitem__(self, idx: int) -> dict[str, torch.Tensor]:
        text = self.texts[idx]
        label = self.labels[idx]

        encoded = self.tokenizer(
            text,
            padding="max_length",
            truncation=True,
            max_length=self.max_length,
            return_tensors="pt",
        )

        return {
            "input_ids": encoded["input_ids"].squeeze(0),
            "attention_mask": encoded["attention_mask"].squeeze(0),
            "labels": torch.tensor(label, dtype=torch.long),
        }


def _initialize_model_and_tokenizer(
    model_name: str = "distilbert-base-uncased",
) -> tuple[DistilBertForSequenceClassification, DistilBertTokenizer]:
    """Initialize DistilBERT model and tokenizer with offline fallback if Hub is unreachable."""
    try:
        tokenizer = DistilBertTokenizer.from_pretrained(model_name)
        model = DistilBertForSequenceClassification.from_pretrained(model_name, num_labels=2)
        return model, tokenizer
    except Exception as err:
        logger.warning(
            "Could not download %s from Hugging Face Hub (%s). Initializing local DistilBERT configuration.",
            model_name,
            err,
        )
        # Offline initialization using standard DistilBERT architecture configuration
        config = DistilBertConfig(
            vocab_size=30522,
            max_position_embeddings=512,
            n_layers=6,
            n_heads=12,
            dim=768,
            hidden_dim=3072,
            num_labels=2,
        )
        model = DistilBertForSequenceClassification(config)
        # Basic character/word tokenizer fallback if remote tokenizer asset cannot be fetched
        try:
            tokenizer = DistilBertTokenizer.from_pretrained(
                "distilbert-base-uncased", local_files_only=True
            )
        except Exception:
            # Create a minimal vocab tokenizer if completely offline
            from transformers import BertTokenizer

            tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")
        return model, tokenizer


def train_command_model(
    dataset_path: str | Path = "data/processed/unified/unified_dataset.jsonl",
    output_dir: str | Path = "models/artifacts/command",
    eval_dir: str | Path = "evaluation/binary",
    model_name: str = "distilbert-base-uncased",
    batch_size: int = 4,
    epochs: int = 3,
    lr: float = 5e-5,
    max_length: int = 128,
    random_state: int = 42,
) -> dict[str, Any]:
    """Train, validate, and evaluate the Command DistilBERT binary classifier.

    Args:
        dataset_path: Path to unified dataset JSONL or CSV.
        output_dir: Directory where model weights and tokenizer are saved.
        eval_dir: Directory where evaluation JSON report is saved.
        model_name: Base transformer architecture identifier.
        batch_size: Mini-batch size (default: 4 for low memory overhead).
        epochs: Training epochs (default: 3).
        lr: Learning rate for AdamW optimizer (default: 5e-5).
        max_length: Maximum tokenization sequence length.
        random_state: RNG seed for reproducible splitting and initialization.

    Returns:
        Dictionary containing evaluation metrics and training metadata.
    """
    data_file = Path(dataset_path)
    out_path = Path(output_dir)
    eval_path = Path(eval_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    eval_path.mkdir(parents=True, exist_ok=True)

    if not data_file.exists():
        raise FileNotFoundError(f"Unified dataset not found at {data_file}")

    if data_file.suffix == ".jsonl":
        rows = [
            json.loads(line)
            for line in data_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        df = pd.DataFrame(rows)
    else:
        df = pd.read_csv(data_file)

    logger.info("Loaded %d total samples from %s", len(df), data_file)

    if "raw_command_text" not in df.columns:
        raise KeyError("Command dataset missing required column 'raw_command_text'")

    # Set random seeds for reproducibility
    torch.manual_seed(random_state)
    np.random.seed(random_state)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(random_state)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info("Training on device: %s", device)

    # Stratified 70/15/15 train/val/test splitting
    df_train, df_val, df_test = stratified_split_dataset(
        df,
        target_col="binary_label",
        test_size=0.15,
        val_size=0.15,
        random_state=random_state,
    )

    train_texts = ["" if pd.isna(t) else str(t) for t in df_train["raw_command_text"]]
    val_texts = ["" if pd.isna(t) else str(t) for t in df_val["raw_command_text"]]
    test_texts = ["" if pd.isna(t) else str(t) for t in df_test["raw_command_text"]]

    y_train = df_train["binary_label"].astype(int).values
    y_val = df_val["binary_label"].astype(int).values
    y_test = df_test["binary_label"].astype(int).values

    model, tokenizer = _initialize_model_and_tokenizer(model_name)
    model.to(device)

    train_dataset = CommandTextDataset(train_texts, y_train, tokenizer, max_length=max_length)
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)

    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)

    # PyTorch fine-tuning loop
    model.train()
    for epoch in range(1, epochs + 1):
        total_loss = 0.0
        for batch in train_loader:
            optimizer.zero_grad()
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
            loss = outputs.loss
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            total_loss += loss.item()

        avg_loss = total_loss / max(len(train_loader), 1)
        logger.info("Epoch %d/%d complete - Average Loss: %.4f", epoch, epochs, avg_loss)

    # Wrap in CommandModel
    command_model = CommandModel(
        model=model,
        tokenizer=tokenizer,
        max_length=max_length,
        device=device,
    )

    # Evaluate on test set (and validation set for reference)
    val_probs = command_model.predict_proba(val_texts)
    val_metrics = compute_binary_metrics(y_val, val_probs)

    test_probs = command_model.predict_proba(test_texts)
    test_metrics = compute_binary_metrics(y_test, test_probs)

    logger.info("Test Metrics for Command Model (DistilBERT): %s", test_metrics)

    hyperparams = {
        "architecture": "DistilBertForSequenceClassification",
        "base_model": model_name,
        "epochs": epochs,
        "batch_size": batch_size,
        "learning_rate": lr,
        "max_length": max_length,
        "random_seed": random_state,
        "device": str(device),
    }

    # Metadata specification
    metadata: dict[str, Any] = {
        "model_type": "distilbert",
        "modality": "command",
        "dataset_source": str(data_file.resolve()),
        "train_sample_count": len(df_train),
        "validation_sample_count": len(df_val),
        "test_sample_count": len(df_test),
        "train_class_distribution": {
            "benign": int(sum(y_train == 0)),
            "malware": int(sum(y_train == 1)),
        },
        "validation_class_distribution": {
            "benign": int(sum(y_val == 0)),
            "malware": int(sum(y_val == 1)),
        },
        "test_class_distribution": {
            "benign": int(sum(y_test == 0)),
            "malware": int(sum(y_test == 1)),
        },
        "feature_names": ["raw_command_text"],
        "random_seed": random_state,
        "hyperparameters": hyperparams,
        "training_timestamp": datetime.now(tz=UTC).isoformat(),
        "software_versions": {
            "torch": get_package_version("torch"),
            "transformers": get_package_version("transformers"),
            "scikit-learn": get_package_version("scikit-learn"),
            "pandas": get_package_version("pandas"),
        },
        "git_commit": get_git_commit(),
        "small_dataset_warning": SMALL_DATASET_WARNING,
    }

    # Save model artifacts
    command_model.save(out_path)
    (out_path / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    # Save evaluation report
    eval_report = {
        "model": "CommandModel (DistilBERT)",
        "modality": "command",
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics,
        "metadata": metadata,
    }
    eval_file = eval_path / "command_evaluation.json"
    eval_file.write_text(json.dumps(eval_report, indent=2), encoding="utf-8")

    logger.info("Command model artifacts saved to %s", out_path)
    logger.info("Command evaluation report saved to %s", eval_file)

    return eval_report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Command DistilBERT Model")
    parser.add_argument("--dataset", default="data/processed/unified/unified_dataset.jsonl")
    parser.add_argument("--output-dir", default="models/artifacts/command")
    parser.add_argument("--eval-dir", default="evaluation/binary")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    train_command_model(
        dataset_path=args.dataset,
        output_dir=args.output_dir,
        eval_dir=args.eval_dir,
        epochs=args.epochs,
        random_state=args.seed,
    )
