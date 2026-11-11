"""Inference predictor and CLI for Command Model (DistilBERT)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from models.command.model import CommandModel


class CommandPredictor:
    """Production predictor wrapping serialized CommandModel."""

    def __init__(self, model_dir: str | Path = "models/artifacts/command") -> None:
        """Load model from artifact directory."""
        self.model_dir = Path(model_dir)
        self.model = CommandModel.load(self.model_dir)

    def predict_proba(self, X: Any) -> np.ndarray:
        """Predict malware probability for raw command string inputs."""
        return self.model.predict_proba(X)

    def predict(self, X: Any, threshold: float = 0.5) -> np.ndarray:
        """Predict binary class for raw command string inputs."""
        return self.model.predict(X, threshold=threshold)


def main() -> None:
    """CLI for standalone command text prediction."""
    parser = argparse.ArgumentParser(description="Predict using CommandModel (DistilBERT)")
    parser.add_argument(
        "--model-dir", default="models/artifacts/command", help="Artifacts directory"
    )
    parser.add_argument("--command", help="Single raw command string to score")
    parser.add_argument("--input", help="Input CSV or JSON file containing 'raw_command_text'")
    parser.add_argument("--output", help="Optional output JSON file")
    parser.add_argument("--threshold", type=float, default=0.5, help="Classification threshold")
    args = parser.parse_args()

    predictor = CommandPredictor(args.model_dir)

    if args.command:
        prob = float(predictor.predict_proba([args.command])[0])
        pred = 1 if prob >= args.threshold else 0
        result = {
            "raw_command_text": args.command,
            "malware_probability": round(prob, 4),
            "predicted_class": pred,
            "verdict": "malware" if pred == 1 else "benign",
        }
        print(json.dumps(result, indent=2))
        return

    if not args.input:
        parser.error("Either --command or --input must be provided.")

    in_path = Path(args.input)
    if in_path.suffix == ".json":
        data = json.loads(in_path.read_text(encoding="utf-8"))
        df = pd.DataFrame([data] if isinstance(data, dict) else data)
    else:
        df = pd.read_csv(in_path)

    probs = predictor.predict_proba(df)
    preds = (probs >= args.threshold).astype(int)

    results = []
    for i, (prob, pred) in enumerate(zip(probs, preds, strict=False)):
        sid = df["sample_id"].iloc[i] if "sample_id" in df.columns else f"sample_{i}"
        cmd_txt = df["raw_command_text"].iloc[i] if "raw_command_text" in df.columns else ""
        results.append(
            {
                "sample_id": sid,
                "raw_command_text": cmd_txt,
                "malware_probability": round(float(prob), 4),
                "predicted_class": int(pred),
                "verdict": "malware" if pred == 1 else "benign",
            }
        )

    if args.output:
        Path(args.output).write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"Saved {len(results)} predictions to {args.output}")
    else:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
