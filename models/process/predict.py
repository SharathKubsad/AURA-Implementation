"""Inference predictor and CLI for Process Model (XGBoost)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from models.process.model import ProcessModel


class ProcessPredictor:
    """Production predictor wrapping serialized ProcessModel."""

    def __init__(self, model_dir: str | Path = "models/artifacts/process") -> None:
        """Load model from artifact directory."""
        self.model_dir = Path(model_dir)
        self.model = ProcessModel.load(self.model_dir)

    def predict_proba(
        self, X: pd.DataFrame | np.ndarray | dict[str, Any] | list[dict[str, Any]]
    ) -> np.ndarray:
        """Predict malware probability for input samples."""
        if isinstance(X, dict):
            X = pd.DataFrame([X])
        elif isinstance(X, list) and len(X) > 0 and isinstance(X[0], dict):
            X = pd.DataFrame(X)
        return self.model.predict_proba(X)

    def predict(
        self,
        X: pd.DataFrame | np.ndarray | dict[str, Any] | list[dict[str, Any]],
        threshold: float = 0.5,
    ) -> np.ndarray:
        """Predict binary class for input samples."""
        probs = self.predict_proba(X)
        return (probs >= threshold).astype(int)


def main() -> None:
    """CLI for standalone process prediction."""
    parser = argparse.ArgumentParser(description="Predict using ProcessModel (XGBoost)")
    parser.add_argument(
        "--model-dir", default="models/artifacts/process", help="Artifacts directory"
    )
    parser.add_argument(
        "--input", required=True, help="Input CSV or JSON file containing process telemetry"
    )
    parser.add_argument("--output", help="Optional output JSON file")
    parser.add_argument("--threshold", type=float, default=0.5, help="Classification threshold")
    args = parser.parse_args()

    predictor = ProcessPredictor(args.model_dir)
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
        results.append(
            {
                "sample_id": sid,
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
