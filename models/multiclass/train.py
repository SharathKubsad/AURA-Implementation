"""Train Multi-Class Family Classifier (Objective 3 - XGBoost).

Reuses already-computed 4-modality feature vector (Process + Command + Network + Memory)
to attribute exact malware family from the authentic unified custom dataset.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from models.multiclass.train_on_custom import (
    FAMILY_LABEL_MAP,
    train_multiclass_model as _train_on_custom,
)


def train_multiclass_model(
    data_path: str | Path = "data/processed/unified/unified_dataset.jsonl",
    output_dir: str | Path = "models/multiclass/artifacts",
) -> dict[str, Any]:
    """Train multi-class XGBoost classifier on fused 4-modality vector from authentic data."""
    return _train_on_custom(
        data_path=Path(data_path),
        output_dir=Path(output_dir),
    )


if __name__ == "__main__":
    train_multiclass_model()

