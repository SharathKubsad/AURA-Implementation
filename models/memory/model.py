"""Memory forensics binary classification model (CatBoost).

Wraps CatBoostClassifier with the common detection model interface:
- predict_proba(X) -> 1D numpy array of probabilities in [0.0, 1.0]
- predict(X, threshold=0.5) -> 1D numpy array of binary predictions
- save(output_dir) / load(model_dir)

CatBoost natively handles missing numeric values (such as unextracted entropy metrics)
via nan_mode="Min".
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
from catboost import CatBoostClassifier

from preprocessing.pipeline import MEMORY_FEATURE_COLS

PERMITTED_MEMORY_FEATURES: list[str] = MEMORY_FEATURE_COLS + ["memory_injection_score"]


class MemoryModel:
    """CatBoost classifier for volatile memory forensic features."""

    def __init__(
        self,
        classifier: CatBoostClassifier | None = None,
        feature_names: list[str] | None = None,
    ) -> None:
        """Initialize MemoryModel.

        Args:
            classifier: Fitted or unfitted CatBoostClassifier instance.
            feature_names: Ordered list of memory feature column names.
        """
        self.classifier = classifier or CatBoostClassifier(
            iterations=100,
            depth=3,
            learning_rate=0.05,
            random_seed=42,
            nan_mode="Min",  # Native handling of optional memory entropy nulls
            verbose=False,
        )
        self.feature_names = feature_names or PERMITTED_MEMORY_FEATURES.copy()

    def _prepare_input(self, X: pd.DataFrame | np.ndarray) -> pd.DataFrame:
        """Extract memory features strictly, computing memory_injection_score if needed."""
        if isinstance(X, pd.DataFrame):
            df_in = X.copy()
            if (
                "memory_injection_score" in self.feature_names
                and "memory_injection_score" not in df_in.columns
            ):
                rwx = (
                    df_in["rwx_page_count"].fillna(0.0)
                    if "rwx_page_count" in df_in.columns
                    else 0.0
                )
                inj = (
                    df_in["injected_code_regions"].fillna(0.0)
                    if "injected_code_regions" in df_in.columns
                    else 0.0
                )
                vad = (
                    df_in["vad_protection_anomaly_count"].fillna(0.0)
                    if "vad_protection_anomaly_count" in df_in.columns
                    else 0.0
                )
                df_in["memory_injection_score"] = rwx * 2.0 + inj * 3.0 + vad * 1.5

            missing = [f for f in self.feature_names if f not in df_in.columns]
            if missing:
                raise KeyError(f"Memory input DataFrame is missing required features: {missing}")

            X_df = df_in[self.feature_names].astype(float)
        else:
            X_mat = np.asarray(X, dtype=float)
            if X_mat.ndim == 1:
                X_mat = X_mat.reshape(1, -1)
            if X_mat.shape[1] != len(self.feature_names):
                raise ValueError(
                    f"Expected {len(self.feature_names)} features, got matrix with {X_mat.shape[1]} columns"
                )
            X_df = pd.DataFrame(X_mat, columns=self.feature_names)

        return X_df

    def predict_proba(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        """Predict malware probability for given memory forensic samples.

        Args:
            X: DataFrame or 2D array containing memory forensic features.

        Returns:
            1D numpy array of shape (N,) with float probabilities in [0.0, 1.0].
        """
        X_df = self._prepare_input(X)
        proba_2d = self.classifier.predict_proba(X_df)
        return proba_2d[:, 1].astype(float)

    def predict(self, X: pd.DataFrame | np.ndarray, threshold: float = 0.5) -> np.ndarray:
        """Predict binary class (0: Benign, 1: Malware) at specified threshold.

        Args:
            X: DataFrame or 2D array containing memory forensic features.
            threshold: Probability threshold for malware classification.

        Returns:
            1D numpy array of shape (N,) with integer class labels {0, 1}.
        """
        probs = self.predict_proba(X)
        return (probs >= threshold).astype(int)

    def save(self, output_dir: Path | str) -> None:
        """Save model weights and feature registry to directory.

        Args:
            output_dir: Target directory path.
        """
        p = Path(output_dir)
        p.mkdir(parents=True, exist_ok=True)

        model_file = p / "model.cbm"
        self.classifier.save_model(str(model_file))

        features_file = p / "features.json"
        features_file.write_text(
            json.dumps({"feature_names": self.feature_names}, indent=2),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, model_dir: Path | str) -> MemoryModel:
        """Load saved MemoryModel from artifact directory.

        Args:
            model_dir: Directory containing model.cbm and features.json.

        Returns:
            Reconstructed MemoryModel instance.
        """
        p = Path(model_dir)
        features_file = p / "features.json"
        if not features_file.exists():
            raise FileNotFoundError(f"Feature specification not found at {features_file}")

        feat_data = json.loads(features_file.read_text(encoding="utf-8"))
        features = feat_data["feature_names"]

        model_file = p / "model.cbm"
        if not model_file.exists():
            raise FileNotFoundError(f"Model file not found at {model_file}")

        clf = CatBoostClassifier()
        clf.load_model(str(model_file))
        return cls(classifier=clf, feature_names=features)
