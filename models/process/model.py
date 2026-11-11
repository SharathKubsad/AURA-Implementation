"""Process telemetry binary classification model (XGBoost).

Wraps XGBClassifier with the common detection model interface:
- predict_proba(X) -> 1D numpy array of probabilities in [0.0, 1.0]
- predict(X, threshold=0.5) -> 1D numpy array of binary predictions
- save(output_dir) / load(model_dir)
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from xgboost import XGBClassifier

from preprocessing.pipeline import PROCESS_FEATURE_COLS

try:
    from sklearn.exceptions import InconsistentVersionWarning

    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
except ImportError:
    pass
warnings.filterwarnings("ignore", message="Trying to unpickle estimator.*")
warnings.filterwarnings("ignore", message=".*InconsistentVersionWarning.*")

PERMITTED_PROCESS_FEATURES: list[str] = PROCESS_FEATURE_COLS + ["thread_to_process_ratio"]


class ProcessModel:
    """XGBoost classifier for process telemetry forensic features."""

    def __init__(
        self,
        classifier: XGBClassifier | None = None,
        feature_names: list[str] | None = None,
        scaler: Any | None = None,
    ) -> None:
        """Initialize ProcessModel.

        Args:
            classifier: Fitted or unfitted XGBClassifier instance.
            feature_names: Ordered list of process feature column names.
            scaler: Fitted preprocessing scaler (StandardScaler or MinMaxScaler).
        """
        self.classifier = classifier or XGBClassifier(
            n_estimators=100,
            max_depth=3,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42,
            eval_metric="logloss",
        )
        self.feature_names = feature_names or PERMITTED_PROCESS_FEATURES.copy()
        self.scaler = scaler

    def _prepare_input(self, X: pd.DataFrame | np.ndarray) -> pd.DataFrame:
        """Extract and validate process features strictly, enforcing modality isolation."""
        if isinstance(X, pd.DataFrame):
            df_in = X.copy()
            # Enforce modality isolation: verify that only process features are used
            missing = [f for f in self.feature_names if f not in df_in.columns]
            if missing:
                # If engineered feature is missing, compute it if possible
                if (
                    "thread_to_process_ratio" in missing
                    and "avg_threads_per_process" in df_in.columns
                    and "total_process_count" in df_in.columns
                ):
                    df_in["thread_to_process_ratio"] = df_in["avg_threads_per_process"] / (
                        df_in["total_process_count"].replace(0, 1.0)
                    )
                    missing.remove("thread_to_process_ratio")
                if missing:
                    raise KeyError(
                        f"Process input DataFrame is missing required features: {missing}"
                    )

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

        if self.scaler is not None:
            scaled_vals = self.scaler.transform(X_df)
            X_df = pd.DataFrame(scaled_vals, columns=self.feature_names)

        return X_df

    def predict_proba(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        """Predict malware probability for given process telemetry samples.

        Args:
            X: DataFrame or 2D array containing process telemetry features.

        Returns:
            1D numpy array of shape (N,) with float probabilities in [0.0, 1.0].
        """
        X_df = self._prepare_input(X)
        proba_2d = self.classifier.predict_proba(X_df)
        # Return probability of positive class (malware = 1)
        return proba_2d[:, 1].astype(float)

    def predict(self, X: pd.DataFrame | np.ndarray, threshold: float = 0.5) -> np.ndarray:
        """Predict binary class (0: Benign, 1: Malware) at specified threshold.

        Args:
            X: DataFrame or 2D array containing process telemetry features.
            threshold: Probability threshold for malware classification.

        Returns:
            1D numpy array of shape (N,) with integer class labels {0, 1}.
        """
        probs = self.predict_proba(X)
        return (probs >= threshold).astype(int)

    def save(self, output_dir: Path | str) -> None:
        """Save model weights, scaler, and feature registry to directory.

        Args:
            output_dir: Target directory path.
        """
        p = Path(output_dir)
        p.mkdir(parents=True, exist_ok=True)

        model_file = p / "model.json"
        self.classifier.save_model(str(model_file))

        if self.scaler is not None:
            joblib.dump(self.scaler, p / "scaler.joblib")

        features_file = p / "features.json"
        features_file.write_text(
            json.dumps({"feature_names": self.feature_names}, indent=2),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, model_dir: Path | str) -> ProcessModel:
        """Load saved ProcessModel from artifact directory.

        Args:
            model_dir: Directory containing model.json and features.json.

        Returns:
            Reconstructed ProcessModel instance.
        """
        p = Path(model_dir)
        features_file = p / "features.json"
        if not features_file.exists():
            raise FileNotFoundError(f"Feature specification not found at {features_file}")

        feat_data = json.loads(features_file.read_text(encoding="utf-8"))
        features = feat_data["feature_names"]

        scaler = None
        scaler_file = p / "scaler.joblib"
        if scaler_file.exists():
            scaler = joblib.load(scaler_file)

        clf = XGBClassifier()
        model_file = p / "model.json"
        if not model_file.exists():
            # Check for legacy .xgb naming
            legacy_file = p / "process_model.xgb"
            if legacy_file.exists():
                clf.load_model(str(legacy_file))
            else:
                raise FileNotFoundError(f"Model file not found at {model_file}")
        else:
            clf.load_model(str(model_file))

        return cls(classifier=clf, feature_names=features, scaler=scaler)
