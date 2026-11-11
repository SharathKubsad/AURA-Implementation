"""Network telemetry binary classification model (LightGBM).

Wraps LGBMClassifier with the common detection model interface:
- predict_proba(X) -> 1D numpy array of probabilities in [0.0, 1.0]
- predict(X, threshold=0.5) -> 1D numpy array of binary predictions
- save(output_dir) / load(model_dir)

Crucial constraint:
PCAP-dependent features (dns_query_count, avg_interpacket_interval_ms, etc.)
are preserved as genuine NaNs. LightGBM natively learns optimal split directions
for missing values; values are never converted to artificial zeros or median-imputed.
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier

from preprocessing.pipeline import NETWORK_FEATURE_COLS, PCAP_NULL_FIELDS

try:
    from sklearn.exceptions import InconsistentVersionWarning

    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
except ImportError:
    pass
warnings.filterwarnings("ignore", message="Trying to unpickle estimator.*")
warnings.filterwarnings("ignore", message=".*InconsistentVersionWarning.*")

PERMITTED_NETWORK_FEATURES: list[str] = NETWORK_FEATURE_COLS + [
    f"is_missing_{f}" for f in sorted(PCAP_NULL_FIELDS)
]


class NetworkModel:
    """LightGBM classifier for network telemetry features with native NaN handling."""

    def __init__(
        self,
        classifier: LGBMClassifier | None = None,
        feature_names: list[str] | None = None,
    ) -> None:
        """Initialize NetworkModel.

        Args:
            classifier: Fitted or unfitted LGBMClassifier instance.
            feature_names: Ordered list of network feature column names.
        """
        self.classifier = classifier or LGBMClassifier(
            n_estimators=100,
            max_depth=3,
            num_leaves=7,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            min_child_samples=3,  # Adjusted for small dataset support
            random_state=42,
            verbosity=-1,
        )
        self.feature_names = feature_names or PERMITTED_NETWORK_FEATURES.copy()

    def _prepare_input(self, X: pd.DataFrame | np.ndarray) -> pd.DataFrame:
        """Extract network features, adding is_missing_* flags while preserving genuine NaNs."""
        if isinstance(X, pd.DataFrame):
            df_in = X.copy()
            # Generate sentinel indicators if missing from DataFrame
            for field in PCAP_NULL_FIELDS:
                sentinel_col = f"is_missing_{field}"
                if sentinel_col not in df_in.columns:
                    if field in df_in.columns:
                        df_in[sentinel_col] = df_in[field].isna().astype(int)
                    else:
                        df_in[sentinel_col] = 1

            missing = [f for f in self.feature_names if f not in df_in.columns]
            if missing:
                raise KeyError(f"Network input DataFrame missing required features: {missing}")

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
        """Predict malware probability for given network telemetry samples.

        Args:
            X: DataFrame or 2D array containing network telemetry features.

        Returns:
            1D numpy array of shape (N,) with float probabilities in [0.0, 1.0].
        """
        X_df = self._prepare_input(X)
        proba_2d = self.classifier.predict_proba(X_df)
        return proba_2d[:, 1].astype(float)

    def predict(self, X: pd.DataFrame | np.ndarray, threshold: float = 0.5) -> np.ndarray:
        """Predict binary class (0: Benign, 1: Malware) at specified threshold.

        Args:
            X: DataFrame or 2D array containing network telemetry features.
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

        joblib.dump(self.classifier, p / "model.joblib")

        features_file = p / "features.json"
        features_file.write_text(
            json.dumps({"feature_names": self.feature_names}, indent=2),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, model_dir: Path | str) -> NetworkModel:
        """Load saved NetworkModel from artifact directory.

        Args:
            model_dir: Directory containing model.joblib and features.json.

        Returns:
            Reconstructed NetworkModel instance.
        """
        p = Path(model_dir)
        features_file = p / "features.json"
        if not features_file.exists():
            raise FileNotFoundError(f"Feature specification not found at {features_file}")

        feat_data = json.loads(features_file.read_text(encoding="utf-8"))
        features = feat_data["feature_names"]

        model_file = p / "model.joblib"
        if not model_file.exists():
            raise FileNotFoundError(f"Model file not found at {model_file}")

        clf = joblib.load(model_file)
        return cls(classifier=clf, feature_names=features)
