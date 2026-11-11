"""Data preprocessing and feature engineering pipeline (Objectives 1 & 2).

Design contracts
----------------
* The pipeline MUST be fitted exclusively on training data.
* Scaler, zero-variance filter, and (optionally) SMOTE are all fit on the
  training partition and then applied without re-fitting to val/test.
* sample_id is NEVER included in the model feature matrix.
* Legitimate null values (PCAP-unavailable fields) are represented as NaN
  in NumPy/pandas matrices but tracked via is_missing_* sentinel features
  so tree-based models can condition on availability.
* Zero-variance features (constant across training set) are recorded and
  excluded; the removed list is serialised so inference code can replicate
  the exact column-drop.
* SMOTE / ADASYN is applied ONLY to the training partition, never to
  validation or test.

Implements
----------
1. Stratified train / val / test split (70 / 15 / 15)
2. Null-sentinel feature generation for PCAP-null fields
3. Zero-variance removal (fit on train)
4. StandardScaler / MinMaxScaler (fit on train)
5. Class balancing with SMOTE or ADASYN (train only)
6. Composite feature engineering
7. Serialisation / deserialisation of fitted pipeline
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.preprocessing import MinMaxScaler, StandardScaler

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Feature column definitions
# ---------------------------------------------------------------------------
PROCESS_FEATURE_COLS: list[str] = [
    "total_process_count",
    "hidden_process_count",
    "anomalous_ppid_count",
    "avg_threads_per_process",
    "max_threads_in_single_process",
    "total_handle_count",
    "suspicious_dll_count",
    "malfind_process_count",
    "elevated_privilege_count",
    "unlinked_dll_count",
]

MEMORY_FEATURE_COLS: list[str] = [
    "rwx_page_count",
    "injected_code_regions",
    "unmapped_executable_pages",
    "vad_protection_anomaly_count",
    "ldrmodules_inconsistencies",
    "yara_shellcode_matches",
    "mean_memory_entropy",
    "max_memory_entropy",
]

COMMAND_FEATURE_COLS: list[str] = [
    "command_length",
    "shannon_entropy",
    "is_base64_encoded",
    "has_download_cradle",
    "has_bypass_execution_policy",
    "has_hidden_window",
    "uses_lolbins",
    "registry_persistence_count",
]

NETWORK_FEATURE_COLS: list[str] = [
    "active_connection_count",
    "listening_port_count",
    "outbound_connection_count",
    "dns_query_count",
    "unique_remote_ips",
    "avg_interpacket_interval_ms",
    "beacon_regularity_score",
    "total_bytes_sent",
    "total_bytes_received",
    "suspicious_port_usage",
]

# Fields that are legitimately null when PCAP is unavailable (host-only capture)
PCAP_NULL_FIELDS: frozenset[str] = frozenset(
    [
        "dns_query_count",
        "avg_interpacket_interval_ms",
        "beacon_regularity_score",
        "total_bytes_sent",
        "total_bytes_received",
    ]
)

ALL_NUMERIC_FEATURE_COLS: list[str] = (
    PROCESS_FEATURE_COLS + MEMORY_FEATURE_COLS + COMMAND_FEATURE_COLS + NETWORK_FEATURE_COLS
)

# Engineered composite feature names
ENGINEERED_COLS: list[str] = [
    "thread_to_process_ratio",
    "memory_injection_score",
    "cmd_stealth_factor",
]

# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


def load_unified_jsonl(jsonl_path: Path) -> pd.DataFrame:
    """Load unified dataset from JSONL file into a DataFrame.

    Args:
        jsonl_path: Path to ``unified_dataset.jsonl``.

    Returns:
        DataFrame with one row per sample; all columns including metadata.

    Raises:
        FileNotFoundError: If ``jsonl_path`` does not exist.
    """
    if not jsonl_path.exists():
        raise FileNotFoundError(f"Unified JSONL not found: {jsonl_path}")
    rows = []
    with jsonl_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    df = pd.DataFrame(rows)
    logger.info("Loaded %d samples from %s", len(df), jsonl_path)
    return df


# ---------------------------------------------------------------------------
# Preprocessing pipeline
# ---------------------------------------------------------------------------


class PreprocessingPipeline:
    """End-to-end preprocessing pipeline with strict no-leakage contract.

    The pipeline must be ``fit`` only on training data. ``transform`` applies
    the fitted transformations to any partition (train / val / test) without
    re-fitting.

    Attributes:
        scaler_type: ``"standard"`` (default) or ``"minmax"``.
        val_size: Fraction of data for validation split.
        test_size: Fraction of data for test split.
        random_state: RNG seed for reproducibility.
        zero_variance_features_: Features removed due to zero variance on train.
        removed_features_: All features removed for any reason.
        selected_features_: Final ordered list of features after removal.
        engineered_feature_cols_: Names of added composite features.
        _fitted: Whether the pipeline has been fitted.
    """

    def __init__(
        self,
        scaler_type: str = "standard",
        val_size: float = 0.15,
        test_size: float = 0.15,
        random_state: int = 42,
    ) -> None:
        """Initialise the pipeline.

        Args:
            scaler_type: ``"standard"`` for StandardScaler, ``"minmax"`` for
                MinMaxScaler.
            val_size: Fraction of data used for validation.
            test_size: Fraction of data used for test.
            random_state: RNG seed used in all stochastic operations.
        """
        self.scaler_type = scaler_type
        self.val_size = val_size
        self.test_size = test_size
        self.random_state = random_state

        self._scaler: StandardScaler | MinMaxScaler = (
            StandardScaler() if scaler_type == "standard" else MinMaxScaler()
        )
        self.zero_variance_features_: list[str] = []
        self.removed_features_: list[str] = []
        self.selected_features_: list[str] = []
        self.engineered_feature_cols_: list[str] = []
        self._fitted: bool = False
        self._null_sentinel_cols: list[str] = []

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def split(
        self,
        df: pd.DataFrame,
        target_col: str = "binary_label",
        stratify_col: str | None = "family",
    ) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """Stratified train / val / test split.

        Splits are stratified by ``stratify_col`` when provided (falls back to
        ``target_col`` if any stratum has fewer than 2 members).

        Args:
            df: Full unified DataFrame.
            target_col: Binary label column name.
            stratify_col: Column to use for stratification (default: ``family``).

        Returns:
            Tuple of (train_df, val_df, test_df).
        """
        # Build stratification key – combine family + label for richest strata
        if stratify_col and stratify_col in df.columns:
            strat_key = df[stratify_col].astype(str) + "_" + df[target_col].astype(str)
            # Fall back to label-only if any stratum has <2 members
            if strat_key.value_counts().min() < 2:
                logger.warning(
                    "Stratify-by-family produces singletons; falling back to label-only stratification."
                )
                strat_key = df[target_col].astype(str)
        else:
            strat_key = df[target_col].astype(str)

        # First split: carve out test
        sss_test = StratifiedShuffleSplit(
            n_splits=1,
            test_size=self.test_size,
            random_state=self.random_state,
        )
        train_val_idx, test_idx = next(sss_test.split(df, strat_key))
        df_train_val = df.iloc[train_val_idx].reset_index(drop=True)
        df_test = df.iloc[test_idx].reset_index(drop=True)

        # Second split: carve out val from train_val
        strat_key_tv = strat_key.iloc[train_val_idx].reset_index(drop=True)
        if strat_key_tv.value_counts().min() < 2:
            strat_key_tv = df_train_val[target_col].astype(str)

        relative_val = self.val_size / (1.0 - self.test_size)
        sss_val = StratifiedShuffleSplit(
            n_splits=1,
            test_size=relative_val,
            random_state=self.random_state,
        )
        train_idx, val_idx = next(sss_val.split(df_train_val, strat_key_tv))
        df_train = df_train_val.iloc[train_idx].reset_index(drop=True)
        df_val = df_train_val.iloc[val_idx].reset_index(drop=True)

        logger.info("Split: train=%d  val=%d  test=%d", len(df_train), len(df_val), len(df_test))
        return df_train, df_val, df_test

    def fit_transform(
        self,
        df_train: pd.DataFrame,
        target_col: str = "binary_label",
        balance_method: str | None = "smote",
    ) -> tuple[pd.DataFrame, pd.Series, pd.Series]:
        """Fit pipeline on training data and return transformed training set.

        This is the ONLY method that fits (calibrates) the scaler and
        zero-variance filter. It must not be called on validation or test data.

        Args:
            df_train: Training partition DataFrame.
            target_col: Binary label column.
            balance_method: ``"smote"``, ``"adasyn"``, or ``None`` to skip.

        Returns:
            Tuple of (X_train, y_train, sample_ids_train) where:
              - X_train is a scaled, engineered, zero-variance-filtered DataFrame
              - y_train is a binary label Series (may be oversampled)
              - sample_ids_train is the sample_id Series aligned with X_train
        """
        # 1. Add null sentinels for PCAP-null fields
        df_feat = self._add_null_sentinels(df_train)

        # 2. Impute missing values (median — computed from train only)
        df_feat = self._fit_impute(df_feat)

        # 3. Engineer composite features
        df_feat = self._engineer_features(df_feat)

        # 4. Collect all candidate numeric features
        candidate_cols = self._all_candidate_cols()
        candidate_cols = [c for c in candidate_cols if c in df_feat.columns]

        y = df_train[target_col].astype(int).reset_index(drop=True)
        sample_ids = df_train["sample_id"].reset_index(drop=True)

        X = df_feat[candidate_cols].copy()

        # 5. Remove zero-variance features (fit on train)
        self.zero_variance_features_ = [
            col for col in candidate_cols if X[col].nunique(dropna=False) <= 1
        ]
        self.removed_features_ = self.zero_variance_features_.copy()
        active_cols = [c for c in candidate_cols if c not in self.removed_features_]
        X = X[active_cols]
        if self.zero_variance_features_:
            logger.info(
                "Removed %d zero-variance features: %s",
                len(self.zero_variance_features_),
                self.zero_variance_features_,
            )

        # 6. Fit scaler on training data
        X_arr = self._scaler.fit_transform(X.values.astype(float))
        X_scaled = pd.DataFrame(X_arr, columns=active_cols, index=X.index)

        self.selected_features_ = active_cols
        self._fitted = True

        # 7. SMOTE / ADASYN on training partition only
        if balance_method:
            X_scaled, y, sample_ids = self._balance_train(X_scaled, y, sample_ids, balance_method)

        return X_scaled, y, sample_ids

    def transform(
        self,
        df: pd.DataFrame,
        target_col: str = "binary_label",
    ) -> tuple[pd.DataFrame, pd.Series, pd.Series]:
        """Transform val/test data using the already-fitted pipeline.

        Must be called after ``fit_transform``. Does NOT fit the scaler or
        zero-variance filter.

        Args:
            df: Validation or test partition DataFrame.
            target_col: Binary label column.

        Returns:
            Tuple of (X, y, sample_ids).

        Raises:
            RuntimeError: If pipeline has not been fitted.
        """
        if not self._fitted:
            raise RuntimeError("Pipeline has not been fitted. Call fit_transform first.")

        df_feat = self._add_null_sentinels(df)
        df_feat = self._apply_impute(df_feat)
        df_feat = self._engineer_features(df_feat)

        # Apply exactly the fitted feature set; fill missing columns with 0
        X = pd.DataFrame(index=df_feat.index)
        for col in self.selected_features_:
            X[col] = df_feat[col] if col in df_feat.columns else 0.0

        X_arr = self._scaler.transform(X.values.astype(float))
        X_scaled = pd.DataFrame(X_arr, columns=self.selected_features_, index=X.index)

        y = df[target_col].astype(int).reset_index(drop=True)
        sample_ids = df["sample_id"].reset_index(drop=True)

        return X_scaled, y, sample_ids

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def save(self, output_dir: Path | str = "models/artifacts") -> None:
        """Serialise fitted pipeline components to disk.

        Args:
            output_dir: Directory to write ``scaler.joblib`` and
                ``pipeline_config.json``.

        Raises:
            RuntimeError: If pipeline has not been fitted.
        """
        import joblib

        if not self._fitted:
            raise RuntimeError("Cannot save an unfitted pipeline.")
        p = Path(output_dir)
        p.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._scaler, p / "scaler.joblib")
        config: dict[str, Any] = {
            "scaler_type": self.scaler_type,
            "val_size": self.val_size,
            "test_size": self.test_size,
            "random_state": self.random_state,
            "selected_features": self.selected_features_,
            "zero_variance_features": self.zero_variance_features_,
            "removed_features": self.removed_features_,
            "engineered_feature_cols": self.engineered_feature_cols_,
            "null_sentinel_cols": self._null_sentinel_cols,
            "imputation_medians": self._imputation_medians,
        }
        (p / "pipeline_config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
        logger.info("Saved pipeline to %s", p)

    @classmethod
    def load(cls, artifacts_dir: Path | str = "models/artifacts") -> PreprocessingPipeline:
        """Load a previously serialised pipeline from disk.

        Args:
            artifacts_dir: Directory containing ``scaler.joblib`` and
                ``pipeline_config.json``.

        Returns:
            A fully configured, fitted ``PreprocessingPipeline`` instance.
        """
        import joblib

        p = Path(artifacts_dir)
        config = json.loads((p / "pipeline_config.json").read_text(encoding="utf-8"))
        pipe = cls(
            scaler_type=config["scaler_type"],
            val_size=config["val_size"],
            test_size=config["test_size"],
            random_state=config["random_state"],
        )
        pipe._scaler = joblib.load(p / "scaler.joblib")
        pipe.selected_features_ = config["selected_features"]
        pipe.zero_variance_features_ = config["zero_variance_features"]
        pipe.removed_features_ = config["removed_features"]
        pipe.engineered_feature_cols_ = config["engineered_feature_cols"]
        pipe._null_sentinel_cols = config["null_sentinel_cols"]
        pipe._imputation_medians = config["imputation_medians"]
        pipe._fitted = True
        return pipe

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _all_candidate_cols(self) -> list[str]:
        """Return ordered list of all numeric candidate feature columns."""
        base = ALL_NUMERIC_FEATURE_COLS + ENGINEERED_COLS
        sentinel = self._null_sentinel_cols or [f"is_missing_{f}" for f in sorted(PCAP_NULL_FIELDS)]
        result: list[str] = []
        for col in base + sentinel:
            if col not in result:
                result.append(col)
        return result

    def _add_null_sentinels(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add binary is_missing_* flags for PCAP-null fields.

        Args:
            df: Input DataFrame with original feature columns.

        Returns:
            DataFrame with added sentinel columns (original nulls preserved).
        """
        df_out = df.copy()
        sentinel_cols: list[str] = []
        for field in sorted(PCAP_NULL_FIELDS):
            sentinel_col = f"is_missing_{field}"
            if field in df_out.columns:
                df_out[sentinel_col] = df_out[field].isna().astype(int)
            else:
                df_out[sentinel_col] = 1  # field entirely absent → treat as missing
            sentinel_cols.append(sentinel_col)
        self._null_sentinel_cols = sentinel_cols
        return df_out

    # Imputation state
    _imputation_medians: dict[str, float] = {}

    def _fit_impute(self, df: pd.DataFrame) -> pd.DataFrame:
        """Fit median imputation from training data and apply it.

        Imputation medians are computed from the training partition exclusively.
        Columns not in ALL_NUMERIC_FEATURE_COLS are set to 0.0 if absent.

        Args:
            df: Training DataFrame with optional nulls.

        Returns:
            Imputed copy of the DataFrame.
        """
        df_out = df.copy()
        self._imputation_medians = {}
        all_cols = ALL_NUMERIC_FEATURE_COLS + ENGINEERED_COLS
        for col in all_cols:
            if col in df_out.columns:
                finite_vals = df_out[col].dropna()
                median_val: float = float(finite_vals.median()) if len(finite_vals) > 0 else 0.0
                self._imputation_medians[col] = median_val
                df_out[col] = df_out[col].fillna(median_val)
            else:
                self._imputation_medians[col] = 0.0
                df_out[col] = 0.0
        return df_out

    def _apply_impute(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply previously fitted imputation medians to val/test data.

        Args:
            df: DataFrame to impute (val or test partition).

        Returns:
            Imputed copy of the DataFrame.
        """
        df_out = df.copy()
        for col, median_val in self._imputation_medians.items():
            if col in df_out.columns:
                df_out[col] = df_out[col].fillna(median_val)
            else:
                df_out[col] = median_val
        return df_out

    def _engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add composite engineered features.

        Derived features:
        - ``thread_to_process_ratio``: avg threads / process count
        - ``memory_injection_score``: weighted combination of RWX + injected + VAD anomalies
        - ``cmd_stealth_factor``: weighted combination of command obfuscation indicators

        Note: ``bytes_sent_ratio`` is intentionally omitted because
        ``total_bytes_sent`` and ``total_bytes_received`` are PCAP-null fields;
        computing a ratio over imputed zeros would be misleading.

        Args:
            df: DataFrame with base features available.

        Returns:
            Copy with engineered feature columns added.
        """
        df_out = df.copy()

        def _col(name: str, default: float = 0.0) -> pd.Series:
            """Return column if present, else a Series of default values."""
            if name in df_out.columns:
                return df_out[name].fillna(default)
            return pd.Series(default, index=df_out.index, dtype=float)

        # Thread/process ratio
        df_out["thread_to_process_ratio"] = _col("avg_threads_per_process") / (
            _col("total_process_count", 1.0).replace(0, 1.0)
        )

        # Memory injection composite
        df_out["memory_injection_score"] = (
            _col("rwx_page_count") * 2.0
            + _col("injected_code_regions") * 3.0
            + _col("vad_protection_anomaly_count") * 1.5
        )

        # Command stealth composite
        df_out["cmd_stealth_factor"] = (
            _col("has_hidden_window") * 2
            + _col("has_bypass_execution_policy") * 2
            + _col("is_base64_encoded") * 3
            + _col("has_download_cradle") * 3
        )

        self.engineered_feature_cols_ = ENGINEERED_COLS.copy()
        return df_out

    def _balance_train(
        self,
        X: pd.DataFrame,
        y: pd.Series,
        sample_ids: pd.Series,
        method: str,
    ) -> tuple[pd.DataFrame, pd.Series, pd.Series]:
        """Apply SMOTE or ADASYN to the training partition only.

        Synthetic samples receive auto-generated IDs of the form
        ``SYNTHETIC_<n>`` so they can be distinguished from real samples.

        Args:
            X: Scaled training feature matrix.
            y: Binary training labels.
            sample_ids: Training sample IDs aligned with X.
            method: ``"smote"`` or ``"adasyn"``.

        Returns:
            Tuple of (X_resampled, y_resampled, sample_ids_resampled).
        """
        try:
            if method.lower() == "adasyn":
                from imblearn.over_sampling import ADASYN

                sampler: Any = ADASYN(random_state=self.random_state)
            else:
                from imblearn.over_sampling import SMOTE

                sampler = SMOTE(random_state=self.random_state)

            X_arr, y_arr = sampler.fit_resample(X.values, y.values)
            n_original = len(X)
            n_synthetic = len(X_arr) - n_original
            synth_ids = pd.Series(
                [f"SYNTHETIC_{i}" for i in range(n_synthetic)],
                name="sample_id",
            )
            new_sample_ids = pd.concat(
                [sample_ids.reset_index(drop=True), synth_ids], ignore_index=True
            )
            X_res = pd.DataFrame(X_arr, columns=X.columns)
            y_res = pd.Series(y_arr, name=y.name)
            logger.info(
                "Balanced with %s: %d → %d (+%d synthetic)",
                method.upper(),
                n_original,
                len(X_res),
                n_synthetic,
            )
            return X_res, y_res, new_sample_ids
        except Exception as exc:
            logger.warning(
                "SMOTE/ADASYN failed (%s); returning original training distribution.", exc
            )
            return X, y, sample_ids

    # ------------------------------------------------------------------
    # Backwards-compatible helpers (used by older calling code / tests)
    # ------------------------------------------------------------------

    def fit_transform_full(
        self,
        df: pd.DataFrame,
        target_col: str = "binary_label",
        balance_method: str = "smote",
    ) -> tuple[pd.DataFrame, pd.Series]:
        """Legacy helper: fit on the full df and return (X, y).

        Retained for backward compatibility with pre-split test scaffolding.
        In production, use ``split()`` + ``fit_transform()`` + ``transform()``.

        Args:
            df: Full unified DataFrame.
            target_col: Binary label column.
            balance_method: Oversampling method.

        Returns:
            Tuple of (X_transformed, y_transformed).
        """
        x, y, _ = self.fit_transform(df, target_col=target_col, balance_method=balance_method)
        return x, y

    def _deduplicate(self, df: pd.DataFrame) -> pd.DataFrame:
        """Remove duplicate samples based on numeric telemetry fingerprint.

        Args:
            df: Input DataFrame.

        Returns:
            Deduplicated DataFrame.
        """
        subset_cols = [c for c in ALL_NUMERIC_FEATURE_COLS if c in df.columns]
        before = len(df)
        df_dedup = df.drop_duplicates(subset=subset_cols).copy()
        logger.info("Deduplication: %d → %d samples", before, len(df_dedup))
        return df_dedup
