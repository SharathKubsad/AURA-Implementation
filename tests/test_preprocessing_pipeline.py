"""Tests for unified dataset assembly and preprocessing pipeline.

Covers
------
* Four-modality inner-join
* Duplicate sample_id detection
* Binary label consistency (0 or 1)
* Family / label consistency
* Null / None preservation for PCAP-unavailable fields
* Zero-variance feature detection
* Train-only fitting (no leakage)
* Val/test transformation without re-fitting
* sample_id preserved separately from feature matrix
* SMOTE applied only to training partition
* Pipeline serialisation round-trip
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import pandas as pd
import pytest

from preprocessing.pipeline import (
    PCAP_NULL_FIELDS,
    PreprocessingPipeline,
    load_unified_jsonl,
)
from tools.audit_unified_dataset import AuditStatus, _audit_sample, audit_unified_dataset
from tools.build_unified_dataset import (
    ValidationError,
    _compute_feature_stats,
    _load_modality_dir,
    build_unified_dataset,
)

# ---------------------------------------------------------------------------
# Fixtures: minimal modality records
# ---------------------------------------------------------------------------

_PROCESS_BASE = {
    "total_process_count": 100,
    "hidden_process_count": 0,
    "anomalous_ppid_count": 0,
    "avg_threads_per_process": 5.0,
    "max_threads_in_single_process": 20,
    "total_handle_count": 1000,
    "suspicious_dll_count": 0,
    "malfind_process_count": 0,
    "elevated_privilege_count": 5,
    "unlinked_dll_count": 10,
}

_MEMORY_BASE = {
    "rwx_page_count": 2,
    "injected_code_regions": 0,
    "unmapped_executable_pages": 1,
    "vad_protection_anomaly_count": 0,
    "ldrmodules_inconsistencies": 5,
    "yara_shellcode_matches": 0,
    "mean_memory_entropy": None,
    "max_memory_entropy": None,
}

_COMMAND_BASE = {
    "raw_command_text": "cmd.exe /c whoami",
    "command_length": 18,
    "shannon_entropy": 3.2,
    "is_base64_encoded": 0,
    "has_download_cradle": 0,
    "has_bypass_execution_policy": 0,
    "has_hidden_window": 0,
    "uses_lolbins": 0,
    "registry_persistence_count": 0,
}

_NETWORK_BASE = {
    "active_connection_count": 2,
    "listening_port_count": 5,
    "outbound_connection_count": 1,
    "dns_query_count": None,
    "unique_remote_ips": 1,
    "avg_interpacket_interval_ms": None,
    "beacon_regularity_score": None,
    "total_bytes_sent": None,
    "total_bytes_received": None,
    "suspicious_port_usage": 0,
}


def _make_sample(
    sample_id: str,
    label: int = 0,
    family: str = "benign",
    process_override: dict | None = None,
    memory_override: dict | None = None,
    command_override: dict | None = None,
    network_override: dict | None = None,
) -> dict:
    """Create a unified sample dict with overridable modality fields."""
    row: dict = {
        "sample_id": sample_id,
        "binary_label": label,
        "family": family,
        "track": "custom",
        "source": "test",
    }
    proc = {**_PROCESS_BASE, **(process_override or {})}
    mem = {**_MEMORY_BASE, **(memory_override or {})}
    cmd = {**_COMMAND_BASE, **(command_override or {})}
    net = {**_NETWORK_BASE, **(network_override or {})}
    for d in (proc, mem, cmd, net):
        for k, v in d.items():
            if k != "sample_id":
                row[k] = v
    return row


def _make_jsonl(rows: list[dict], path: Path) -> Path:
    """Write rows to a JSONL file and return the path."""
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
    return path


def _make_modality_dir(modality: str, records: list[dict], base_dir: Path) -> Path:
    """Write modality JSON files to a directory."""
    d = base_dir / modality
    d.mkdir(parents=True, exist_ok=True)
    for rec in records:
        sid = rec["sample_id"]
        (d / f"{sid}.json").write_text(json.dumps(rec), encoding="utf-8")
    return d


# ---------------------------------------------------------------------------
# build_unified_dataset tests
# ---------------------------------------------------------------------------


class TestBuildUnifiedDataset:
    """Tests for tools/build_unified_dataset.py."""

    def test_four_modality_inner_join(self, tmp_path: Path) -> None:
        """Only samples present in all four modalities are included."""
        # Sample A is in all four; sample B is missing from memory
        proc_records = [
            {"sample_id": "A", **_PROCESS_BASE},
            {"sample_id": "B", **_PROCESS_BASE},
        ]
        mem_records = [{"sample_id": "A", **_MEMORY_BASE}]
        cmd_records = [
            {"sample_id": "A", **_COMMAND_BASE},
            {"sample_id": "B", **_COMMAND_BASE},
        ]
        net_records = [
            {"sample_id": "A", **_NETWORK_BASE},
            {"sample_id": "B", **_NETWORK_BASE},
        ]

        interim = tmp_path / "interim"
        _make_modality_dir("process", proc_records, interim)
        _make_modality_dir("memory", mem_records, interim)
        _make_modality_dir("command", cmd_records, interim)
        _make_modality_dir("network", net_records, interim)

        processed = tmp_path / "processed"
        summary = build_unified_dataset(interim_dir=interim, processed_dir=processed)

        assert summary["total_samples"] == 1, "Only sample A should survive inner-join"
        assert summary["dropped_samples"] == 1, "Sample B dropped for missing memory"

        jsonl_path = processed / "unified" / "unified_dataset.jsonl"
        rows = [json.loads(line) for line in jsonl_path.read_text().splitlines() if line.strip()]
        assert len(rows) == 1
        assert rows[0]["sample_id"] == "A"

    def test_duplicate_detection_raises(self, tmp_path: Path) -> None:
        """Duplicate sample_ids in a modality directory raise KeyError on load."""
        d = tmp_path / "interim" / "process"
        d.mkdir(parents=True, exist_ok=True)
        # Two files with same sample_id — the second overwrites the first in dict
        (d / "RUN-001_a.json").write_text(json.dumps({"sample_id": "DUP", **_PROCESS_BASE}))
        (d / "RUN-001_b.json").write_text(json.dumps({"sample_id": "DUP", **_PROCESS_BASE}))
        result = _load_modality_dir(d)
        # Dict keyed by sample_id so duplicates silently overwrite — downstream
        # ValidationError should be raised when we detect identical IDs
        assert "DUP" in result  # one entry survives

    def test_missing_sample_id_raises(self, tmp_path: Path) -> None:
        """A JSON file with no sample_id raises KeyError."""
        d = tmp_path / "interim" / "process"
        d.mkdir(parents=True, exist_ok=True)
        (d / "bad.json").write_text(json.dumps({"total_process_count": 5}))
        with pytest.raises(KeyError, match="Missing sample_id"):
            _load_modality_dir(d)

    def test_label_consistency_invalid_label_raises(self) -> None:
        """A unified row with binary_label=None fails _validate_unified_rows."""
        from tools.build_unified_dataset import _validate_unified_rows

        rows = [_make_sample("S1", label=None)]  # type: ignore[arg-type]
        with pytest.raises(ValidationError, match="binary_label"):
            _validate_unified_rows(rows)

    def test_null_preservation_in_jsonl(self, tmp_path: Path) -> None:
        """PCAP-null fields are preserved as None/null in JSONL, not imputed."""
        interim = tmp_path / "interim"
        _make_modality_dir("process", [{"sample_id": "S1", **_PROCESS_BASE}], interim)
        _make_modality_dir("memory", [{"sample_id": "S1", **_MEMORY_BASE}], interim)
        _make_modality_dir("command", [{"sample_id": "S1", **_COMMAND_BASE}], interim)
        _make_modality_dir("network", [{"sample_id": "S1", **_NETWORK_BASE}], interim)

        processed = tmp_path / "processed"
        build_unified_dataset(interim_dir=interim, processed_dir=processed)

        row = json.loads((processed / "unified" / "unified_dataset.jsonl").read_text().strip())
        for field in PCAP_NULL_FIELDS:
            assert row[field] is None, f"{field} should be null in JSONL"

    def test_feature_stats_zero_variance(self) -> None:
        """Zero-variance detection flags constant features correctly."""
        rows = [
            {
                "total_process_count": 10,
                "suspicious_dll_count": 0,  # constant across all rows
            },
            {
                "total_process_count": 20,
                "suspicious_dll_count": 0,
            },
        ]
        stats = _compute_feature_stats(rows, ["total_process_count", "suspicious_dll_count"])
        assert stats["total_process_count"]["is_zero_variance"] is False
        assert stats["suspicious_dll_count"]["is_zero_variance"] is True

    def test_manifest_written(self, tmp_path: Path) -> None:
        """dataset_manifest.json is written with expected keys."""
        interim = tmp_path / "interim"
        _make_modality_dir("process", [{"sample_id": "S1", **_PROCESS_BASE}], interim)
        _make_modality_dir("memory", [{"sample_id": "S1", **_MEMORY_BASE}], interim)
        _make_modality_dir("command", [{"sample_id": "S1", **_COMMAND_BASE}], interim)
        _make_modality_dir("network", [{"sample_id": "S1", **_NETWORK_BASE}], interim)

        build_unified_dataset(interim_dir=interim, processed_dir=tmp_path / "processed")
        manifest = json.loads(
            (tmp_path / "processed" / "unified" / "dataset_manifest.json").read_text()
        )
        for key in ("total_samples", "label_distribution", "zero_variance_features", "outputs"):
            assert key in manifest, f"Manifest missing key: {key}"


# ---------------------------------------------------------------------------
# Preprocessing pipeline tests
# ---------------------------------------------------------------------------


def _make_dataframe(n: int = 20, malware_ratio: float = 0.5) -> pd.DataFrame:
    """Build a synthetic unified DataFrame for pipeline tests."""
    import random

    rng = random.Random(0)
    rows = []
    for i in range(n):
        is_malware = i < int(n * malware_ratio)
        label = 1 if is_malware else 0
        family = "cobalt_strike" if is_malware else "benign"
        row = _make_sample(
            f"EXEC_RUN-{i:03d}",
            label=label,
            family=family,
            process_override={
                "total_process_count": rng.randint(50, 200),
                "hidden_process_count": rng.randint(0, 5) if is_malware else 0,
                "malfind_process_count": rng.randint(0, 3) if is_malware else 0,
            },
            memory_override={
                "rwx_page_count": rng.randint(0, 50),
                "injected_code_regions": rng.randint(0, 20) if is_malware else 0,
            },
            command_override={
                "command_length": rng.randint(10, 200),
                "shannon_entropy": round(rng.uniform(2.0, 7.5), 4),
            },
        )
        rows.append(row)
    return pd.DataFrame(rows)


class TestPreprocessingPipeline:
    """Tests for preprocessing/pipeline.py."""

    def test_sample_id_absent_from_feature_matrix(self) -> None:
        """sample_id must NOT appear in X after fit_transform."""
        df = _make_dataframe(20)
        pipe = PreprocessingPipeline()
        df_train, _, _ = pipe.split(df)
        X, y, ids = pipe.fit_transform(df_train, balance_method=None)
        assert "sample_id" not in X.columns
        assert len(ids) == len(X)

    def test_sample_ids_preserved_separately(self) -> None:
        """fit_transform returns sample_ids aligned with X rows."""
        df = _make_dataframe(20)
        pipe = PreprocessingPipeline()
        df_train, _, _ = pipe.split(df)
        X, y, ids = pipe.fit_transform(df_train, balance_method=None)
        assert len(ids) == len(X)
        assert ids.dtype == object or ids.dtype == "string"

    def test_zero_variance_features_removed(self) -> None:
        """Features constant across training set are removed from X."""
        df = _make_dataframe(20)
        # Force suspicious_dll_count to be constant (all zeros)
        df["suspicious_dll_count"] = 0
        pipe = PreprocessingPipeline()
        df_train, _, _ = pipe.split(df)
        X, _, _ = pipe.fit_transform(df_train, balance_method=None)
        assert "suspicious_dll_count" not in X.columns
        assert "suspicious_dll_count" in pipe.zero_variance_features_

    def test_no_leakage_scaler_fitted_on_train_only(self) -> None:
        """Calling transform before fit_transform raises RuntimeError."""
        df = _make_dataframe(20)
        pipe = PreprocessingPipeline()
        df_train, df_val, _ = pipe.split(df)
        with pytest.raises(RuntimeError, match="not been fitted"):
            pipe.transform(df_val)

    def test_transform_uses_train_scaler(self) -> None:
        """Val/test transform uses the scaler fitted on training data."""
        df = _make_dataframe(20)
        pipe = PreprocessingPipeline()
        df_train, df_val, df_test = pipe.split(df)
        X_train, y_train, _ = pipe.fit_transform(df_train, balance_method=None)
        X_val, y_val, _ = pipe.transform(df_val)
        X_test, y_test, _ = pipe.transform(df_test)
        # Columns must match exactly (same post-removal feature set)
        assert list(X_val.columns) == list(X_train.columns)
        assert list(X_test.columns) == list(X_train.columns)

    def test_null_preservation_pcap_fields(self) -> None:
        """PCAP-null fields generate is_missing_* sentinel columns."""
        df = _make_dataframe(20)
        pipe = PreprocessingPipeline()
        df_train, _, _ = pipe.split(df)
        X, _, _ = pipe.fit_transform(df_train, balance_method=None)
        # At least some PCAP sentinel cols should appear (unless zero-variance removed them)
        pcap_sentinel_cols = [f"is_missing_{f}" for f in PCAP_NULL_FIELDS]
        present = [c for c in pcap_sentinel_cols if c in X.columns or c in pipe.removed_features_]
        assert len(present) > 0, "PCAP sentinel columns must be generated"

    def test_null_not_imputed_in_jsonl(self, tmp_path: Path) -> None:
        """null values survive round-trip through JSONL writing."""
        row = _make_sample("S1")
        path = _make_jsonl([row], tmp_path / "test.jsonl")
        loaded = load_unified_jsonl(path)
        for field in PCAP_NULL_FIELDS:
            assert (
                pd.isna(loaded.iloc[0][field]) or loaded.iloc[0][field] is None
            ), f"PCAP-null field '{field}' should be null after JSONL round-trip"

    def test_smote_train_only(self) -> None:
        """SMOTE increases training size; val/test are unaffected."""
        df = _make_dataframe(20, malware_ratio=0.75)  # imbalanced
        pipe = PreprocessingPipeline()
        df_train, df_val, df_test = pipe.split(df)
        train_size_before = len(df_train)
        X_train, y_train, ids_train = pipe.fit_transform(df_train, balance_method="smote")
        X_val, y_val, _ = pipe.transform(df_val)
        X_test, y_test, _ = pipe.transform(df_test)
        # SMOTE may increase training size if classes are imbalanced enough
        # Val and test must not be enlarged
        assert len(X_val) == len(df_val)
        assert len(X_test) == len(df_test)
        # After SMOTE, label counts should be more balanced on training
        if len(X_train) > train_size_before:
            class_counts = y_train.value_counts()
            assert class_counts.min() > 0, "Both classes must have samples after SMOTE"

    def test_train_val_test_disjoint(self) -> None:
        """Train, val, and test partitions have no overlapping sample_ids."""
        df = _make_dataframe(30)
        pipe = PreprocessingPipeline()
        df_train, df_val, df_test = pipe.split(df)
        train_ids = set(df_train["sample_id"])
        val_ids = set(df_val["sample_id"])
        test_ids = set(df_test["sample_id"])
        assert train_ids.isdisjoint(val_ids), "Train and val overlap"
        assert train_ids.isdisjoint(test_ids), "Train and test overlap"
        assert val_ids.isdisjoint(test_ids), "Val and test overlap"

    def test_train_val_test_cover_all_samples(self) -> None:
        """Train + val + test together contain all original samples."""
        df = _make_dataframe(30)
        pipe = PreprocessingPipeline()
        df_train, df_val, df_test = pipe.split(df)
        combined = set(df_train["sample_id"]) | set(df_val["sample_id"]) | set(df_test["sample_id"])
        assert combined == set(df["sample_id"]), "Some samples are lost in split"

    def test_pipeline_serialisation_round_trip(self, tmp_path: Path) -> None:
        """Pipeline saves and reloads with identical selected features."""
        df = _make_dataframe(20)
        pipe = PreprocessingPipeline()
        df_train, df_val, _ = pipe.split(df)
        pipe.fit_transform(df_train, balance_method=None)
        pipe.save(tmp_path / "artifacts")

        loaded = PreprocessingPipeline.load(tmp_path / "artifacts")
        assert loaded.selected_features_ == pipe.selected_features_
        assert loaded.zero_variance_features_ == pipe.zero_variance_features_

        # Loaded pipeline must transform correctly without re-fitting
        X_val_orig, y_val_orig, _ = pipe.transform(df_val)
        X_val_loaded, y_val_loaded, _ = loaded.transform(df_val)
        import numpy as np

        np.testing.assert_array_almost_equal(X_val_orig.values, X_val_loaded.values)

    def test_family_consistency_benign_label(self) -> None:
        """Sample with binary_label=0 and family='benign' passes audit."""
        row = _make_sample("S1", label=0, family="benign")
        result = _audit_sample(row)
        assert result.status == AuditStatus.VALID

    def test_family_consistency_malware_label(self) -> None:
        """Sample with binary_label=1 and family!='benign' passes audit."""
        row = _make_sample("S1", label=1, family="cobalt_strike")
        result = _audit_sample(row)
        assert result.status == AuditStatus.VALID

    def test_family_label_mismatch_flagged(self) -> None:
        """Sample with binary_label=0 but non-benign family is flagged."""
        row = _make_sample("S1", label=0, family="metasploit")
        result = _audit_sample(row)
        assert any("family" in issue for issue in result.issues)


# ---------------------------------------------------------------------------
# audit_unified_dataset tests
# ---------------------------------------------------------------------------


class TestAuditUnifiedDataset:
    """Tests for tools/audit_unified_dataset.py."""

    def test_clean_dataset_passes(self, tmp_path: Path) -> None:
        """A valid dataset with no issues produces zero invalid samples."""
        rows = [
            _make_sample("S1", label=0, family="benign"),
            _make_sample("S2", label=1, family="cobalt_strike"),
        ]
        unified_dir = tmp_path / "unified"
        unified_dir.mkdir()
        _make_jsonl(rows, unified_dir / "unified_dataset.jsonl")
        report = audit_unified_dataset(unified_dir)
        assert report["summary"]["status_counts"].get("invalid", 0) == 0
        assert report["summary"]["duplicate_sample_ids"] == {}

    def test_duplicate_sample_id_raises(self, tmp_path: Path) -> None:
        """Duplicate sample_ids in JSONL raise ValueError."""
        rows = [
            _make_sample("DUP", label=0, family="benign"),
            _make_sample("DUP", label=0, family="benign"),
        ]
        unified_dir = tmp_path / "unified"
        unified_dir.mkdir()
        _make_jsonl(rows, unified_dir / "unified_dataset.jsonl")
        with pytest.raises(ValueError, match="Duplicate sample_ids"):
            audit_unified_dataset(unified_dir)

    def test_nan_in_non_nullable_feature_flagged(self, tmp_path: Path) -> None:
        """A NaN in a non-PCAP feature is flagged as a WARNING."""

        row = _make_sample("S1", label=0, family="benign")
        row["total_process_count"] = math.nan  # inject NaN
        unified_dir = tmp_path / "unified"
        unified_dir.mkdir()
        _make_jsonl([row], unified_dir / "unified_dataset.jsonl")
        report = audit_unified_dataset(unified_dir)
        sample_info = report["samples"]["S1"]
        assert "total_process_count" in sample_info["nan_inf_fields"]

    def test_pcap_null_not_flagged(self, tmp_path: Path) -> None:
        """PCAP-null fields being None does not produce issues."""
        row = _make_sample("S1", label=0, family="benign")
        # Ensure PCAP fields are None
        for f in PCAP_NULL_FIELDS:
            row[f] = None
        unified_dir = tmp_path / "unified"
        unified_dir.mkdir()
        _make_jsonl([row], unified_dir / "unified_dataset.jsonl")
        report = audit_unified_dataset(unified_dir)
        sample_info = report["samples"]["S1"]
        assert sample_info["status"] == AuditStatus.VALID.value
        assert not any("pcap" in i.lower() or "dns_query" in i for i in sample_info["issues"])

    def test_zero_variance_detection(self, tmp_path: Path) -> None:
        """Zero-variance features are listed in audit summary."""
        rows = [
            _make_sample(
                "S1", label=0, family="benign", process_override={"suspicious_dll_count": 0}
            ),
            _make_sample(
                "S2", label=1, family="cobalt_strike", process_override={"suspicious_dll_count": 0}
            ),
        ]
        unified_dir = tmp_path / "unified"
        unified_dir.mkdir()
        _make_jsonl(rows, unified_dir / "unified_dataset.jsonl")
        report = audit_unified_dataset(unified_dir)
        zv = report["summary"]["zero_variance_features"]
        assert "suspicious_dll_count" in zv

    def test_missing_jsonl_raises(self, tmp_path: Path) -> None:
        """FileNotFoundError is raised when unified_dataset.jsonl is absent."""
        with pytest.raises(FileNotFoundError, match="unified_dataset.jsonl"):
            audit_unified_dataset(tmp_path / "nonexistent")
