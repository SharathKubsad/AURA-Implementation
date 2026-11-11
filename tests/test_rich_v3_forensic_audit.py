"""Tests for richer forensic feature audit, candidate datasets, and provenance integrity."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import numpy as np
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = REPO_ROOT / "data" / "processed"
DOCS_DIR = REPO_ROOT / "docs"
DATASET_DIR = REPO_ROOT / "Dataset"


def test_metadata_and_run_counts():
    """Verify exactly 45 runs, exactly 12 benign and 33 malware, and RUN-001 label=1."""
    meta_files = sorted(DATASET_DIR.glob("**/metadata/*.json"))
    assert len(meta_files) == 45, f"Expected 45 metadata files, found {len(meta_files)}"

    labels = []
    sample_ids = []
    run001_found = False

    for mf in meta_files:
        with open(mf, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        labels.append(int(data["label"]))
        sample_ids.append(data["sample_id"])
        if mf.stem == "RUN-001":
            run001_found = True
            assert int(data["label"]) == 1
            assert data["family"] == "powershell_fileless"

    assert run001_found, "RUN-001 must exist in metadata"
    counts = Counter(labels)
    assert counts[0] == 12, f"Expected 12 benign runs, got {counts[0]}"
    assert counts[1] == 33, f"Expected 33 malware runs, got {counts[1]}"
    assert len(sample_ids) == len(set(sample_ids)), "Duplicate sample_ids found in metadata"


def test_candidate_datasets_alignment():
    """Verify all 4 candidate datasets have exactly 45 rows with identical sample_ids."""
    modalities = ["process", "command", "network", "memory"]
    datasets = {}

    for mod in modalities:
        fpath = PROCESSED_DIR / f"{mod}_rich_v3_candidate.jsonl"
        assert fpath.exists(), f"Candidate dataset missing: {fpath}"
        rows = [json.loads(line) for line in fpath.read_text(encoding="utf-8").splitlines()]
        assert len(rows) == 45, f"Expected 45 rows in {mod}_rich_v3_candidate, got {len(rows)}"
        datasets[mod] = rows

    base_sids = [r["sample_id"] for r in datasets["process"]]
    assert len(base_sids) == 45
    assert len(set(base_sids)) == 45, "Duplicate sample IDs detected"

    for mod in modalities:
        sids = [r["sample_id"] for r in datasets[mod]]
        assert sids == base_sids, f"Sample ID alignment failed for {mod}"
        labels = [r["label"] for r in datasets[mod]]
        counts = Counter(labels)
        assert counts[0] == 12
        assert counts[1] == 33


def test_no_constant_retained_features():
    """Verify no retained candidate feature has zero variance across the 45 runs."""
    modalities = ["process", "command", "network", "memory"]

    for mod in modalities:
        fpath = PROCESSED_DIR / f"{mod}_rich_v3_candidate.jsonl"
        rows = [json.loads(line) for line in fpath.read_text(encoding="utf-8").splitlines()]

        sample_features = rows[0]["features"]
        for feat_name in sample_features:
            if feat_name == "raw_command_text":
                continue
            vals = [r["features"][feat_name] for r in rows]
            assert not any(v is None or (isinstance(v, float) and np.isnan(v)) for v in vals), (
                f"Null or NaN detected in {mod}.{feat_name}"
            )
            uniq = len(set(vals))
            assert uniq > 1, f"Retained feature {mod}.{feat_name} is constant across all 45 runs!"


def test_corrupted_threads_are_not_silently_accepted():
    """Verify corrupted thread values in RUN-002, RUN-003, RUN-1002 are not in process features."""
    fpath = PROCESSED_DIR / "process_rich_v3_candidate.jsonl"
    rows = [json.loads(line) for line in fpath.read_text(encoding="utf-8").splitlines()]

    # Verify pslist thread averages (which exceeded 10^7 due to carved dead pool memory) are excluded
    for r in rows:
        feats = r["features"]
        assert "avg_threads_per_process" not in feats, "Corrupted feature avg_threads_per_process must be rejected"
        assert "thread_to_process_ratio" not in feats, "Derived thread_to_process_ratio must be rejected"
        for k, v in feats.items():
            if isinstance(v, (int, float)):
                assert v < 100_000_000, f"Unreasonably large corrupted value detected: {k}={v} in {r['run_id']}"


def test_provenance_json_integrity():
    """Verify docs/richer_feature_provenance.json exists, maps all features, and has valid metadata."""
    prov_file = DOCS_DIR / "richer_feature_provenance.json"
    assert prov_file.exists(), "richer_feature_provenance.json must exist"

    with open(prov_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["metadata"]["total_runs"] == 45
    assert data["metadata"]["benign_runs"] == 12
    assert data["metadata"]["malware_runs"] == 33
    assert "modalities" in data

    for mod in ["process", "command", "network", "memory"]:
        assert mod in data["modalities"]
        for feat, info in data["modalities"][mod].items():
            assert "source_plugin" in info
            assert "source_fields" in info
            assert "extraction_method" in info
            assert "aggregation_method" in info
            assert info["quality_status"] == "RETAINED"
            assert "rationale" in info
