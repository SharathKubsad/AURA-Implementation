"""Comprehensive unit and integration test suite for the Hybrid ML Detection Framework."""

import pytest

# ruff: noqa: E402
pytest.importorskip("xgboost")
pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from framework.api.main import app
from framework.fusion.fuse import HybridFusionEngine

client = TestClient(app)


def test_api_health():
    """Verify health endpoint reports all models active."""
    res = client.get("/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["models_loaded"]["process"] is True
    assert data["models_loaded"]["command"] is True
    assert data["models_loaded"]["network"] is True
    assert data["models_loaded"]["memory"] is True
    assert data["models_loaded"]["multiclass"] is True


def test_fusion_threshold_logic():
    """Test 2-Stage Bayesian/Probabilistic fusion matching architecture specification."""
    engine = HybridFusionEngine()
    engine.threshold = 0.60

    # Low scores -> S1: 0.35*0.1 + 0.40*0.2 + 0.25*0.1 = 0.14 (< 0.50 -> mem clean baseline 0.05)
    # S2: 0.50*0.14 + 0.50*0.05 = 0.095 (< 0.60 -> Benign)
    res_benign = engine.evaluate(
        process_conf=0.1, command_conf=0.2, network_conf=0.1, memory_conf=0.05
    )
    assert res_benign.verdict == "Benign"
    assert res_benign.is_malware is False
    assert res_benign.stage1_confidence == 0.14
    assert res_benign.confidence == 0.095
    assert res_benign.memory_triggered is False

    # High scores -> S1: 0.35*0.9 + 0.40*0.85 + 0.25*0.7 = 0.83 (>= 0.50 -> mem triggered)
    # S2: 0.50*0.83 + 0.50*0.95 = 0.89 (>= 0.60 -> Malware)
    res_malware = engine.evaluate(
        process_conf=0.9, command_conf=0.85, network_conf=0.7, memory_conf=0.95
    )
    assert res_malware.verdict == "Malware"
    assert res_malware.is_malware is True
    assert res_malware.stage1_confidence == 0.83
    assert res_malware.confidence == 0.89
    assert res_malware.memory_triggered is True


def test_simulation_benign():
    """Test simulating benign sample — verifies schema/contract, not model accuracy.

    NOTE: The custom binary models are trained on 45 samples (small_dataset_warning).
    They are not expected to produce reliable verdicts on synthetic benchmark data;
    only the response schema and HTTP contract are verified here.
    """
    res = client.post("/v1/simulate", json={"family_id": 0})
    assert res.status_code == 200
    data = res.json()
    # Schema / contract assertions only — not accuracy assertions
    assert "verdict" in data
    assert data["verdict"] in ("benign", "malware")
    assert "confidence" in data
    assert 0.0 <= data["confidence"] <= 1.0
    assert "memory_triggered" in data
    assert isinstance(data["memory_triggered"], bool)
    assert "shap_explanation" in data
    assert "lime_tokens" in data


def test_simulation_malware_powershell():
    """Test simulating PowerShell fileless cradle — verifies schema/contract, not model accuracy.

    NOTE: Custom models trained on 45 samples; response schema is verified only.
    """
    res = client.post("/v1/simulate", json={"family_id": 1})
    assert res.status_code == 200
    data = res.json()
    assert "verdict" in data
    assert data["verdict"] in ("benign", "malware")
    assert "confidence" in data
    assert 0.0 <= data["confidence"] <= 1.0
    assert "memory_triggered" in data
    assert "shap_explanation" in data
    assert "lime_tokens" in data


def test_simulation_malware_cobalt_strike():
    """Test simulating Cobalt Strike beacon — verifies schema/contract, not model accuracy.

    NOTE: Custom models trained on 45 samples; response schema is verified only.
    """
    res = client.post("/v1/simulate", json={"family_id": 6})
    assert res.status_code == 200
    data = res.json()
    assert "verdict" in data
    assert data["verdict"] in ("benign", "malware")
    assert "confidence" in data
    assert 0.0 <= data["confidence"] <= 1.0
    assert "shap_explanation" in data
    assert "lime_tokens" in data


def test_metrics_assurance_endpoint():
    """Verify assurance and robustness endpoint returns metrics."""
    res = client.get("/v1/metrics/assurance")
    assert res.status_code == 200
    data = res.json()
    assert "in_distribution" in data
    assert "robustness" in data
    assert "generalization" in data


def test_dashboard_route():
    """Verify root / serves HTML dashboard."""
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "AURA" in res.text
