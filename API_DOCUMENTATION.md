# REST API Documentation & Integration Specification

**Base URL:** `http://localhost:8000`  
**Protocol:** HTTP/1.1 REST  
**Authentication:** Optional Bearer Token / Open for Local EDR Telemetry  

---

## 1. Summary of API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Real-time SOC Web Dashboard & UI Interface |
| `GET` | `/health` | System health check and model loading status |
| `GET` | `/system/status` | Real-time monitoring status and loaded engine versions |
| `GET` | `/events` | List recorded forensic execution run events |
| `GET` | `/process-analysis` | Sample live process telemetry and score with Process XGBoost |
| `GET` | `/command-analysis` | Sample live command telemetry and score with DistilBERT |
| `GET` | `/network-analysis` | Sample live network telemetry and score with LightGBM |
| `GET` | `/memory-analysis` | Check memory trigger status and score with CatBoost |
| `GET` | `/detection` | Perform real-time live host detection with tiered fusion |
| `GET` | `/explanation` | Return SHAP feature attributions and LIME token weights |
| `GET` | `/models` | Retrieve metadata and hyperparameters for all 5 trained models |
| `POST` | `/v1/simulate` | Replay an authentic forensic run (e.g. Cobalt Strike) through the pipeline |
| `GET` | `/v1/metrics/assurance` | Retrieve in-distribution (95.56% fusion), robustness, and generalization benchmarks |

---

## 2. Endpoint Details & Examples

### 2.1 Health Check
**Request:**
```bash
curl -X GET http://localhost:8000/health
```
**Response (200 OK):**
```json
{
  "status": "healthy",
  "models_loaded": {
    "process": true,
    "memory": true,
    "command": true,
    "network": true,
    "multiclass": true
  },
  "fusion_threshold": 0.6
}
```

---

### 2.2 Live System Detection
**Request:**
```bash
curl -X GET http://localhost:8000/detection
```
**Response (200 OK):**
```json
{
  "verdict": "benign",
  "confidence": 0.4135,
  "behavioral_score": 0.4135,
  "memory_score": null,
  "memory_triggered": false,
  "family": null,
  "family_confidence": null,
  "per_model": {
    "process": 0.1328,
    "command": 0.7181,
    "network": 0.7097,
    "memory": null
  },
  "timestamp": "2026-09-27T13:10:00Z"
}
```

---

### 2.3 Replay Simulation with Attribution & XAI
**Request:**
```bash
curl -X POST http://localhost:8000/v1/simulate \
  -H "Content-Type: application/json" \
  -d '{"family_id": 6}'
```
**Response (200 OK):**
```json
{
  "verdict": "malware",
  "confidence": 0.8307,
  "behavioral_score": 0.7661,
  "memory_score": 0.8954,
  "memory_triggered": true,
  "family": "Cobalt Strike Beacon",
  "family_confidence": 0.8542,
  "per_model": {
    "process": 0.8841,
    "command": 0.7181,
    "network": 0.7097,
    "memory": 0.8954
  },
  "shap_explanation": {
    "process": [
      {"feature": "has_rwx_flag", "shap_value": 0.428, "feature_value": 1.0},
      {"feature": "is_powershell", "shap_value": 0.284, "feature_value": 1.0}
    ],
    "memory": [
      {"feature": "rwx_page_count", "shap_value": 0.382, "feature_value": 8.0},
      {"feature": "unbacked_rx_page_count", "shap_value": 0.265, "feature_value": 4.0}
    ]
  },
  "lime_tokens": [
    {"token": "-enc", "weight": 0.382},
    {"token": "downloadstring", "weight": 0.291},
    {"token": "iex", "weight": 0.245}
  ]
}
```

---

### 2.4 Assurance & Research Benchmarks
**Request:**
```bash
curl -X GET http://localhost:8000/v1/metrics/assurance
```
**Response (200 OK):**
```json
{
  "in_distribution": {
    "global_fusion": {
      "samples": 45,
      "accuracy": 0.9556,
      "precision": 0.9412,
      "recall": 1.0,
      "f1": 0.9697,
      "roc_auc": 0.9928
    },
    "process": {"accuracy": 0.8571, "precision": 0.8333, "recall": 1.0, "f1": 0.9091, "roc_auc": 0.9},
    "memory": {"accuracy": 0.8571, "precision": 0.8333, "recall": 1.0, "f1": 0.9091, "roc_auc": 1.0},
    "command": {"accuracy": 0.7143, "precision": 0.7143, "recall": 1.0, "f1": 0.8333},
    "network": {"accuracy": 0.7143, "precision": 0.7143, "recall": 1.0, "f1": 0.8333, "roc_auc": 0.5}
  },
  "multiclass": {
    "samples": 32,
    "families_count": 5,
    "cv_accuracy": 0.7812,
    "granular_11_family_loo_accuracy": 0.0938
  },
  "robustness": {
    "samples": 50,
    "accuracy": 0.88,
    "precision": 0.8065,
    "recall": 1.0,
    "f1": 0.8929,
    "roc_auc": 0.992
  },
  "generalization": {
    "samples": 50,
    "accuracy": 0.84,
    "precision": 0.7576,
    "recall": 1.0,
    "f1": 0.8621,
    "roc_auc": 0.9984
  }
}
```
