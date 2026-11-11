# Research & System Reproducibility Guide

## 1. Prerequisites and Environment Setup

This framework runs on Windows, Linux, and macOS with Python 3.11+.

### Option A: Automated One-Click Setup (Windows)
Simply run:
```powershell
.\run_system.bat
```
This automatically configures the environment, installs dependencies, loads models, starts the FastAPI daemon at port 8000, and opens the web dashboard in your browser.

### Option B: Manual Environment Setup
```bash
# Step 1: Create and Activate Virtual Environment
python -m venv .venv
# On Windows PowerShell:
.venv\Scripts\Activate.ps1
# On Linux / macOS:
source .venv/bin/activate

# Step 2: Install Core Dependencies
pip install -U pip setuptools wheel
pip install torch torchvision --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements.txt
```

---

## 2. Dataset Reconstruction & Standardization

To compile the 45 authentic custom VM sandbox executions into the unified benchmark dataset:

```bash
python tools/build_unified_dataset.py
```
*Output Artifacts:* `data/processed/unified/unified_dataset.jsonl` and `data/dataset_metadata.json`.

---

## 3. Training Commands for All Models

Execute the following commands in sequence to train and serialize all 5 models:

### 3.1 Train Process Model (XGBoost)
```bash
python -m models.process.train --data-path data/processed/unified/unified_dataset.jsonl --output-dir models/artifacts/process
```

### 3.2 Train Memory Model (CatBoost)
```bash
python -m models.memory.train --data-path data/processed/unified/unified_dataset.jsonl --output-dir models/artifacts/memory
```

### 3.3 Train Command Model (DistilBERT)
```bash
python -m models.command.train --data-path data/processed/unified/unified_dataset.jsonl --output-dir models/artifacts/command --epochs 3 --batch-size 4 --lr 5e-5
```

### 3.4 Train Network Model (LightGBM)
```bash
python -m models.network.train --data-path data/processed/unified/unified_dataset.jsonl --output-dir models/artifacts/network
```

### 3.5 Train Malware Family Classifier (Multi-Class XGBoost)
```bash
# Train on 5 canonical behavioral threat families:
python -m models.multiclass.train_on_custom --data-path data/processed/unified/unified_dataset.jsonl --output-dir models/multiclass/artifacts
```

---

## 4. Evaluation, Assurance & XAI Generation

### 4.1 Generate SHAP & LIME Interpretability Artifacts
```bash
python evaluation/xai/shap_report.py
python evaluation/xai/lime_report.py
```

### 4.2 Run Robustness & Generalization Stress-Testing
```bash
python evaluation/robustness/evaluate.py
python evaluation/generalization/evaluate.py
```

---

## 5. Automated Test Suite Execution

Run the complete Pytest suite to verify end-to-end schemas, model inference, fusion engine, and API clients:

```bash
pytest -v tests/
```

---

## 6. Launching the Real-Time Detection Backend & Web Dashboard

Start the FastAPI live detection daemon on port 8000:

```bash
uvicorn framework.api.main:app --host 0.0.0.0 --port 8000 --reload
```

- **Web Dashboard:** `http://localhost:8000/`
- **Interactive Swagger UI:** `http://localhost:8000/docs`
- **Assurance Metrics Endpoint:** `http://localhost:8000/v1/metrics/assurance`
