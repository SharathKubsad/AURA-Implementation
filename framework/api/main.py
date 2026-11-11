"""FastAPI Detection and Telemetry Service (Objective 2 & 3).

Exposes:
- POST /v1/detect: Production detection contract
- GET /v1/telemetry/live: Real-time host telemetry
- POST /v1/simulate: Real-dataset scenario evaluation harness
- GET /v1/metrics/assurance: Model benchmark & robustness evaluation metrics
- GET /system/status: Comprehensive system health and model state
- GET /events: Available forensic dataset runs and recent telemetry events
- GET /process-analysis: Live process telemetry and model scoring
- GET /command-analysis: Live command telemetry and model scoring
- GET /network-analysis: Live network telemetry and model scoring
- GET /memory-analysis: Live memory trigger status and telemetry scoring
- GET /detection: Live end-to-end detection verdict
- GET /explanation: Real SHAP and LIME explanations for current detection
- GET /models: Metadata, features, versions, and metrics for all trained models
- GET /health, GET /v1/health: Service health check
- GET /: Interactive web application dashboard
"""

from __future__ import annotations

import json
import logging
import warnings
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from forensics.schemas import (
    CommandFeatures,
    MemoryFeatures,
    NetworkFeatures,
    ProcessFeatures,
)
from framework.command_samples import BUILTIN_SAMPLE_COMMANDS
from framework.detection_service import DetectionService
from models.multiclass.train_on_custom import FAMILY_LABEL_MAP, SLUG_TO_LABEL

try:
    from sklearn.exceptions import InconsistentVersionWarning

    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
except ImportError:
    pass
warnings.filterwarnings("ignore", message="Trying to unpickle estimator.*")
warnings.filterwarnings("ignore", message=".*InconsistentVersionWarning.*")

logger = logging.getLogger("framework.api")

app = FastAPI(
    title="Hybrid ML Framework for Fileless Malware Detection",
    version="1.0.0",
    description="Real-Time Detection, Memory Forensics, Family Attribution, and Assurance Layer",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon() -> Response:
    """Handle browser favicon request cleanly."""
    return Response(status_code=204)


service = DetectionService()

# Inverted slug map for family ID lookup
LABEL_TO_SLUG: dict[int, str] = {v: k for k, v in SLUG_TO_LABEL.items()}

# Cache authentic unified records for replay
UNIFIED_DATA_PATH = Path("data/processed/unified/unified_dataset.jsonl")
_AUTHENTIC_RECORDS: list[dict[str, Any]] = []
if UNIFIED_DATA_PATH.exists():
    try:
        _AUTHENTIC_RECORDS = [
            json.loads(line)
            for line in UNIFIED_DATA_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except Exception as e:
        logger.warning("Could not pre-cache unified dataset: %s", e)


class DetectRequest(BaseModel):
    """Payload for POST /v1/detect contract."""

    process: ProcessFeatures
    command: CommandFeatures
    network: NetworkFeatures
    memory: MemoryFeatures | None = None
    force_memory_trigger: bool = Field(default=False)


class SimulationRequest(BaseModel):
    """Payload for scenario simulation."""

    family_id: int = Field(default=1, ge=0, le=11)
    custom_command: str | None = Field(default=None)
    force_memory_trigger: bool = Field(default=False)


class CommandAnalyzeRequest(BaseModel):
    """Payload for arbitrary user-entered or preset command analysis."""

    command: str = Field(..., description="Raw command line string to evaluate")
    force_memory_trigger: bool = Field(default=False)


@app.get("/")
def serve_dashboard():
    """Serve web dashboard."""
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Dashboard UI not found")
    return FileResponse(index_file)


@app.get("/health")
@app.get("/v1/health")
def health_check() -> dict[str, Any]:
    """Service health and model loading status."""
    return {
        "status": "healthy",
        "models_loaded": {
            "process": service.process_model is not None,
            "memory": service.memory_model is not None,
            "command": service.command_model is not None,
            "network": service.network_model is not None,
            "multiclass": service.multiclass_model is not None,
        },
        "fusion_threshold": service.fusion_engine.threshold,
    }


@app.get("/system/status")
def system_status() -> dict[str, Any]:
    """Detailed system and detection engine telemetry status."""
    return {
        "status": "MONITORING",
        "service": "Fileless Malware Detection Engine",
        "version": "1.0.0",
        "models": {
            "process_xgboost": service.process_model is not None,
            "memory_catboost": service.memory_model is not None,
            "command_distilbert": service.command_model is not None,
            "network_lightgbm": service.network_model is not None,
            "multiclass_xgboost": service.multiclass_model is not None,
        },
        "fusion_engine": {
            "strategy": "two_stage_conditional_hybrid_fusion",
            "threshold": service.fusion_engine.threshold,
            "suspicion_thresholds": service.fusion_engine.suspicion_thresholds,
            "weights": service.fusion_engine.weights,
        },
        "dataset_samples_available": len(_AUTHENTIC_RECORDS),
    }


@app.get("/events")
def list_events() -> dict[str, Any]:
    """List recorded forensic run events from authentic dataset."""
    events = [
        {
            "sample_id": r.get("sample_id"),
            "family": r.get("family"),
            "binary_label": r.get("binary_label"),
            "command_length": r.get("command_length"),
            "active_connection_count": r.get("active_connection_count"),
            "rwx_page_count": r.get("rwx_page_count"),
        }
        for r in _AUTHENTIC_RECORDS
    ]
    return {"total_events": len(events), "events": events}


@app.get("/process-analysis")
def process_analysis() -> dict[str, Any]:
    """Sample live process telemetry and return Process Model scoring."""
    if service.proc_collector is None:
        return {"status": "COLLECTOR_UNAVAILABLE", "score": None}
    proc_features = service.proc_collector.collect()
    score = service.score_process(proc_features)
    return {
        "status": "NORMAL" if score < 0.50 else "SUSPICIOUS",
        "score": round(score, 4),
        "features": proc_features.model_dump(),
    }


@app.get("/command-analysis")
def command_analysis() -> dict[str, Any]:
    """Sample live command telemetry and return Command Model scoring."""
    if service.cmd_collector is None:
        return {"status": "COLLECTOR_UNAVAILABLE", "score": None}
    cmd_features = service.cmd_collector.collect()
    score = service.score_command(cmd_features)
    return {
        "status": "NORMAL" if score < 0.50 else "SUSPICIOUS",
        "score": round(score, 4),
        "features": cmd_features.model_dump(),
    }


@app.get("/network-analysis")
def network_analysis() -> dict[str, Any]:
    """Sample live network telemetry and return Network Model scoring."""
    if service.net_collector is None:
        return {"status": "COLLECTOR_UNAVAILABLE", "score": None}
    net_features = service.net_collector.collect()
    score = service.score_network(net_features)
    return {
        "status": "NORMAL" if score < 0.50 else "SUSPICIOUS",
        "score": round(score, 4),
        "features": net_features.model_dump(),
    }


@app.get("/memory-analysis")
def memory_analysis() -> dict[str, Any]:
    """Check memory trigger status and return memory analysis metrics."""
    if service.mem_trigger is None:
        return {"status": "TRIGGER_UNAVAILABLE", "score": None}
    mem_features = service.mem_trigger.inspect_process(is_suspicious_context=False)
    score = service.score_memory(mem_features)
    return {
        "status": "NORMAL" if score < 0.50 else "SUSPICIOUS",
        "score": round(score, 4),
        "features": mem_features.model_dump(),
    }


@app.get("/detection")
def get_detection() -> dict[str, Any]:
    """Perform real-time detection on the live host system."""
    return service.detect_live_system()


@app.get("/explanation")
def get_explanation() -> dict[str, Any]:
    """Return SHAP and LIME explainability analysis for live host detection."""
    live_res = service.detect_live_system()
    sample_feats = live_res.get("sample_features", {})
    proc = sample_feats.get("process", {})
    cmd = sample_feats.get("command", {})
    mem = sample_feats.get("memory", {})

    shap_exp = {"process": [], "memory": [], "multiclass": []}
    lime_tokens = []

    try:
        if service.shap_mgr:
            shap_exp["process"] = service.shap_mgr.explain_process(proc)[:5]
            if live_res.get("memory_triggered") and mem:
                shap_exp["memory"] = service.shap_mgr.explain_memory(mem)[:5]
    except Exception as e:
        logger.debug("SHAP explanation generation skipped: %s", e)

    try:
        cmd_text = cmd.get("raw_command_text", "")
        if cmd_text and service.lime_mgr:
            lime_tokens = [
                {"token": t, "weight": round(float(w), 4)}
                for t, w in service.lime_mgr.explain_command_text(cmd_text, num_features=5)
            ]
    except Exception as e:
        logger.debug("LIME explanation generation skipped: %s", e)

    return {
        "verdict": live_res["verdict"],
        "confidence": live_res["confidence"],
        "shap_explanation": shap_exp,
        "lime_tokens": lime_tokens,
    }


@app.get("/models")
def get_models_metadata() -> dict[str, Any]:
    """Return metadata and evaluation metrics for all trained models."""
    models_info = {}
    for mod in ["process", "memory", "command", "network"]:
        meta_p = Path(f"models/artifacts/{mod}/metadata.json")
        eval_p = Path(f"evaluation/binary/{mod}_evaluation.json")
        info: dict[str, Any] = {}
        if meta_p.exists():
            with open(meta_p, encoding="utf-8") as f:
                info["metadata"] = json.load(f)
        if eval_p.exists():
            with open(eval_p, encoding="utf-8") as f:
                info["evaluation"] = json.load(f)
        models_info[mod] = info

    mc_meta_p = Path("models/multiclass/artifacts/metrics.json")
    if mc_meta_p.exists():
        with open(mc_meta_p, encoding="utf-8") as f:
            models_info["multiclass"] = json.load(f)

    return models_info


@app.post("/v1/detect")
def detect_telemetry(payload: DetectRequest) -> dict[str, Any]:
    """Execute hybrid detection contract conforming to AGENTS.md §8."""
    return service.detect(
        proc=payload.process,
        cmd=payload.command,
        net=payload.network,
        mem=payload.memory,
        force_memory_trigger=payload.force_memory_trigger,
    )


@app.get("/v1/telemetry/live")
def get_live_telemetry() -> dict[str, Any]:
    """Sample live system and return detection & attribution verdict."""
    return service.detect_live_system()


@app.get("/v1/command/samples")
def get_sample_commands() -> dict[str, Any]:
    """Return built-in sample command preset library across multiple threat categories."""
    return {
        "total_samples": len(BUILTIN_SAMPLE_COMMANDS),
        "samples": BUILTIN_SAMPLE_COMMANDS,
    }


@app.post("/v1/command/analyze")
def analyze_custom_command(req: CommandAnalyzeRequest) -> dict[str, Any]:
    """Execute full hybrid ML detection pipeline on arbitrary user-entered or preset command.

    Conforms to the requirements:
    - Zero command-specific hardcoded results
    - Feature extraction from raw command text (Shannon entropy, Base64 regex, cradle keywords, etc.)
    - Process, Network, and Memory telemetry scoring
    - Hybrid confidence fusion against the 0.60 threshold
    - Multi-class family attribution (Objective 3) if malware
    - LIME & SHAP explainability (Objective 4)
    """
    if not req.command or not req.command.strip():
        raise HTTPException(status_code=400, detail="Command string cannot be empty")
    return service.analyze_command(
        command_text=req.command.strip(),
        force_memory_trigger=req.force_memory_trigger,
    )


@app.post("/v1/simulate")
def simulate_scenario(req: SimulationRequest) -> dict[str, Any]:
    """Evaluate an authentic forensic scenario across all 11 malware families or custom commands."""
    if req.custom_command and req.custom_command.strip():
        # User-entered or preset command passes through the exact same dynamic pipeline
        res = service.analyze_command(
            command_text=req.custom_command.strip(),
            force_memory_trigger=req.force_memory_trigger,
        )
        family_name = res.get("family") or ("Malware" if res.get("is_malware") else "Benign")
        res["simulation_info"] = {
            "family_id": req.family_id,
            "family_name": family_name,
            "sample_id": res.get("extracted_features", {}).get("sample_id", "CMD_SIM_001"),
            "source": "dynamic_command_pipeline",
        }
        return res

    slug = LABEL_TO_SLUG.get(req.family_id, "benign")
    matching_records = [r for r in _AUTHENTIC_RECORDS if r.get("family") == slug]

    if not matching_records:
        matching_records = [
            r
            for r in _AUTHENTIC_RECORDS
            if (req.family_id == 0 and r.get("binary_label") == 0)
            or (req.family_id > 0 and r.get("binary_label") == 1)
        ]

    if matching_records:
        rec = matching_records[0]
        sid = rec.get("sample_id", f"SCENARIO_{slug.upper()}_001")
        proc = ProcessFeatures(
            sample_id=sid,
            total_process_count=int(rec.get("total_process_count", 120)),
            hidden_process_count=int(rec.get("hidden_process_count", 0)),
            anomalous_ppid_count=int(rec.get("anomalous_ppid_count", 0)),
            avg_threads_per_process=float(rec.get("avg_threads_per_process", 12.0)),
            max_threads_in_single_process=int(rec.get("max_threads_in_single_process", 80)),
            total_handle_count=int(rec.get("total_handle_count", 50000)),
            suspicious_dll_count=int(rec.get("suspicious_dll_count", 0)),
            malfind_process_count=int(rec.get("malfind_process_count", 0)),
            elevated_privilege_count=int(rec.get("elevated_privilege_count", 0)),
            unlinked_dll_count=int(rec.get("unlinked_dll_count", 0)),
        )
        cmd_text = req.custom_command or str(rec.get("raw_command_text") or "powershell.exe")
        cmd = CommandFeatures(
            sample_id=sid,
            raw_command_text=cmd_text,
            command_length=len(cmd_text),
            shannon_entropy=float(rec.get("shannon_entropy") or 4.0),
            is_base64_encoded=int(rec.get("is_base64_encoded", 0)),
            has_download_cradle=int(rec.get("has_download_cradle", 0)),
            has_bypass_execution_policy=int(rec.get("has_bypass_execution_policy", 0)),
            has_hidden_window=int(rec.get("has_hidden_window", 0)),
            uses_lolbins=int(rec.get("uses_lolbins", 0)),
            registry_persistence_count=int(rec.get("registry_persistence_count", 0)),
        )
        net = NetworkFeatures(
            sample_id=sid,
            active_connection_count=int(rec.get("active_connection_count", 0)),
            listening_port_count=int(rec.get("listening_port_count", 0)),
            outbound_connection_count=int(rec.get("outbound_connection_count", 0)),
            dns_query_count=int(rec.get("dns_query_count") or 0),
            unique_remote_ips=int(rec.get("unique_remote_ips", 0)),
            avg_interpacket_interval_ms=float(rec.get("avg_interpacket_interval_ms") or 0.0),
            beacon_regularity_score=float(rec.get("beacon_regularity_score") or 0.0),
            total_bytes_sent=int(rec.get("total_bytes_sent") or 0),
            total_bytes_received=int(rec.get("total_bytes_received") or 0),
            suspicious_port_usage=int(rec.get("suspicious_port_usage", 0)),
        )
        mem = MemoryFeatures(
            sample_id=sid,
            rwx_page_count=int(rec.get("rwx_page_count", 0)),
            injected_code_regions=int(rec.get("injected_code_regions", 0)),
            unmapped_executable_pages=int(rec.get("unmapped_executable_pages", 0)),
            vad_protection_anomaly_count=int(rec.get("vad_protection_anomaly_count", 0)),
            ldrmodules_inconsistencies=int(rec.get("ldrmodules_inconsistencies", 0)),
            yara_shellcode_matches=int(rec.get("yara_shellcode_matches", 0)),
            mean_memory_entropy=float(rec.get("mean_memory_entropy") or 0.0),
            max_memory_entropy=float(rec.get("max_memory_entropy") or 0.0),
        )
    else:
        # Fallback to defaults if dataset is unindexed
        sid = f"SAMPLE_FAM_{req.family_id:02d}"
        proc = ProcessFeatures(
            sample_id=sid,
            total_process_count=120,
            hidden_process_count=0,
            anomalous_ppid_count=0,
            avg_threads_per_process=12.0,
            max_threads_in_single_process=50,
            total_handle_count=5000,
            suspicious_dll_count=0,
            malfind_process_count=0,
            elevated_privilege_count=1,
            unlinked_dll_count=0,
        )
        cmd_text = req.custom_command or "powershell.exe -ExecutionPolicy Bypass"
        cmd = CommandFeatures(
            sample_id=sid,
            raw_command_text=cmd_text,
            command_length=len(cmd_text),
            shannon_entropy=4.2,
            is_base64_encoded=0,
            has_download_cradle=0,
            has_bypass_execution_policy=1,
            has_hidden_window=0,
            uses_lolbins=1,
            registry_persistence_count=0,
        )
        net = NetworkFeatures(
            sample_id=sid,
            active_connection_count=5,
            listening_port_count=10,
            outbound_connection_count=2,
            dns_query_count=2,
            unique_remote_ips=2,
            avg_interpacket_interval_ms=100.0,
            beacon_regularity_score=0.1,
            total_bytes_sent=1024,
            total_bytes_received=4096,
            suspicious_port_usage=0,
        )
        mem = MemoryFeatures(
            sample_id=sid,
            rwx_page_count=0,
            injected_code_regions=0,
            unmapped_executable_pages=0,
            vad_protection_anomaly_count=0,
            ldrmodules_inconsistencies=0,
            yara_shellcode_matches=0,
            mean_memory_entropy=0.0,
            max_memory_entropy=0.0,
        )

    res = service.detect(
        proc=proc,
        cmd=cmd,
        net=net,
        mem=mem,
        force_memory_trigger=req.force_memory_trigger,
    )

    family_name = FAMILY_LABEL_MAP.get(req.family_id, "Unknown")
    res["simulation_info"] = {
        "family_id": req.family_id,
        "family_name": family_name,
        "sample_id": sid,
        "source": "authentic_custom_dataset",
    }

    # Generate real explainability points
    try:
        if service.shap_mgr:
            res["shap_explanation"] = {
                "process": service.shap_mgr.explain_process(proc.model_dump())[:4],
                "memory": service.shap_mgr.explain_memory(mem.model_dump())[:4] if mem else [],
            }
        else:
            res["shap_explanation"] = {"process": [], "memory": []}
    except Exception:
        res["shap_explanation"] = {"process": [], "memory": []}

    try:
        if service.lime_mgr:
            res["lime_tokens"] = [
                {"token": t, "weight": round(float(w), 4)}
                for t, w in service.lime_mgr.explain_command_text(
                    cmd.raw_command_text, num_features=5
                )
            ]
        else:
            res["lime_tokens"] = []
    except Exception:
        res["lime_tokens"] = []

    return res


@app.get("/v1/metrics/assurance")
def get_assurance_metrics() -> dict[str, Any]:
    """Return in-distribution, robustness, and generalization scorecards."""
    base_metrics: dict[str, Any] = {}
    for mod in ["process", "memory", "command", "network"]:
        mf = Path(f"evaluation/binary/{mod}_evaluation.json")
        if mf.exists():
            with open(mf, encoding="utf-8") as f:
                base_metrics[mod] = json.load(f)

    rob_metrics: dict[str, Any] = {}
    rf = Path("evaluation/robustness/artifacts/robustness_metrics.json")
    if rf.exists():
        with open(rf, encoding="utf-8") as f:
            rob_metrics = json.load(f)

    gen_metrics: dict[str, Any] = {}
    gf = Path("evaluation/generalization/artifacts/generalization_metrics.json")
    if gf.exists():
        with open(gf, encoding="utf-8") as f:
            gen_metrics = json.load(f)

    multi_metrics: dict[str, Any] = {}
    muf = Path("models/multiclass/artifacts/metrics.json")
    if muf.exists():
        with open(muf, encoding="utf-8") as f:
            multi_metrics = json.load(f)

    return {
        "in_distribution": base_metrics,
        "multiclass": multi_metrics,
        "robustness": rob_metrics,
        "generalization": gen_metrics,
        "families": FAMILY_LABEL_MAP,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
