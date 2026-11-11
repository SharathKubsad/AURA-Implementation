"""Hybrid Confidence Fusion Engine (Objective 2).

Implements the multi-stage hybrid detection logic matching architecture specifications:
1. Receives individual live telemetry confidences (Process, Command, Network).
2. Computes Stage 1 Behavioral Fusion:
   S_behavioral = w_proc * P(Malware|Proc) + w_cmd * P(Malware|Cmd) + w_net * P(Malware|Net)
   (Default weights: Process = 0.35, Command = 0.40, Network = 0.25)
3. Evaluates Memory Forensics Trigger Gate:
   Triggers volatile memory acquisition if S_behavioral >= 0.50
   (or if any individual live modality >= per-model suspicion threshold, default 0.50).
4. Computes Stage 2 Global Detection Fusion:
   S_final = alpha * S_behavioral + beta * P(Malware|Memory)
   (Default weights: alpha = 0.50, beta = 0.50; baseline clean memory = 0.05 if not triggered).
5. Compares against the final fusion decision threshold (0.60) for Benign vs Malware verdict.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

logger = logging.getLogger("framework.fusion")


@dataclass
class FusionResult:
    """Decision output of the hybrid fusion pipeline."""

    verdict: str  # "Benign" or "Malware"
    confidence: float  # Fused Stage 2 global confidence [0.0 - 1.0]
    is_malware: bool
    memory_triggered: bool
    per_model: dict[str, float]
    threshold: float
    suspicion_thresholds: dict[str, float]
    stage1_confidence: float = 0.0
    stage1_weights: dict[str, float] = field(default_factory=dict)
    stage2_weights: dict[str, float] = field(default_factory=dict)


class HybridFusionEngine:
    """Config-driven confidence fusion engine implementing 2-Stage Hierarchical Fusion."""

    def __init__(self, config_path: str | Path = "configs/thresholds.yaml") -> None:
        self.config_path = Path(config_path)
        self.threshold: float = 0.60
        self.behavioral_suspicion_threshold: float = 0.50
        self.suspicion_thresholds: dict[str, float] = {
            "process": 0.50,
            "command": 0.50,
            "network": 0.50,
        }
        self.stage1_weights: dict[str, float] = {
            "process": 0.35,
            "command": 0.40,
            "network": 0.25,
        }
        self.stage2_weights: dict[str, float] = {
            "behavioral": 0.50,
            "memory": 0.50,
        }
        # Flat weights property for backward compatibility
        self.weights: dict[str, float] = {
            "process": 0.35,
            "command": 0.40,
            "network": 0.25,
            "memory": 0.50,
        }
        self.load_config()

    def load_config(self) -> None:
        """Load decision and suspicion thresholds and fusion weights from YAML."""
        if not self.config_path.exists():
            logger.warning("Thresholds config %s not found, using defaults.", self.config_path)
            return

        try:
            with open(self.config_path, encoding="utf-8") as f:
                cfg = yaml.safe_load(f)

            fusion_cfg = cfg.get("fusion", {})
            self.threshold = float(fusion_cfg.get("threshold", 0.60))
            self.behavioral_suspicion_threshold = float(
                fusion_cfg.get("behavioral_suspicion_threshold", 0.50)
            )

            susp_cfg = fusion_cfg.get("suspicion_thresholds", {})
            for mod in ["process", "command", "network"]:
                if mod in susp_cfg:
                    self.suspicion_thresholds[mod] = float(susp_cfg[mod])

            # Load Stage 1 weights
            s1_cfg = fusion_cfg.get("stage1_weights", {})
            for mod in ["process", "command", "network"]:
                if mod in s1_cfg:
                    self.stage1_weights[mod] = float(s1_cfg[mod])
            s1_total = sum(self.stage1_weights.values())
            if s1_total > 0 and abs(s1_total - 1.0) > 1e-4:
                self.stage1_weights = {k: v / s1_total for k, v in self.stage1_weights.items()}

            # Load Stage 2 weights
            s2_cfg = fusion_cfg.get("stage2_weights", {})
            for comp in ["behavioral", "memory"]:
                if comp in s2_cfg:
                    self.stage2_weights[comp] = float(s2_cfg[comp])
            s2_total = sum(self.stage2_weights.values())
            if s2_total > 0 and abs(s2_total - 1.0) > 1e-4:
                self.stage2_weights = {k: v / s2_total for k, v in self.stage2_weights.items()}

            # Synchronize models section if present
            models_cfg = cfg.get("models", {})
            for mod in ["process", "command", "network", "memory"]:
                if mod in models_cfg and "weight" in models_cfg[mod]:
                    self.weights[mod] = float(models_cfg[mod]["weight"])

            logger.info(
                "Loaded fusion configuration: threshold=%.2f, S1_weights=%s, S2_weights=%s",
                self.threshold,
                self.stage1_weights,
                self.stage2_weights,
            )
        except Exception as err:
            logger.error("Error reading thresholds config: %s", err)

    def is_suspicious(self, process_conf: float, command_conf: float, network_conf: float) -> bool:
        """Evaluate whether behavioral telemetry exceeds the suspicion gate for memory acquisition."""
        s1_score = (
            self.stage1_weights.get("process", 0.35) * process_conf
            + self.stage1_weights.get("command", 0.40) * command_conf
            + self.stage1_weights.get("network", 0.25) * network_conf
        )
        return (
            s1_score >= self.behavioral_suspicion_threshold
            or process_conf >= self.suspicion_thresholds.get("process", 0.50)
            or command_conf >= self.suspicion_thresholds.get("command", 0.50)
            or network_conf >= self.suspicion_thresholds.get("network", 0.50)
        )

    def evaluate(
        self,
        process_conf: float,
        command_conf: float,
        network_conf: float,
        memory_conf: float | None = None,
        force_memory_trigger: bool = False,
    ) -> FusionResult:
        """Execute two-stage hybrid fusion decision matching architecture specification."""
        # Stage 1: Behavioral Confidence Fusion (0.35 proc + 0.40 cmd + 0.25 net)
        stage1_score = (
            self.stage1_weights.get("process", 0.35) * process_conf
            + self.stage1_weights.get("command", 0.40) * command_conf
            + self.stage1_weights.get("network", 0.25) * network_conf
        )
        stage1_score = round(min(max(stage1_score, 0.0), 1.0), 4)

        # Suspicion / Memory Forensics Escalation Gate
        suspicious = (
            stage1_score >= self.behavioral_suspicion_threshold
            or self.is_suspicious(process_conf, command_conf, network_conf)
        )
        memory_triggered = suspicious or force_memory_trigger

        # If memory not triggered, assume clean memory baseline (0.05)
        effective_memory_conf = (
            memory_conf if (memory_conf is not None and memory_triggered) else 0.05
        )

        per_model = {
            "process": round(float(process_conf), 4),
            "command": round(float(command_conf), 4),
            "network": round(float(network_conf), 4),
            "memory": round(float(effective_memory_conf), 4),
        }

        # Stage 2: Global Fusion (0.50 * S_behavioral + 0.50 * S_memory)
        alpha = self.stage2_weights.get("behavioral", 0.50)
        beta = self.stage2_weights.get("memory", 0.50)
        fused_confidence = (alpha * stage1_score) + (beta * float(effective_memory_conf))
        fused_confidence = round(min(max(fused_confidence, 0.0), 1.0), 4)

        is_malware = fused_confidence >= self.threshold
        verdict = "Malware" if is_malware else "Benign"

        return FusionResult(
            verdict=verdict,
            confidence=fused_confidence,
            is_malware=is_malware,
            memory_triggered=memory_triggered,
            per_model=per_model,
            threshold=self.threshold,
            suspicion_thresholds=self.suspicion_thresholds,
            stage1_confidence=stage1_score,
            stage1_weights=dict(self.stage1_weights),
            stage2_weights=dict(self.stage2_weights),
        )
