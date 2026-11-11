"""Multi-modal dataset collector and record assembler."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from tools.dataset.command_capture import CommandCapture
from tools.dataset.execution_manager import ExecutionManager, WorkloadProfile
from tools.dataset.labeling import get_binary_label, get_multiclass_label, normalize_family_name
from tools.dataset.memory_capture import MemoryCapture
from tools.dataset.network_capture import NetworkCapture
from tools.dataset.process_capture import ProcessCapture

logger = logging.getLogger("dataset.collector")


class DatasetCollector:
    """Coordinates telemetry capture across Process, Command, Network, and Memory modalities."""

    def __init__(self) -> None:
        self.process_cap = ProcessCapture()
        self.command_cap = CommandCapture()
        self.network_cap = NetworkCapture()
        self.memory_cap = MemoryCapture()
        self.exec_mgr = ExecutionManager()

    def assemble_record(
        self,
        execution_id: str,
        family: str,
        command_text: str,
        is_malware: bool,
        source: str = "sandbox_vm",
        run_number: int = 1,
    ) -> dict[str, Any]:
        """Assemble a single four-modality dataset record adhering to strict schemas."""
        norm_family = normalize_family_name(family)
        bin_label = 1 if is_malware else 0
        multi_label = get_multiclass_label(norm_family) or 0

        proc = self.process_cap.capture(sample_id=execution_id, is_malicious_context=is_malware)
        cmd = self.command_cap.capture(sample_id=execution_id, raw_command=command_text)
        net = self.network_cap.capture(sample_id=execution_id, is_malicious_context=is_malware)
        mem = self.memory_cap.capture(sample_id=execution_id, is_malicious_context=is_malware, family=norm_family)

        record = {
            "sample_id": execution_id,
            "execution_id": execution_id,
            "binary_label": bin_label,
            "multi_class_label": multi_label,
            "family": norm_family,
            "sample_source": source,
            "run_number": run_number,
            # Process Modality
            **proc.model_dump(),
            # Command Modality
            **cmd.model_dump(),
            # Network Modality
            **net.model_dump(),
            # Memory Modality
            **mem.model_dump(),
        }
        return record
