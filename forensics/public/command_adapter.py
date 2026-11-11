"""Command telemetry adapter for public benchmark datasets (Track B)."""

from __future__ import annotations

import logging
from typing import Any

from forensics.command.command_extractor import (
    BASE64_COMMAND_FLAGS,
    BYPASS_POLICY_PATTERNS,
    DOWNLOAD_CRADLE_PATTERNS,
    HIDDEN_WINDOW_PATTERNS,
    LOLBINS_HIGH_RISK,
    REGISTRY_PERSISTENCE_PATTERNS,
    calculate_shannon_entropy,
)
from forensics.schemas.command import CommandFeatures

logger = logging.getLogger("command_adapter")


class CommandAdapter:
    """Adapts public command telemetry to canonical CommandFeatures schema without fabrication."""

    @staticmethod
    def from_raw_command(raw_command_text: str, sample_id: str) -> CommandFeatures:
        """Derive CommandFeatures deterministically from a genuine raw command string.

        Args:
            raw_command_text: The authentic command line string executed during the workload.
            sample_id: Canonical target sample_id.

        Returns:
            Validated CommandFeatures instance.

        Raises:
            ValueError: If raw_command_text is empty or invalid.
        """
        if raw_command_text is None:
            raise ValueError(
                "raw_command_text cannot be None; command telemetry cannot be fabricated."
            )

        cmd_clean = str(raw_command_text).strip()
        length = len(cmd_clean)
        entropy = calculate_shannon_entropy(cmd_clean)

        cmd_lower = cmd_clean.lower()
        is_base64 = 1 if any(p.search(cmd_clean) for p in BASE64_COMMAND_FLAGS) else 0
        has_cradle = 1 if any(p.search(cmd_clean) for p in DOWNLOAD_CRADLE_PATTERNS) else 0
        has_bypass = 1 if any(p.search(cmd_clean) for p in BYPASS_POLICY_PATTERNS) else 0
        has_hidden = 1 if any(p.search(cmd_clean) for p in HIDDEN_WINDOW_PATTERNS) else 0
        uses_lolbin = 1 if any(lb in cmd_lower for lb in LOLBINS_HIGH_RISK) else 0
        reg_count = sum(1 for p in REGISTRY_PERSISTENCE_PATTERNS if p.search(cmd_clean))

        return CommandFeatures(
            sample_id=sample_id,
            raw_command_text=cmd_clean,
            command_length=length,
            shannon_entropy=entropy,
            is_base64_encoded=is_base64,
            has_download_cradle=has_cradle,
            has_bypass_execution_policy=has_bypass,
            has_hidden_window=has_hidden,
            uses_lolbins=uses_lolbin,
            registry_persistence_count=reg_count,
        )

    @staticmethod
    def from_sandbox_report(raw_record: dict[str, Any], sample_id: str) -> CommandFeatures:
        """Extract CommandFeatures from dynamic sandbox execution reports (Any.Run/CAPE).

        Args:
            raw_record: Sandbox JSON report or dict containing command strings.
            sample_id: Canonical target sample_id.

        Returns:
            Validated CommandFeatures instance.

        Raises:
            ValueError: If no valid command line exists in the report.
        """
        cmd = (
            raw_record.get("raw_command_text")
            or raw_record.get("command_line")
            or raw_record.get("cmdline")
        )
        if not cmd and "commands" in raw_record and isinstance(raw_record["commands"], list):
            valid_cmds = [c for c in raw_record["commands"] if c]
            if valid_cmds:
                cmd = valid_cmds[0]

        if not cmd:
            raise ValueError(
                f"No authentic command line found for sample {sample_id}; Command modality must be marked unavailable."
            )

        return CommandAdapter.from_raw_command(str(cmd), sample_id)
