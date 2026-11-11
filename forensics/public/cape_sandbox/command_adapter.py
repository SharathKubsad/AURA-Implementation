"""Command telemetry adapter for CAPEv2 sandbox execution reports."""

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

logger = logging.getLogger("cape_command_adapter")


class CapeCommandAdapter:
    """Adapts CAPEv2 command line executions to canonical CommandFeatures schema."""

    @staticmethod
    def from_cape_report(raw_report: dict[str, Any], sample_id: str) -> CommandFeatures:
        """Extract CommandFeatures from CAPEv2 JSON execution report.

        Args:
            raw_report: CAPEv2 report JSON.
            sample_id: Canonical sample ID.

        Returns:
            Validated CommandFeatures instance.

        Raises:
            ValueError: If no valid command line can be extracted.
        """
        behavior = raw_report.get("behavior", {})
        summary = behavior.get("summary", {})
        commands = summary.get("commands", [])

        cmd_text = None
        if commands and isinstance(commands, list) and len(commands) > 0:
            cmd_text = str(commands[0]).strip()
        else:
            # Fallback to behavior.processes
            processes = behavior.get("processes", [])
            for proc in processes:
                cl = proc.get("command_line")
                if cl and str(cl).strip():
                    cmd_text = str(cl).strip()
                    break

        if not cmd_text:
            raise ValueError(f"No authentic command line found in CAPEv2 report for {sample_id}")

        length = len(cmd_text)
        entropy = calculate_shannon_entropy(cmd_text)

        cmd_lower = cmd_text.lower()
        is_base64 = 1 if any(p.search(cmd_text) for p in BASE64_COMMAND_FLAGS) else 0
        has_cradle = 1 if any(p.search(cmd_text) for p in DOWNLOAD_CRADLE_PATTERNS) else 0
        has_bypass = 1 if any(p.search(cmd_text) for p in BYPASS_POLICY_PATTERNS) else 0
        has_hidden = 1 if any(p.search(cmd_text) for p in HIDDEN_WINDOW_PATTERNS) else 0
        uses_lolbin = 1 if any(lb in cmd_lower for lb in LOLBINS_HIGH_RISK) else 0
        reg_count = sum(1 for p in REGISTRY_PERSISTENCE_PATTERNS if p.search(cmd_text))

        return CommandFeatures(
            sample_id=sample_id,
            raw_command_text=cmd_text,
            command_length=length,
            shannon_entropy=entropy,
            is_base64_encoded=is_base64,
            has_download_cradle=has_cradle,
            has_bypass_execution_policy=has_bypass,
            has_hidden_window=has_hidden,
            uses_lolbins=uses_lolbin,
            registry_persistence_count=reg_count,
        )
