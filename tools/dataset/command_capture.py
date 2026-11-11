"""Command-line telemetry capture and entropy calculation module."""

from __future__ import annotations

import base64
import collections
import math
import re
from typing import Any

from forensics.schemas.command import CommandFeatures


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy H(X) = -sum(p(x) * log2(p(x))) of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = collections.Counter(data)
    for count in counts.values():
        p_x = count / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return round(float(entropy), 4)


def is_base64_string(s: str) -> int:
    """Check if command contains potential Base64 payload."""
    pattern = r"(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
    matches = re.findall(pattern, s)
    for match in matches:
        if len(match) >= 24:
            try:
                decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
                if any(c.isalnum() for c in decoded):
                    return 1
            except Exception:
                continue
    return 0


class CommandCapture:
    """Captures and extracts structured NLP features from command strings."""

    def capture(self, sample_id: str, raw_command: str) -> CommandFeatures:
        """Parse raw command string into CommandFeatures schema."""
        raw_clean = raw_command.strip()
        cmd_lower = raw_clean.lower()

        # Indicators
        has_cradle = int(bool(re.search(r"(downloadstring|downloaddata|downloadfile|iwr|curl|wget|webrequest)", cmd_lower)))
        has_bypass = int(bool(re.search(r"(-ep\s+bypass|-executionpolicy\s+bypass|bypass)", cmd_lower)))
        has_hidden = int(bool(re.search(r"(-w\s+hidden|-windowstyle\s+hidden|hidden)", cmd_lower)))
        uses_lolbin = int(bool(re.search(r"(certutil|bitsadmin|mshta|rundll32|regsvr32|wmic|cscript|wscript|installutil)", cmd_lower)))
        has_reg = int(bool(re.search(r"(reg\s+add|set-itemproperty|currentversion\\run)", cmd_lower)))
        has_b64 = is_base64_string(raw_clean) or int(bool(re.search(r"(-e\s+|-enc\s+|-encodedcommand\s+)", cmd_lower)))

        entropy = calculate_shannon_entropy(raw_clean)

        return CommandFeatures(
            sample_id=sample_id,
            raw_command_text=raw_clean or "powershell.exe -NoProfile",
            command_length=len(raw_clean),
            shannon_entropy=min(max(entropy, 0.0), 8.0),
            is_base64_encoded=has_b64,
            has_download_cradle=has_cradle,
            has_bypass_execution_policy=has_bypass,
            has_hidden_window=has_hidden,
            uses_lolbins=uses_lolbin,
            registry_persistence_count=has_reg,
        )
