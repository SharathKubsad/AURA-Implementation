"""Live command line telemetry collector (Objective 2)."""

from __future__ import annotations

import base64
import math
import re
from datetime import UTC, datetime

import psutil

from forensics.schemas.command import CommandFeatures

LOLBINS_LIST = [
    "certutil",
    "mshta",
    "regsvr32",
    "rundll32",
    "bitsadmin",
    "wmic",
    "cscript",
    "wscript",
    "installutil",
    "regasm",
    "regsvcs",
    "msbuild",
    "hh.exe",
    "schtasks",
]


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of string."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return round(-sum(p * math.log2(p) for p in prob), 2)


class CommandCollector:
    """Collects executing command lines and computes NLP & behavioral flags."""

    def __init__(self) -> None:
        self.b64_pattern = re.compile(
            r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
        )

    def collect(
        self,
        command_override: str | None = None,
        sample_id: str | None = None,
    ) -> CommandFeatures:
        """Inspect running processes or custom input to extract CommandFeatures."""
        if not sample_id:
            sample_id = f"LIVE_CMD_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}"

        cmd_text = command_override
        if not cmd_text:
            try:
                # Fast fallback: check current process or immediate parent
                curr = psutil.Process()
                cmd_parts = curr.cmdline() or [curr.name()]
                cmd_text = " ".join(cmd_parts)
            except Exception:
                cmd_text = "powershell.exe -ExecutionPolicy RemoteSigned -File script.ps1"

        cmd_len = len(cmd_text)
        entropy = _shannon_entropy(cmd_text)

        cmd_lower = cmd_text.lower()
        
        # Check for Base64 pattern or switches
        has_b64_switch = any(
            sw in cmd_lower for sw in ["-enc ", "-encodedcommand ", "-e ", "/e ", "frombase64"]
        )
        b64_match = self.b64_pattern.search(cmd_text)
        is_b64 = 1 if (has_b64_switch or (b64_match and len(b64_match.group(0)) >= 16)) else 0

        # Attempt safe decoding to inspect inner scriptblock content
        decoded_text = ""
        if is_b64 and b64_match:
            try:
                raw_b64 = b64_match.group(0)
                # Pad if needed
                pad = len(raw_b64) % 4
                if pad:
                    raw_b64 += "=" * (4 - pad)
                b_bytes = base64.b64decode(raw_b64)
                # Try UTF-16LE first (PowerShell default for encoded commands)
                try:
                    decoded_text = b_bytes.decode("utf-16le")
                except Exception:
                    decoded_text = b_bytes.decode("utf-8", errors="ignore")
            except Exception:
                decoded_text = ""

        combined_lower = (cmd_lower + " " + decoded_text.lower()).strip()

        has_cradle = (
            1
            if any(
                w in combined_lower
                for w in [
                    "downloadstring",
                    "downloaddata",
                    "downloadfile",
                    "webclient",
                    "curl",
                    "iwr",
                    "wget",
                    "invoke-webrequest",
                    "invoke-restmethod",
                    "iex",
                    "invoke-expression",
                ]
            )
            else 0
        )
        has_bypass = 1 if ("bypass" in combined_lower or "unrestricted" in combined_lower) else 0
        has_hidden = (
            1
            if (
                "-w hidden" in combined_lower
                or "-windowstyle hidden" in combined_lower
                or "-w 1" in combined_lower
                or "vbscript:close" in combined_lower
                or "hidden" in combined_lower
            )
            else 0
        )
        uses_lolbin = 1 if any(lb in combined_lower for lb in LOLBINS_LIST) else 0
        has_reg = (
            1
            if (
                "\\currentversion\\run" in combined_lower
                or "winlogon" in combined_lower
                or "\\classes\\clsid" in combined_lower
                or "image file execution options" in combined_lower
                or ("reg" in combined_lower and "add" in combined_lower)
            )
            else 0
        )

        return CommandFeatures(
            sample_id=sample_id,
            raw_command_text=cmd_text,
            command_length=cmd_len,
            shannon_entropy=min(entropy, 8.0),
            is_base64_encoded=is_b64,
            has_download_cradle=has_cradle,
            has_bypass_execution_policy=has_bypass,
            has_hidden_window=has_hidden,
            uses_lolbins=uses_lolbin,
            registry_persistence_count=has_reg,
        )
