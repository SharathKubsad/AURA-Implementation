"""Memory telemetry adapter placeholder for CAPEv2 sandbox reports.

CAPEv2 dynamic sandbox execution does not capture full volatile RAM memory dumps
or extract Volatility VAD trees. This adapter explicitly refuses to fabricate
memory features, enforcing semantic honesty.
"""

from __future__ import annotations

import logging
from typing import Any

from forensics.schemas.memory import MemoryFeatures

logger = logging.getLogger("cape_memory_adapter")


class CapeMemoryAdapter:
    """Explicitly rejects memory feature extraction for CAPEv2 reports."""

    @staticmethod
    def is_supported() -> bool:
        """Indicate whether memory telemetry is supported for CAPEv2."""
        return False

    @staticmethod
    def from_cape_report(raw_report: dict[str, Any], sample_id: str) -> MemoryFeatures:
        """Reject memory extraction to prevent false data fabrication.

        Raises:
            NotImplementedError: CAPEv2 does not provide volatile memory forensics.
        """
        raise NotImplementedError(
            f"Memory modality is NOT_COMPARABLE for CAPEv2 sample {sample_id}. "
            "CAPEv2 does not capture complete physical RAM dumps or VAD trees. "
            "Memory features cannot be fabricated."
        )
